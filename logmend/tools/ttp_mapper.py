"""
tools/ttp_mapper.py
Maps observed process behaviour to MITRE ATT&CK techniques using
sentence-transformer cosine similarity (MiniLM-L12-v2).

11 TTPs total:
  5 Linux general (original BETH set)
  6 DARPA THEIA/TRACE APT-specific (added for LogMend 2.0)

Critical fix over the original:
  Returns 'ttp_id' and 'ttp_impact' as top-level JSON keys so that
  main.py can pass them to ThreatLookup and severity_calculator without
  parsing a text blob.

Signature: map_ttp(identifier: dict, dataset_tag: str) -> str (JSON)
"""

import json
import warnings
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from logmend.database.neo4j_router import db_router

warnings.filterwarnings("ignore")

# ── TTP knowledge base ────────────────────────────────────────────────────────
# Each entry: id → {name, tactic, description, impact (1-5), kill_chain_stage (1-7)}
# impact      : used by severity_calculator for BETH
# kill_chain_stage : used by severity_calculator for DARPA (1=initial, 7=exfil)

TTP_KNOWLEDGE = {
    # ── Linux general (BETH) ──────────────────────────────────────────────────
    "T1059.004": {
        "name":              "Unix Shell",
        "tactic":            "Execution",
        "description":       (
            "Adversaries abuse Unix shell commands and scripts for execution. "
            "Unix shells are the primary command interface on Linux systems and "
            "are used to run arbitrary commands, launch processes, and automate tasks."
        ),
        "impact":            3,
        "kill_chain_stage":  2,
    },
    "T1083": {
        "name":              "File and Directory Discovery",
        "tactic":            "Discovery",
        "description":       (
            "Adversaries enumerate files and directories to locate sensitive "
            "information such as /etc/shadow, SSH private keys, or configuration "
            "files that support lateral movement or privilege escalation."
        ),
        "impact":            2,
        "kill_chain_stage":  2,
    },
    "T1548.001": {
        "name":              "Setuid and Setgid",
        "tactic":            "Privilege Escalation",
        "description":       (
            "Adversaries abuse setuid or setgid file permissions to execute "
            "binaries with elevated privileges, allowing a non-root user to "
            "perform actions as root without explicit sudo."
        ),
        "impact":            4,
        "kill_chain_stage":  3,
    },
    "T1070.004": {
        "name":              "File Deletion",
        "tactic":            "Defence Evasion",
        "description":       (
            "Adversaries delete files left behind during intrusion activity to "
            "remove forensic evidence of their presence, including tools, logs, "
            "and temporary scripts."
        ),
        "impact":            2,
        "kill_chain_stage":  3,
    },
    "T1105": {
        "name":              "Ingress Tool Transfer",
        "tactic":            "Command and Control",
        "description":       (
            "Adversaries transfer tools or malicious payloads from an external "
            "system onto a compromised host using wget, curl, or sftp, typically "
            "as part of establishing a persistent foothold."
        ),
        "impact":            3,
        "kill_chain_stage":  4,
    },
    # ── DARPA THEIA/TRACE APT-specific (ADDED for LogMend 2.0) ───────────────
    "T1189": {
        "name":              "Drive-by Compromise",
        "tactic":            "Initial Access",
        "description":       (
            "Adversaries gain access to a system through a user browsing to a "
            "website hosting exploit code.  The Firefox Drakon APT campaign in "
            "THEIA E5 used a malicious webpage to exploit the browser and gain "
            "initial code execution."
        ),
        "impact":            3,
        "kill_chain_stage":  1,
    },
    "T1068": {
        "name":              "Exploitation for Privilege Escalation",
        "tactic":            "Privilege Escalation",
        "description":       (
            "Adversaries exploit software vulnerabilities to elevate privileges. "
            "In THEIA E5 the attacker used a kernel module (load_helper.ko, "
            "read_scan.ko) to escalate from browser context to kernel-level access."
        ),
        "impact":            5,
        "kill_chain_stage":  3,
    },
    "T1055": {
        "name":              "Process Injection",
        "tactic":            "Defence Evasion / Privilege Escalation",
        "description":       (
            "Adversaries inject code into the address space of a running process "
            "to evade detection and execute with elevated permissions.  The THEIA "
            "E5 attack injected malicious code into the sshd process via ptrace."
        ),
        "impact":            5,
        "kill_chain_stage":  4,
    },
    "T1547": {
        "name":              "Boot/Logon Autostart Execution",
        "tactic":            "Persistence",
        "description":       (
            "Adversaries configure system settings to execute their payload on "
            "startup.  In THEIA E5 the sshdlog binary was installed as a "
            "persistent autostart service to survive reboots."
        ),
        "impact":            4,
        "kill_chain_stage":  5,
    },
    "T1071": {
        "name":              "Application Layer Protocol",
        "tactic":            "Command and Control",
        "description":       (
            "Adversaries communicate using application-layer protocols to avoid "
            "detection.  C2 traffic in THEIA E5 used HTTP to the known C2 IP "
            "35.106.122.76, blending with normal browser traffic."
        ),
        "impact":            4,
        "kill_chain_stage":  6,
    },
    "T1014": {
        "name":              "Rootkit",
        "tactic":            "Defence Evasion",
        "description":       (
            "Adversaries use rootkits to conceal the existence of malware by "
            "intercepting OS calls.  The Azazel APT rootkit in THEIA E5 hid "
            "processes and files from standard Linux utilities."
        ),
        "impact":            5,
        "kill_chain_stage":  5,
    },
}

BETH_QUERY = """
MATCH (p:Process {processId: $pid, hostName: $host_name,
                   processName: $process_name, parentProcessId: $parent_pid})
RETURN
    coalesce(p.processName, '') AS ProcessName,
    coalesce(p.cmdLine, '')     AS CommandLine
"""

DARPA_QUERY = """
MATCH (p:Process {uuid: $uuid})
OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)
RETURN
    coalesce(p.processName, p.type, '') AS ProcessName,
    coalesce(p.cmdLine, '')              AS CommandLine,
    collect(DISTINCT n.remoteAddress)    AS RemoteAddresses
"""

# Minimum cosine similarity to accept a TTP match
THRESHOLD = 0.30


class TTPMapper:
    def __init__(self):
        self.db = db_router
        print("[TTPMapper] Loading MiniLM-L12-v2 (sentence-transformers)...")
        self.model = SentenceTransformer("all-MiniLM-L12-v2")

        # Pre-compute TTP embeddings once at startup
        self._ttp_ids   = list(TTP_KNOWLEDGE.keys())
        self._ttp_embs  = self.model.encode(
            [TTP_KNOWLEDGE[tid]["description"] for tid in self._ttp_ids]
        )
        print(f"[TTPMapper] {len(self._ttp_ids)} TTPs embedded and ready.")

    # ── public API ────────────────────────────────────────────────────────────

    def map_ttp(self, identifier: dict, dataset_tag: str) -> str:
        """
        Returns JSON string:
        {
            "status"     : "success",
            "result"     : "<formatted match string>",
            "ttp_id"     : "T1189" | None,
            "ttp_impact" : int (1-5) | 1,
            "similarity" : float
        }
        """
        if dataset_tag == "beth":
            return self._map(identifier, "beth", BETH_QUERY, self._beth_params(identifier))
        return self._map(identifier, "darpa", DARPA_QUERY, self._darpa_params(identifier))

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _beth_params(identifier: dict) -> dict:
        return {
            "pid":          identifier.get("pid"),
            "host_name":    identifier.get("host_name"),
            "process_name": identifier.get("process_name"),
            "parent_pid":   identifier.get("parent_pid"),
        }

    @staticmethod
    def _darpa_params(identifier: dict) -> dict:
        return {"uuid": identifier.get("uuid")}

    def _map(self, identifier: dict, db_name: str,
             query: str, params: dict) -> str:
        label = (f"BETH PID={params.get('pid')}"
                 if db_name == "beth"
                 else f"DARPA UUID={params.get('uuid')}")
        print(f"[Tool: TTPMapper] Mapping {label}...")

        result = self.db.query(db_name, query, params)
        if not result:
            return json.dumps({
                "status":     "error",
                "message":    f"Process not found ({label})",
                "ttp_id":     None, 
                "ttp_impact": 1,
                "similarity": 0.0,
            })

        row          = result[0]
        proc_name    = row.get("ProcessName") or ""
        cmd_line     = row.get("CommandLine")  or ""
        remote_addrs = row.get("RemoteAddresses") or []

        # Build log description text for embedding
        log_text = f"Process {proc_name} executed command: {cmd_line}"
        if remote_addrs:
            log_text += f" connected to: {', '.join(remote_addrs[:3])}"

        log_emb     = self.model.encode([log_text])
        sims        = cosine_similarity(log_emb, self._ttp_embs)[0]
        best_idx    = int(np.argmax(sims))
        best_score  = float(sims[best_idx])

        if best_score >= THRESHOLD:
            tid      = self._ttp_ids[best_idx]
            ttp_info = TTP_KNOWLEDGE[tid]
            result_str = (
                f"[ID: {tid} | Name: {ttp_info['name']} | "
                f"Tactic: {ttp_info['tactic']} | "
                f"Similarity: {best_score:.2f}]"
            )
            return json.dumps({
                "status":     "success",
                "result":     result_str,
                "ttp_id":     tid,
                "ttp_impact": ttp_info["impact"],
                "kill_chain_stage": ttp_info["kill_chain_stage"],
                "similarity": round(best_score, 4),
            })

        return json.dumps({
            "status":     "success",
            "result":     "No confident MITRE ATT&CK TTP mapping found.",
            "ttp_id":     None,
            "ttp_impact": 1,
            "kill_chain_stage": 1,
            "similarity": round(best_score, 4),
        })


# ── quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tool = TTPMapper()

    print("=== BETH ===")
    r = tool.map_ttp(
        {"pid": 7426, "host_name": "ip-10-100-1-217",
         "process_name": "bash", "parent_pid": 1},
        "beth"
    )
    print(json.dumps(json.loads(r), indent=2))

    print("\n=== DARPA ===")
    r = tool.map_ttp(
        {"uuid": "df8a8c88-1234-4a2a-9b1b-8f8f8f8f8f8f"},
        "darpa"
    )
    print(json.dumps(json.loads(r), indent=2))