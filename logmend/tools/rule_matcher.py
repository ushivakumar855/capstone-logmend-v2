"""
tools/rule_matcher.py
Scans the command line and process name of a log record against 12 signature
patterns: 6 general Linux attack patterns + 6 DARPA THEIA/TRACE APT-specific
patterns.  Also checks remoteAddress fields against the known C2 IP blocklist.

Returns:
  matched_rules  : list of matched rule names
  c2_match       : bool — True if any C2 IP was found in network connections
  severity_hint  : "high" | "low" | "none"

Signature: match_rules(identifier: dict, dataset_tag: str) -> str (JSON)
"""

import json
import re
from logmend.database.neo4j_router import db_router

# ── Signature library ─────────────────────────────────────────────────────────

LINUX_PATTERNS = {
    # General Linux attack signatures (retained from original BETH prototype)
    "Reverse Shell":
        r"(nc\s+-e|bash\s+-i\s+>&|/dev/tcp/|socat\s+.*exec)",
    "Data Exfiltration":
        r"(curl|wget)\s+.*https?://",
    "Permission Modification":
        r"chmod\s+(777|u\+s|g\+s|a\+x|4[0-7]{3})|chown\s+root",
    "Sensitive File Access":
        r"(/etc/shadow|/etc/passwd|\.ssh/id_rsa|\.ssh/authorized_keys)",
    "Obfuscation / Encoding":
        r"(base64\s+-d|base64\s+--decode|xxd\s+-r\s+-p|echo\s+.*\|.*base64)",
    "Suspicious Temp Execution":
        r"(/tmp/\S+|/dev/shm/\S+|/var/tmp/\S+)\s*(&&|\||;|$)",
}

APT_PATTERNS = {
    # DARPA THEIA/TRACE E5 APT-specific signatures
    # Source: TA51 Final Report E5 attack ground truth
    "Suspicious Kernel Module Load":
        r"insmod\s+\S+\.ko|modprobe\s+\S+\s+allow_writes",
    "ptrace / Process Injection":
        r"(ptrace|/proc/\d+/mem|process_vm_writev)",
    "Browser Non-Standard Port C2":
        # Firefox / Chrome reaching out on non-HTTP ports (common drive-by C2)
        r"(firefox|chrome|chromium).*--no-sandbox|"
        r"(firefox|chrome|chromium).*-sh\b",
    "Firefox Spawn Shell Chain":
        # Firefox spawning sh/bash/python directly — the THEIA E5 initial-access chain
        r"(firefox|chrome)\s+.*(-e|/bin/sh|/bin/bash|python\s+-c)",
    "sshdlog Persistence Artifact":
        # The sshdlog binary created in THEIA E5 T1547 stage
        r"sshdlog|sshd\.log\s+install|systemctl\s+enable\s+sshd",
    "Botnet / Cryptominer Dropper":
        # BETH botnet patterns (dota3.tar.gz, krane, modprobe msr)
        r"(dota3\.tar\.gz|\.mountfs|krane\s+user|"
        r"modprobe\s+msr|sftp-server\s+.*dota)",
}

# Known DARPA E5 C2 IP addresses (TA51 Final Report)
C2_IP_SET = frozenset({
    "35.106.122.76",
    "69.155.209.87",
    "189.141.204.211",
    "208.203.20.42",
})

# Compile all patterns once at import time for efficiency
_COMPILED = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in {**LINUX_PATTERNS, **APT_PATTERNS}.items()
}

# ── Neo4j queries ─────────────────────────────────────────────────────────────

BETH_QUERY = """
MATCH (p:Process {processId: $pid, hostName: $host_name,
                   processName: $process_name, parentProcessId: $parent_pid})
RETURN
    coalesce(p.processName, '')   AS ProcessName,
    coalesce(p.cmdLine, '')       AS CommandLine,
    []                            AS RemoteAddresses
"""

DARPA_QUERY = """
MATCH (p:Process {uuid: $uuid})
OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)
RETURN
    coalesce(p.processName, p.type, '') AS ProcessName,
    coalesce(p.cmdLine, '')              AS CommandLine,
    collect(DISTINCT n.remoteAddress)    AS RemoteAddresses
"""

class RuleMatcher:
    def __init__(self):
        self.db = db_router

    # ── public API ────────────────────────────────────────────────────────────

    def match_rules(self, identifier: dict, dataset_tag: str) -> str:
        """
        Returns JSON string:
        {
            "status"        : "success",
            "result"        : "Malicious Pattern: X, Y" | "Malicious Pattern: None",
            "matched_rules" : [list of rule names],
            "c2_match"      : bool,
            "severity_hint" : "high" | "low" | "none",
            "Malicious Behavior": str
        }
        """
        if dataset_tag == "beth":
            return self._run(identifier, "beth", BETH_QUERY, self._beth_params(identifier))
        return self._run(identifier, "darpa", DARPA_QUERY, self._darpa_params(identifier))

    # ── internal helpers ──────────────────────────────────────────────────────

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

    def _run(self, identifier: dict, db_name: str,
             query: str, params: dict) -> str:
        label = (f"BETH PID={params.get('pid')} Host={params.get('host_name')}"
                 if db_name == "beth"
                 else f"DARPA UUID={params.get('uuid')}")
        print(f"[Tool: RuleMatcher] Scanning {label}...")

        result = self.db.query(db_name, query, params)
        if not result:
            return json.dumps({
                "status":  "error",
                "message": f"Process not found ({label})"
            })

        row              = result[0]
        proc_name        = (row.get("ProcessName") or "").lower()
        cmd_line         = (row.get("CommandLine")  or "").lower()
        remote_addresses = row.get("RemoteAddresses") or []

        target_text = f"{proc_name} {cmd_line}"

        # ── Pattern matching ──────────────────────────────────────────────────
        matched = [name for name, rx in _COMPILED.items()
                   if rx.search(target_text)]

        # ── C2 IP check ───────────────────────────────────────────────────────
        c2_match = any(ip in C2_IP_SET for ip in remote_addresses)
        if c2_match:
            matched.append("Known C2 IP Communication")

        # ── Severity hint ─────────────────────────────────────────────────────
        apt_names  = set(APT_PATTERNS.keys()) | {"Known C2 IP Communication"}
        is_apt_hit = any(m in apt_names for m in matched)
        severity_hint = (
            "high" if (is_apt_hit or c2_match) else
            "low"  if matched else
            "none"
        )

        if matched:
            behavior_desc = (
                "Matches known APT / kernel-level attack signatures."
                if is_apt_hit or c2_match
                else "Matches known Linux attack signatures."
            )
            return json.dumps({
                "status":           "success",
                "result":           f"Malicious Pattern: {', '.join(matched)}",
                "matched_rules":    matched,
                "c2_match":         c2_match,
                "severity_hint":    severity_hint,
                "Malicious Behavior": behavior_desc,
            })

        return json.dumps({
            "status":           "success",
            "result":           "Malicious Pattern: None, Malicious Behavior: None",
            "matched_rules":    [],
            "c2_match":         False,
            "severity_hint":    "none",
            "Malicious Behavior": "None",
        })


# ── quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tool = RuleMatcher()

    print("=== BETH ===")
    r = tool.match_rules(
        {"pid": 7426, "host_name": "ip-10-100-1-217",
         "process_name": "bash", "parent_pid": 1},
        "beth"
    )
    print(json.dumps(json.loads(r), indent=2))

    print("\n=== DARPA ===")
    r = tool.match_rules(
        {"uuid": "df8a8c88-1234-4a2a-9b1b-8f8f8f8f8f8f"},
        "darpa"
    )
    print(json.dumps(json.loads(r), indent=2))