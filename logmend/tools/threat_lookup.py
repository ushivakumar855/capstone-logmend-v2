"""
tools/threat_lookup.py
Returns human-readable threat intelligence descriptions for:
  - MITRE ATT&CK TTP IDs  (11 entries: 5 Linux + 6 DARPA APT)
  - Known C2 IP addresses  (4 DARPA E5 addresses → Drakon/Azazel attribution)

Signature: lookup_threat(threat_id: str, dataset_tag: str) -> str (JSON)

threat_id can be:
  - A TTP ID string  : "T1189", "T1059.004", etc.
  - A C2 IP address  : "35.106.122.76"
  - Any combined string the LLM may pass: "ID: T1189 | ..."
    (cleaned automatically)
"""

import json

# ── Knowledge base ────────────────────────────────────────────────────────────

TTP_INTEL = {
    # ── Linux general (BETH) ──────────────────────────────────────────────────
    "T1059.004": {
        "name":        "Unix Shell",
        "tactic":      "Execution",
        "description": (
            "Adversaries use Unix shell commands (bash, sh, zsh) to execute "
            "arbitrary code.  Common indicators: bash -i, /dev/tcp redirects, "
            "netcat reverse shells.  Seen in BETH botnet SSH intrusions."
        ),
        "severity_note": "High — direct code execution capability.",
    },
    "T1083": {
        "name":        "File and Directory Discovery",
        "tactic":      "Discovery",
        "description": (
            "Adversaries enumerate the filesystem to locate /etc/shadow, SSH "
            "keys, or configuration files.  Typically an early-stage recon step "
            "before lateral movement or credential access."
        ),
        "severity_note": "Low-Medium — recon activity without direct execution.",
    },
    "T1548.001": {
        "name":        "Setuid and Setgid",
        "tactic":      "Privilege Escalation",
        "description": (
            "Adversaries set the setuid/setgid bit on binaries or scripts so "
            "they execute with owner (often root) privileges regardless of who "
            "invokes them.  chmod 4755 on a shell binary is a classic indicator."
        ),
        "severity_note": "High — results in root-equivalent code execution.",
    },
    "T1070.004": {
        "name":        "File Deletion",
        "tactic":      "Defence Evasion",
        "description": (
            "Adversaries remove their tools, downloaded payloads, and modified "
            "log entries to hinder forensic investigation.  rm -rf on hidden "
            "directories (.mountfs, .X13-unix) is a BETH botnet indicator."
        ),
        "severity_note": "Medium — evidence destruction, not direct damage.",
    },
    "T1105": {
        "name":        "Ingress Tool Transfer",
        "tactic":      "Command and Control",
        "description": (
            "Adversaries download additional tools onto the victim host using "
            "wget, curl, or sftp.  In BETH the botnet node setup involved "
            "downloading dota3.tar.gz via sftp-server."
        ),
        "severity_note": "High — enables subsequent malicious activity.",
    },
    # ── DARPA THEIA/TRACE APT-specific ────────────────────────────────────────
    "T1189": {
        "name":        "Drive-by Compromise",
        "tactic":      "Initial Access",
        "description": (
            "Adversary served malicious content via a website that exploited the "
            "Firefox browser.  No user interaction beyond visiting the page was "
            "required.  This is the initial access vector for the Drakon APT "
            "campaign observed in THEIA E5."
        ),
        "severity_note": "Critical — no-click initial access achieved.",
    },
    "T1068": {
        "name":        "Exploitation for Privilege Escalation",
        "tactic":      "Privilege Escalation",
        "description": (
            "The attacker loaded kernel modules (load_helper.ko, read_scan.ko) "
            "to escalate from a browser sandboxed context to kernel ring 0.  "
            "insmod commands on .ko files from non-system processes are the "
            "primary indicator."
        ),
        "severity_note": "Critical — kernel-level compromise achieved.",
    },
    "T1055": {
        "name":        "Process Injection",
        "tactic":      "Defence Evasion / Privilege Escalation",
        "description": (
            "The Drakon APT injected malicious code into the running sshd daemon "
            "using ptrace.  This allowed the attacker to execute in the context "
            "of a trusted system process, bypassing process-based detection."
        ),
        "severity_note": "Critical — trust boundary of sshd violated.",
    },
    "T1547": {
        "name":        "Boot/Logon Autostart Execution",
        "tactic":      "Persistence",
        "description": (
            "The attacker installed sshdlog as a persistent service that "
            "survives reboots.  This artifact was observed in THEIA E5 after "
            "the process injection stage, establishing long-term persistence "
            "on the compromised host."
        ),
        "severity_note": "High — attacker survives host reboots.",
    },
    "T1071": {
        "name":        "Application Layer Protocol",
        "tactic":      "Command and Control",
        "description": (
            "C2 communications in THEIA E5 used standard HTTP to 35.106.122.76, "
            "blending with browser traffic to evade network-based detection.  "
            "The protocol choice is deliberate to avoid triggering firewall rules "
            "that block non-standard ports."
        ),
        "severity_note": "High — ongoing attacker control channel active.",
    },
    "T1014": {
        "name":        "Rootkit",
        "tactic":      "Defence Evasion",
        "description": (
            "The Azazel APT rootkit was deployed in THEIA E5 to hide processes, "
            "files, and network connections from standard Linux utilities (ps, ls, "
            "netstat).  Its presence indicates deep compromise and active "
            "concealment of the intrusion."
        ),
        "severity_note": "Critical — system visibility compromised at OS level.",
    },
}

# C2 IP address intelligence (DARPA E5 TA51 Final Report)
C2_IP_INTEL = {
    "35.106.122.76": {
        "name":        "Drakon APT C2 Server",
        "tactic":      "Command and Control (T1071)",
        "description": (
            "Primary C2 IP for the Drakon APT campaign observed in THEIA E5.  "
            "Used to receive HTTP-based beacon traffic from the compromised "
            "Firefox process after the drive-by compromise stage."
        ),
        "threat_actor": "Drakon APT",
        "severity_note": "Critical — active C2 channel confirmed.",
    },
    "69.155.209.87": {
        "name":        "Drakon APT Secondary C2",
        "tactic":      "Command and Control (T1071)",
        "description": (
            "Secondary C2 IP for the Drakon APT THEIA E5 campaign.  "
            "Observed receiving beacons post-persistence stage."
        ),
        "threat_actor": "Drakon APT",
        "severity_note": "Critical — active C2 channel confirmed.",
    },
    "189.141.204.211": {
        "name":        "Azazel APT C2 Server",
        "tactic":      "Command and Control (T1071)",
        "description": (
            "C2 IP associated with the Azazel APT rootkit campaign in TRACE E5.  "
            "Traffic to this address indicates successful rootkit deployment "
            "and ongoing attacker control."
        ),
        "threat_actor": "Azazel APT",
        "severity_note": "Critical — rootkit C2 channel active.",
    },
    "208.203.20.42": {
        "name":        "DARPA E5 Attacker Infrastructure",
        "tactic":      "Command and Control (T1071)",
        "description": (
            "Additional attacker-controlled infrastructure observed in the "
            "DARPA THEIA/TRACE E5 engagement.  Associated with tool staging "
            "and exfiltration activity."
        ),
        "threat_actor": "Drakon / Azazel APT",
        "severity_note": "High — attacker infrastructure confirmed.",
    },
}

# Unify for O(1) lookup
_ALL_INTEL = {**TTP_INTEL, **C2_IP_INTEL}

# IPv4 pattern for C2 IP detection
import re
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class ThreatLookup:
    def __init__(self):
        # Nothing to initialise — pure in-memory lookup
        pass

    # ── public API ────────────────────────────────────────────────────────────

    def lookup_threat(self, threat_id, dataset_tag: str = "beth") -> str:
        """
        Returns JSON string:
        {
            "status"      : "success",
            "result"      : "<human-readable description>",
            "name"        : str,
            "tactic"      : str,
            "severity_note": str,
            "threat_actor": str | None   (C2 IPs only)
        }
        """
        # ── Normalise input ───────────────────────────────────────────────────
        raw = str(threat_id).strip() if threat_id else ""
        if not raw:
            return json.dumps({
                "status":       "error",
                "message":      "No threat ID provided.",
                "result":       "No intelligence available.",
                "ttp_id":       None,
            })

        # Extract clean TTP ID or IP from messy LLM-generated strings
        # e.g. "ID: T1189 | Name: Drive-by..." → "T1189"
        # e.g. "[T1055]" → "T1055"
        clean = re.sub(r"[\[\]\(\)]", "", raw)
        # Try to extract a TTP-style token (T followed by digits and optional dot)
        ttp_match = re.search(r"T\d{4}(?:\.\d{3})?", clean)
        ip_match  = _IP_RE.match(clean.split()[0]) if clean else None

        if ttp_match:
            clean_id = ttp_match.group(0)
        elif ip_match:
            clean_id = clean.split()[0]
        else:
            # Last resort: use the first whitespace-free token
            clean_id = clean.split("|")[0].split(":")[0].strip()

        print(f"[Tool: ThreatLookup] Looking up '{clean_id}' (dataset={dataset_tag})...")

        entry = _ALL_INTEL.get(clean_id)
        if not entry:
            return json.dumps({
                "status":       "success",
                "result":       (
                    f"No detailed intelligence found for '{clean_id}'. "
                    "The behaviour remains suspicious and warrants manual review."
                ),
                "name":         "Unknown",
                "tactic":       "Unknown",
                "severity_note":"See anomaly score for guidance.",
                "threat_actor": None,
            })

        return json.dumps({
            "status":        "success",
            "result":        entry["description"],
            "name":          entry["name"],
            "tactic":        entry["tactic"],
            "severity_note": entry["severity_note"],
            "threat_actor":  entry.get("threat_actor"),
        })


# ── quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tool = ThreatLookup()

    for tid in ["T1059.004", "T1189", "T1014", "35.106.122.76",
                "[ID: T1055 | Name: Process Injection]", "UNKNOWN"]:
        r = tool.lookup_threat(tid, "beth")
        d = json.loads(r)
        print(f"\n  {tid}")
        print(f"  Name   : {d.get('name')}")
        print(f"  Tactic : {d.get('tactic')}")
        print(f"  Result : {d.get('result')[:80]}...")