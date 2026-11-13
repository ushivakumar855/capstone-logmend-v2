"""
tools/description_generator.py
Converts a structured process record from Neo4j into a natural language
sentence that the LLM planner can reason over.

For DARPA records the description includes:
  - Network connection targets (remoteAddress:port)
  - C2 annotation when is_c2=true

Signature: generate_description(identifier: dict, dataset_tag: str) -> str (JSON)
"""

import json
from logmend.database.neo4j_router import db_router

# Known C2 IPs (same set as context_retriever)
C2_IP_SET = frozenset({
    "35.106.122.76",
    "69.155.209.87",
    "189.141.204.211",
    "208.203.20.42",
})

BETH_QUERY = """
MATCH (p:Process {processId: $pid, hostName: $host_name,
                   processName: $process_name, parentProcessId: $parent_pid})
OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p)
OPTIONAL MATCH (p)-[:RUNS_AS]->(u:User)

RETURN
    p.processName       AS ProcessName,
    p.cmdLine           AS CommandLine,
    parent.processName  AS ParentProcess,
    p.hostName          AS HostName,
    coalesce(u.userId, p.userId, 'unknown')  AS UserID,
    p.userId = '0'      AS IsRoot
"""

DARPA_QUERY = """
MATCH (p:Process {uuid: $uuid})
OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p)
OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)

RETURN
    coalesce(p.processName, p.type, 'unknown')        AS ProcessName,
    coalesce(p.cmdLine, '')                            AS CommandLine,
    coalesce(parent.processName, parent.type, '')      AS ParentProcess,
    p.userId IN ['0', 0]                               AS IsRoot,
    coalesce(p.userId, 'unknown')                      AS UserID,
    collect(DISTINCT n.remoteAddress + ':' +
        coalesce(toString(n.remotePort), '?'))         AS NetworkTargets,
    collect(DISTINCT n.remoteAddress)                  AS RemoteAddresses
"""


class DescriptionGenerator:
    def __init__(self):
        self.db = db_router

    # ── public API ────────────────────────────────────────────────────────────

    def generate_description(self, identifier: dict, dataset_tag: str) -> str:
        """
        Returns JSON string:
        { "status": "success", "result": "<natural language description>" }
        """
        if dataset_tag == "beth":
            return self._describe_beth(identifier)
        return self._describe_darpa(identifier)

    # ── internal methods ──────────────────────────────────────────────────────

    def _describe_beth(self, identifier: dict) -> str:
        pid          = identifier.get("pid")
        host_name    = identifier.get("host_name")
        process_name = identifier.get("process_name")
        parent_pid   = identifier.get("parent_pid")

        print(f"[Tool: DescriptionGenerator] BETH  PID={pid}  Host={host_name}  "
              f"Process={process_name}")

        params = {
            "pid":          pid,
            "host_name":    host_name,
            "process_name": process_name,
            "parent_pid":   parent_pid,
        }
        result = self.db.query("beth", BETH_QUERY, params)

        if not result:
            return json.dumps({
                "status": "error",
                "message": (f"Cannot generate description. "
                            f"PID={pid} Host={host_name} Process={process_name} not found.")
            })

        data      = result[0]
        proc_name = data.get("ProcessName") or "unknown"
        cmd_line  = data.get("CommandLine")  or "(no command line)"
        parent    = data.get("ParentProcess") or "an unknown parent"
        host      = data.get("HostName")      or "unknown host"
        is_root   = data.get("IsRoot", False)
        user_id   = data.get("UserID", "unknown")
        privilege = "root privileges" if is_root else f"user ID {user_id}"

        description = (
            f"Process '{proc_name}' was spawned by '{parent}' on host '{host}'. "
            f"It ran with {privilege} using the command: '{cmd_line}'."
        )
        return json.dumps({"status": "success", "result": description})

    def _describe_darpa(self, identifier: dict) -> str:
        uuid = identifier.get("uuid")
        print(f"[Tool: DescriptionGenerator] DARPA  UUID={uuid}")

        params = {"uuid": uuid}
        result = self.db.query("darpa", DARPA_QUERY, params)

        if not result:
            return json.dumps({
                "status": "error",
                "message": f"Cannot generate description. UUID={uuid} not found."
            })

        data            = result[0]
        proc_name       = data.get("ProcessName")    or "unknown"
        cmd_line        = data.get("CommandLine")     or "(no command line)"
        parent          = data.get("ParentProcess")   or "an unknown parent"
        is_root         = data.get("IsRoot", False)
        user_id         = data.get("UserID", "unknown")
        net_targets     = data.get("NetworkTargets")  or []
        remote_addrs    = data.get("RemoteAddresses") or []
        privilege       = "root privileges" if is_root else f"user ID {user_id}"

        description = (
            f"Process '{proc_name}' was spawned by '{parent}'. "
            f"It ran with {privilege} using the command: '{cmd_line}'."
        )

        # Append network context — this is the critical APT signal
        if net_targets:
            c2_addrs = [a for a in remote_addrs if a in C2_IP_SET]
            if c2_addrs:
                description += (
                    f" It connected to KNOWN C2 addresses: "
                    f"{', '.join(c2_addrs)} (Drakon/Azazel APT attribution)."
                )
            else:
                description += (
                    f" It made network connections to: {', '.join(net_targets[:5])}."
                )

        return json.dumps({"status": "success", "result": description})


# ── quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tool = DescriptionGenerator()

    print("=== BETH ===")
    r = tool.generate_description(
        {"pid": 7426, "host_name": "ip-10-100-1-217",
         "process_name": "bash", "parent_pid": 1},
        "beth"
    )
    print(json.loads(r).get("result", r))

    print("\n=== DARPA ===")
    r = tool.generate_description(
        {"uuid": "df8a8c88-1234-4a2a-9b1b-8f8f8f8f8f8f"},
        "darpa"
    )
    print(json.loads(r).get("result", r))