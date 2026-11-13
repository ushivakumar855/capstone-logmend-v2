"""
tools/context_retriever.py
Queries Neo4j for the neighbourhood of a process node.

Three traversals:
  1. SPAWNED  — parent and child process lineage (up to 3 hops)
  2. ACCESSED — files read or written by this process
  3. CONNECTED_TO — network connections with C2 flag  (DARPA only)

Signature: get_process_context(identifier: dict, dataset_tag: str) -> str (JSON)

identifier keys
───────────────
  BETH  : pid, host_name, process_name, parent_pid
  DARPA : uuid
"""

import json
from logmend.database.neo4j_router import db_router

# Known DARPA E5 C2 IP addresses (from TA51 Final Report E5)
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
OPTIONAL MATCH (p)-[:SPAWNED]->(child:Process)
OPTIONAL MATCH (p)-[:ACCESSED]->(f:FileObject)

RETURN
    p.processName                            AS TargetProcess,
    p.cmdLine                                AS CommandLine,
    parent.processName                       AS ParentProcess,
    CASE WHEN p.userId = '0' THEN 'Root'
         ELSE 'User (' + coalesce(p.userId, '?') + ')' END AS Privileges,
    collect(DISTINCT child.processName)      AS SpawnedChildren,
    collect(DISTINCT f.path)                 AS FilesAccessed,
    []                                       AS NetworkConnections,
    false                                    AS HasC2Connection
"""

DARPA_QUERY = """
MATCH (p:Process {uuid: $uuid})

OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p)
OPTIONAL MATCH (p)-[:SPAWNED]->(child:Process)
OPTIONAL MATCH (p)-[:ACCESSED]->(f:FileObject)
OPTIONAL MATCH (p)-[:CONNECTED_TO]->(n:NetFlowObject)

WITH p, parent, child, f, n
RETURN
    coalesce(p.processName, p.type, 'unknown')    AS TargetProcess,
    coalesce(p.cmdLine, '')                        AS CommandLine,
    coalesce(parent.processName, parent.type, '')  AS ParentProcess,
    CASE WHEN p.userId IN ['0', 0] THEN 'Root'
         ELSE 'User (' + coalesce(p.userId, '?') + ')' END AS Privileges,
    collect(DISTINCT coalesce(child.processName, child.type)) AS SpawnedChildren,
    collect(DISTINCT f.path)                                   AS FilesAccessed,
    collect(DISTINCT n.remoteAddress)                          AS NetworkConnections,
    any(x IN collect(n.remoteAddress) WHERE x IN $c2_ips)     AS HasC2Connection
"""


class ContextRetriever:
    def __init__(self):
        self.db = db_router

    # ── public API ────────────────────────────────────────────────────────────

    def get_process_context(self, identifier: dict, dataset_tag: str) -> str:
        """
        Returns JSON string:
        {
            "status": "success",
            "result": {
                "TargetProcess", "CommandLine", "ParentProcess",
                "Privileges", "SpawnedChildren", "FilesAccessed",
                "NetworkConnections", "HasC2Connection"
            }
        }
        """
        if dataset_tag == "beth":
            return self._query_beth(identifier)
        return self._query_darpa(identifier)

    # ── internal query methods ─────────────────────────────────────────────────

    def _query_beth(self, identifier: dict) -> str:
        pid          = identifier.get("pid")
        host_name    = identifier.get("host_name")
        process_name = identifier.get("process_name")
        parent_pid   = identifier.get("parent_pid")

        print(f"[Tool: ContextRetriever] BETH  PID={pid}  Host={host_name}  "
              f"Process={process_name}  ParentPID={parent_pid}")

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
                "message": (f"Graph context not found for PID={pid} "
                            f"Host={host_name} Process={process_name}")
            })
        return json.dumps({"status": "success", "result": result[0]})

    def _query_darpa(self, identifier: dict) -> str:
        uuid = identifier.get("uuid")
        print(f"[Tool: ContextRetriever] DARPA  UUID={uuid}")

        params = {"uuid": uuid, "c2_ips": list(C2_IP_SET)}
        result = self.db.query("darpa", DARPA_QUERY, params)

        if not result:
            return json.dumps({
                "status": "error",
                "message": f"Graph context not found for UUID={uuid}"
            })

        row = result[0]
        # Enrich: flag any connection whose remoteAddress is in our C2 blocklist
        net_conns = row.get("NetworkConnections") or []
        has_c2    = any(ip in C2_IP_SET for ip in net_conns)
        row["HasC2Connection"] = has_c2

        return json.dumps({"status": "success", "result": row})


# ── quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tool = ContextRetriever()

    print("=== BETH ===")
    r = tool.get_process_context(
        {"pid": 7426, "host_name": "ip-10-100-1-217",
         "process_name": "bash", "parent_pid": 1},
        "beth"
    )
    print(json.dumps(json.loads(r), indent=2))

    print("\n=== DARPA ===")
    r = tool.get_process_context(
        {"uuid": "df8a8c88-1234-4a2a-9b1b-8f8f8f8f8f8f"},
        "darpa"
    )
    print(json.dumps(json.loads(r), indent=2))