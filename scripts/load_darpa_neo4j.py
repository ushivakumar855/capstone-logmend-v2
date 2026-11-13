"""
load_darpa_neo4j.py
===================
Load cleaned DARPA graph tables (from scripts/clean_darpa.py) into Neo4j.

Reads   data/cleaned/darpa/<source>/<split>/{processes,files,netflows,edges}.jsonl
Writes  the database for that source, as configured in
        logmend/database/neo4j_router.py (NEO4J_THEIA_DB default "theia",
        NEO4J_TRACE_DB default "trace"):

    (:Process       {uuid, processName, cmdLine, exePath, pid, ppid, userId, ...})
    (:FileObject    {uuid, path, fileType, ownerUserId, permissionMode})
    (:NetFlowObject {uuid, localAddress, localPort, remoteAddress, remotePort, is_c2})
    (parent:Process)-[:SPAWNED]->(child:Process)
    (:Process)-[:ACCESSED     {count, readCount, writeCount, openCount, execCount, ...}]->(:FileObject)
    (:Process)-[:CONNECTED_TO {count, connectCount, sendCount, recvCount, ...}]->(:NetFlowObject)

One relationship is created per process/object pair; the per-event-type counts
are stored on it. Edges to memory, IPC and undefined objects are not loaded as
relationships, but they are included in Process.eventCount.
For TRACE, Process.userId is null: the raw files carry no user records.

The target database must be empty, or pass --wipe to clear it first.

Usage (from the repository root):
    python -m scripts.load_darpa_neo4j --source theia --splits train --wipe
    python -m scripts.load_darpa_neo4j --source theia --splits train --dry-run
"""

import argparse
import collections
import json
import os
import time

from logmend.database.neo4j_router import db_router
from logmend.tools.rule_matcher import C2_IP_SET

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLEAN_DIR = os.path.join(REPO_ROOT, "data", "cleaned", "darpa")
BATCH = 10_000

READ_EVENTS = {"EVENT_READ", "EVENT_RECVFROM", "EVENT_RECVMSG"}
WRITE_EVENTS = {"EVENT_WRITE", "EVENT_SENDTO", "EVENT_SENDMSG"}
DELETE_EVENTS = {"EVENT_UNLINK"}


def _rows(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def _batches(rows, size=BATCH):
    batch = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def read_cleaned(source, splits):
    """Read and aggregate the cleaned tables for the requested splits."""
    procs, files, nets = {}, {}, {}
    kinds = {}
    for split in splits:
        d = os.path.join(CLEAN_DIR, source, split)
        if not os.path.exists(os.path.join(d, "edges.jsonl")):
            raise SystemExit(f"Missing cleaned data: {d}  (run scripts.clean_darpa first)")
        for r in _rows(os.path.join(d, "processes.jsonl")):
            procs[r["uuid"]] = r
        for r in _rows(os.path.join(d, "files.jsonl")):
            files[r["uuid"]] = r
        for r in _rows(os.path.join(d, "netflows.jsonl")):
            nets[r["uuid"]] = r
    kinds.update({u: "process" for u in procs})

    # (process, object) -> counters
    accessed = {}
    connected = {}
    event_count = collections.Counter()
    skipped = collections.Counter()
    for split in splits:
        for e in _rows(os.path.join(CLEAN_DIR, source, split, "edges.jsonl")):
            p, o, et, n = e["processUuid"], e["objectUuid"], e["eventType"], e["count"]
            event_count[p] += n
            if p not in procs:
                skipped["process_not_defined"] += 1
                continue
            if o in files:
                table = accessed
            elif o in nets:
                table = connected
            else:
                skipped[f"object_{e['objectType'] or 'none'}"] += 1
                continue
            agg = table.get((p, o))
            if agg is None:
                agg = table[(p, o)] = {
                    "count": 0, "readCount": 0, "writeCount": 0, "openCount": 0,
                    "execCount": 0, "connectCount": 0, "deleteCount": 0,
                    "totalBytes": 0,
                    "firstTimestampNanos": e["firstTimestampNanos"],
                    "lastTimestampNanos": e["lastTimestampNanos"],
                }
            agg["count"] += n
            agg["totalBytes"] += e["totalBytes"] or 0
            agg["firstTimestampNanos"] = min(agg["firstTimestampNanos"], e["firstTimestampNanos"])
            agg["lastTimestampNanos"] = max(agg["lastTimestampNanos"], e["lastTimestampNanos"])
            if et in READ_EVENTS:
                agg["readCount"] += n
            elif et in WRITE_EVENTS:
                agg["writeCount"] += n
            elif et == "EVENT_OPEN":
                agg["openCount"] += n
            elif et == "EVENT_EXECUTE":
                agg["execCount"] += n
            elif et == "EVENT_CONNECT":
                agg["connectCount"] += n
            elif et in DELETE_EVENTS:
                agg["deleteCount"] += n

    spawned = [(r["parentUuid"], u) for u, r in procs.items()
               if r.get("parentUuid") and r["parentUuid"] in procs]
    return procs, files, nets, accessed, connected, spawned, event_count, skipped


def process_node(r, source, event_count):
    return {
        "uuid": r["uuid"],
        "processName": r["processName"],
        "cmdLine": r["cmdLine"] or "",
        "exePath": r["exePath"],
        "execCmdLines": r.get("execCmdLines") or [],
        "pid": r["pid"],
        "ppid": r["ppid"],
        "userId": r["userId"],
        "effectiveUserId": r["effectiveUserId"],
        "hostId": r["hostId"],
        "startTimestampNanos": r["startTimestampNanos"],
        "eventCount": event_count.get(r["uuid"], 0),
        "source": source,
    }


def file_node(r):
    return {"uuid": r["uuid"], "path": r["path"], "fileType": r["fileType"],
            "ownerUserId": r["ownerUserId"], "permissionMode": r["mode"]}


def netflow_node(r):
    return {"uuid": r["uuid"], "localAddress": r["localAddress"], "localPort": r["localPort"],
            "remoteAddress": r["remoteAddress"], "remotePort": r["remotePort"],
            "is_c2": r["remoteAddress"] in C2_IP_SET}


def _load(session, label, query, rows, total):
    t0, done = time.time(), 0
    for batch in _batches(rows):
        session.run(query, rows=batch).consume()
        done += len(batch)
        if done % (BATCH * 20) == 0 or done == total:
            rate = done / max(time.time() - t0, 0.001)
            print(f"    {label:14} {done:>10,} / {total:,}  ({rate:,.0f}/s)", flush=True)
    return time.time() - t0


def main():
    ap = argparse.ArgumentParser(description="Load cleaned DARPA graph tables into Neo4j.")
    ap.add_argument("--source", choices=["theia", "trace"], default="theia")
    ap.add_argument("--splits", nargs="+", choices=["train", "val", "test"], default=["train"])
    ap.add_argument("--wipe", action="store_true", help="Delete everything in the target database first.")
    ap.add_argument("--dry-run", action="store_true", help="Read and count only; do not touch Neo4j.")
    args = ap.parse_args()

    t0 = time.time()
    print(f"[load_darpa] reading cleaned {args.source} {args.splits} ...", flush=True)
    procs, files, nets, accessed, connected, spawned, event_count, skipped = \
        read_cleaned(args.source, args.splits)
    print(f"[load_darpa] read in {time.time() - t0:.0f}s: "
          f"{len(procs):,} processes, {len(files):,} files, {len(nets):,} netflows | "
          f"{len(spawned):,} SPAWNED, {len(accessed):,} ACCESSED, {len(connected):,} CONNECTED_TO")
    print(f"[load_darpa] edge rows not loaded as relationships: {dict(skipped)}")
    print(f"[load_darpa] netflows flagged is_c2: "
          f"{sum(1 for r in nets.values() if r['remoteAddress'] in C2_IP_SET)}")
    if args.dry_run:
        return

    tag = "darpa" if args.source == "theia" else "trace"
    database = db_router.get_database(tag)
    driver = db_router.get_driver(tag)
    with driver.session(database=database) as s:
        existing = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        if existing and not args.wipe:
            raise SystemExit(f"Database '{database}' already has {existing:,} nodes. "
                             f"Re-run with --wipe to replace them.")
        if existing:
            print(f"[load_darpa] wiping {existing:,} nodes from '{database}' ...", flush=True)
            s.run("MATCH (n) CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS").consume()

        for label in ("Process", "FileObject", "NetFlowObject"):
            s.run(f"CREATE CONSTRAINT {label.lower()}_uuid IF NOT EXISTS "
                  f"FOR (n:{label}) REQUIRE n.uuid IS UNIQUE").consume()
        s.run("CREATE INDEX process_name IF NOT EXISTS FOR (n:Process) ON (n.processName)").consume()
        s.run("CALL db.awaitIndexes(300)").consume()

        print(f"[load_darpa] loading into database '{database}' ...", flush=True)
        _load(s, "Process", "UNWIND $rows AS r CREATE (n:Process) SET n = r",
              (process_node(r, args.source, event_count) for r in procs.values()), len(procs))
        _load(s, "FileObject", "UNWIND $rows AS r CREATE (n:FileObject) SET n = r",
              (file_node(r) for r in files.values()), len(files))
        _load(s, "NetFlowObject", "UNWIND $rows AS r CREATE (n:NetFlowObject) SET n = r",
              (netflow_node(r) for r in nets.values()), len(nets))
        _load(s, "SPAWNED",
              "UNWIND $rows AS r MATCH (a:Process {uuid: r.a}) MATCH (b:Process {uuid: r.b}) "
              "CREATE (a)-[:SPAWNED]->(b)",
              ({"a": a, "b": b} for a, b in spawned), len(spawned))
        _load(s, "ACCESSED",
              "UNWIND $rows AS r MATCH (a:Process {uuid: r.a}) MATCH (b:FileObject {uuid: r.b}) "
              "CREATE (a)-[x:ACCESSED]->(b) SET x = r.props",
              ({"a": a, "b": b, "props": props} for (a, b), props in accessed.items()), len(accessed))
        _load(s, "CONNECTED_TO",
              "UNWIND $rows AS r MATCH (a:Process {uuid: r.a}) MATCH (b:NetFlowObject {uuid: r.b}) "
              "CREATE (a)-[x:CONNECTED_TO]->(b) SET x = r.props",
              ({"a": a, "b": b, "props": props} for (a, b), props in connected.items()), len(connected))

        nodes = s.run("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC").data()
        rels = s.run("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n ORDER BY n DESC").data()
    print(f"[load_darpa] database '{database}' now holds: nodes {nodes} | relationships {rels}")
    print(f"[load_darpa] done in {time.time() - t0:.0f}s")
    db_router.close()


if __name__ == "__main__":
    main()
