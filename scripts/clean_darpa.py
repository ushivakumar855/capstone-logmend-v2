"""
clean_darpa.py
==============
Clean DARPA TC Engagement 5 raw data (THEIA or TRACE) into compact graph tables.

Input  (never unpacked to disk; streamed zip -> gzip -> Avro CDM20):
    data/raw/darpa/<source>/{training,validation,testing}.zip
        └── <Split>/ta1-<source>-1-e5-official-N.bin.M.gz

Output (one self-contained folder per split):
    data/cleaned/darpa/<source>/{train,val,test}/
        processes.jsonl   one row per process (Subject)
        files.jsonl       one row per file object
        netflows.jsonl    one row per network flow object
        principals.jsonl  one row per user principal
        edges.jsonl       one row per (process, object, event type), with
                          count / first + last timestamp / total bytes.
                          Events on memory regions and anonymous sources/sinks
                          are merged into one row per process and kind
                          (objectUuid null, objectType "memory" / "srcsink").
        summary.json      record counts, event-type counts, per-raw-file stats

Repeated events are aggregated: millions of identical read/write events between
the same process and object become a single edge row carrying a count.
UUIDs are written as standard UUID strings. No labels are added here.

Usage (from the repository root):
    python -m scripts.clean_darpa --source theia
    python -m scripts.clean_darpa --source theia --splits test --limit 500000
"""

import argparse
import collections
import gzip
import json
import os
import time
import uuid
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed

import fastavro

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(REPO_ROOT, "data", "raw", "darpa")
CLEAN_DIR = os.path.join(REPO_ROOT, "data", "cleaned", "darpa")

SPLITS = {"train": "training.zip", "val": "validation.zip", "test": "testing.zip"}
ZERO_UUID = b"\x00" * 16
MAX_EXEC_CMDLINES = 20  # distinct exec command lines remembered per process

# Memory regions and anonymous sources/sinks are one-off objects nobody looks
# up by uuid. Events on them are merged per process into one row per kind.
MERGED_KINDS = {"memory": bytes(15) + bytes([1]), "srcsink": bytes(15) + bytes([2])}
MERGED_BY_SENTINEL = {v: k for k, v in MERGED_KINDS.items()}

# CDM record type -> short object kind used in edges.jsonl "objectType"
OBJECT_KINDS = {
    "RECORD_SUBJECT": "process",
    "RECORD_FILE_OBJECT": "file",
    "RECORD_NET_FLOW_OBJECT": "netflow",
    "RECORD_MEMORY_OBJECT": "memory",
    "RECORD_IPC_OBJECT": "ipc",
    "RECORD_SRC_SINK_OBJECT": "srcsink",
    "RECORD_PACKET_SOCKET_OBJECT": "packet_socket",
    "RECORD_REGISTRY_KEY_OBJECT": "registry_key",
}


def _u(b):
    """16 raw bytes -> canonical UUID string (None for missing / all-zero)."""
    if not b or b == ZERO_UUID:
        return None
    return str(uuid.UUID(bytes=bytes(b)))


def _props(d):
    return d.get("properties") or {}


def _base_props(d):
    return (d.get("baseObject") or {}).get("properties") or {}


def _process_name(path, cmd_line):
    src = path or (cmd_line.split(" ", 1)[0] if cmd_line else "")
    return src.rstrip("/").rsplit("/", 1)[-1] or "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Worker: one raw .bin.gz file -> entities + aggregated edges
# ─────────────────────────────────────────────────────────────────────────────

def clean_one_file(zip_path, member, limit=None):
    """Stream one raw file and return its cleaned tables (uuids as raw bytes)."""
    processes, files, netflows, principals, kinds = {}, {}, {}, {}, {}
    edges = {}                       # (subject, object, object2, type) -> [n, first, last, bytes]
    exec_cmds = collections.defaultdict(list)
    obj_paths = {}                   # object uuid -> path seen on an event
    record_types = collections.Counter()
    event_types = collections.Counter()
    hosts = set()
    t0 = time.time()
    n = 0

    with zipfile.ZipFile(zip_path) as z, z.open(member) as raw, \
            gzip.GzipFile(fileobj=raw) as gz:
        for rec in fastavro.reader(gz, handle_unicode_errors="replace"):
            n += 1
            rtype = rec["type"]
            d = rec["datum"]
            record_types[rtype] += 1
            hosts.add(rec["hostId"])

            if rtype == "RECORD_EVENT":
                etype = d["type"]
                event_types[etype] += 1
                subj = d["subject"]
                obj = d["predicateObject"] or ZERO_UUID
                merged = MERGED_KINDS.get(kinds.get(obj))
                if merged:
                    obj = merged
                obj2 = d["predicateObject2"] or ZERO_UUID
                ts = d["timestampNanos"]
                key = (subj, obj, obj2, etype)
                agg = edges.get(key)
                if agg is None:
                    edges[key] = [1, ts, ts, d["size"] or 0]
                else:
                    agg[0] += 1
                    if ts < agg[1]:
                        agg[1] = ts
                    if ts > agg[2]:
                        agg[2] = ts
                    agg[3] += d["size"] or 0
                if d["predicateObjectPath"] and obj not in obj_paths:
                    obj_paths[obj] = d["predicateObjectPath"]
                if d["predicateObject2Path"] and obj2 not in obj_paths:
                    obj_paths[obj2] = d["predicateObject2Path"]
                if etype == "EVENT_EXECUTE":
                    cmd = _props(d).get("cmdLine")
                    cmds = exec_cmds[subj]
                    if cmd and cmd not in cmds and len(cmds) < MAX_EXEC_CMDLINES:
                        cmds.append(cmd)

            elif rtype == "RECORD_SUBJECT":
                p = _props(d)
                path = p.get("path") or p.get("name")
                cmd = d.get("cmdLine") or ""
                processes[d["uuid"]] = {
                    "uuid": _u(d["uuid"]),
                    "subjectType": d.get("type"),
                    "processName": _process_name(path, cmd),
                    "exePath": path,
                    "cmdLine": cmd,
                    "pid": d.get("cid"),
                    "ppid": int(p["ppid"]) if str(p.get("ppid", "")).isdigit() else None,
                    "parentUuid": _u(d.get("parentSubject")),
                    "userId": p.get("uid"),
                    "effectiveUserId": p.get("euid"),
                    "principalUuid": _u(d.get("localPrincipal")),
                    "startTimestampNanos": d.get("startTimestampNanos"),
                    "hostId": _u(rec["hostId"]),
                }
                kinds[d["uuid"]] = "process"

            elif rtype == "RECORD_FILE_OBJECT":
                bp = _base_props(d)
                perm = (d.get("baseObject") or {}).get("permission")
                files[d["uuid"]] = {
                    "uuid": _u(d["uuid"]),
                    "path": bp.get("filename") or bp.get("path"),
                    "fileType": d.get("type"),
                    "ownerUserId": bp.get("uid"),
                    "mode": bp.get("mode") or (bytes(perm).hex() if perm else None),
                }
                kinds[d["uuid"]] = "file"

            elif rtype == "RECORD_NET_FLOW_OBJECT":
                netflows[d["uuid"]] = {
                    "uuid": _u(d["uuid"]),
                    "localAddress": d.get("localAddress"),
                    "localPort": d.get("localPort"),
                    "remoteAddress": d.get("remoteAddress"),
                    "remotePort": d.get("remotePort"),
                    "ipProtocol": d.get("ipProtocol"),
                }
                kinds[d["uuid"]] = "netflow"

            elif rtype == "RECORD_PRINCIPAL":
                principals[d["uuid"]] = {
                    "uuid": _u(d["uuid"]),
                    "userId": d.get("userId"),
                    "username": d.get("username"),
                    "groupIds": d.get("groupIds"),
                    "principalType": d.get("type"),
                }

            elif rtype in OBJECT_KINDS and isinstance(d, dict) and d.get("uuid"):
                kinds[d["uuid"]] = OBJECT_KINDS[rtype]

            if limit and n >= limit:
                break

    return {
        "member": member,
        "records": n,
        "seconds": round(time.time() - t0, 1),
        "record_types": dict(record_types),
        "event_types": dict(event_types),
        "hosts": sorted(_u(h) for h in hosts if h),
        "processes": processes,
        "files": files,
        "netflows": netflows,
        "principals": principals,
        "kinds": {u: k for u, k in kinds.items() if k not in MERGED_KINDS},
        "edges": edges,
        "exec_cmds": dict(exec_cmds),
        "obj_paths": obj_paths,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Merge + write
# ─────────────────────────────────────────────────────────────────────────────

def _write_jsonl(path, rows):
    count = 0
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            fh.write("\n")
            count += 1
    return count


def _member_order(member):
    # "Training/ta1-theia-1-e5-official-2.bin.5.gz" -> (2, 5)
    stem = os.path.basename(member).replace(".gz", "")
    official, _, part = stem.rpartition(".bin.")
    return (int(official.rsplit("-", 1)[-1]) if official.rsplit("-", 1)[-1].isdigit() else 0,
            int(part) if part.isdigit() else 0)


def run(source, splits, workers, limit):
    src_raw = os.path.join(RAW_DIR, source)
    jobs = []
    for split in splits:
        zpath = os.path.join(src_raw, SPLITS[split])
        if not os.path.exists(zpath):
            raise SystemExit(f"Missing raw archive: {zpath}")
        with zipfile.ZipFile(zpath) as z:
            for member in sorted(z.namelist(), key=_member_order):
                if member.endswith(".gz"):
                    jobs.append((split, zpath, member))

    print(f"[clean_darpa] source={source}  files={len(jobs)}  workers={workers}")
    t0 = time.time()
    results = collections.defaultdict(list)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(clean_one_file, z, m, limit): (s, m) for s, z, m in jobs}
        for fut in as_completed(futs):
            split, member = futs[fut]
            res = fut.result()
            results[split].append(res)
            print(f"  [{split:5}] {os.path.basename(member):42} "
                  f"{res['records']:>10,} records  {len(res['edges']):>9,} edges  "
                  f"{res['seconds']:>6}s")

    # Global definitions (an object defined in one split may be used in another).
    g_proc, g_file, g_net, g_prin, g_kind, g_path, g_exec = {}, {}, {}, {}, {}, {}, {}
    for split in SPLITS:                       # train -> val -> test = time order
        for res in sorted(results.get(split, []), key=lambda r: _member_order(r["member"])):
            g_proc.update(res["processes"])
            g_file.update(res["files"])
            g_net.update(res["netflows"])
            g_prin.update(res["principals"])
            g_kind.update(res["kinds"])
            for k, v in res["obj_paths"].items():
                g_path.setdefault(k, v)
            for k, cmds in res["exec_cmds"].items():
                seen = g_exec.setdefault(k, [])
                for c in cmds:
                    if c not in seen and len(seen) < MAX_EXEC_CMDLINES:
                        seen.append(c)

    # Objects that never got a definition record in these files but whose path
    # is carried on the events that use them (common in TRACE) become files.
    recovered = 0
    for u, path in g_path.items():
        if u not in g_kind and u != ZERO_UUID:
            g_file[u] = {"uuid": _u(u), "path": path, "fileType": "PATH_FROM_EVENT",
                         "ownerUserId": None, "mode": None}
            g_kind[u] = "file"
            recovered += 1
    if recovered:
        print(f"[clean_darpa] recovered {recovered:,} file objects from event paths")

    # TRACE splits a process into execution "units" (SUBJECT_UNIT). Fold every
    # unit into the process that owns it, so the graph stays process-level.
    parent_of = {u: uuid.UUID(r["parentUuid"]).bytes
                 for u, r in g_proc.items() if r["parentUuid"]}
    owner = {}
    for u, row in g_proc.items():
        if row["subjectType"] != "SUBJECT_UNIT":
            continue
        cur, hops = u, 0
        while (cur in g_proc and g_proc[cur]["subjectType"] == "SUBJECT_UNIT"
               and cur in parent_of and hops < 50):
            cur, hops = parent_of[cur], hops + 1
        owner[u] = cur
    if owner:
        print(f"[clean_darpa] folding {len(owner):,} execution units into their processes")
        for u, cmds in list(g_exec.items()):
            if u in owner:
                seen = g_exec.setdefault(owner[u], [])
                for c in cmds:
                    if c not in seen and len(seen) < MAX_EXEC_CMDLINES:
                        seen.append(c)

    # Fill in what a Subject record does not carry itself.
    for u, row in g_proc.items():
        if row["userId"] is None and row["principalUuid"]:
            prin = g_prin.get(uuid.UUID(row["principalUuid"]).bytes)
            if prin and prin["userId"] is not None:
                row["userId"] = str(prin["userId"])
        parent = parent_of.get(u)
        if parent in owner:
            row["parentUuid"] = _u(owner[parent])

    for split in splits:
        parts = sorted(results[split], key=lambda r: _member_order(r["member"]))
        out_dir = os.path.join(CLEAN_DIR, source, split)
        os.makedirs(out_dir, exist_ok=True)

        edges = {}
        for res in parts:
            for key, (cnt, first, last, size) in res["edges"].items():
                if owner:
                    subj, obj, obj2, etype = key
                    key = (owner.get(subj, subj), owner.get(obj, obj), owner.get(obj2, obj2), etype)
                agg = edges.get(key)
                if agg is None:
                    edges[key] = [cnt, first, last, size]
                else:
                    agg[0] += cnt
                    agg[1] = min(agg[1], first)
                    agg[2] = max(agg[2], last)
                    agg[3] += size

        # Every uuid this split touches, so the split folder is self-contained.
        used = set()
        for subj, obj, obj2, _ in edges:
            used.update((subj, obj, obj2))
        for res in parts:
            used.update(res["processes"], res["files"], res["netflows"])
        for u in [u for u in used if u in g_proc]:
            parent = g_proc[u]["parentUuid"]
            if parent:
                used.add(uuid.UUID(parent).bytes)
        used.discard(ZERO_UUID)
        used.difference_update(MERGED_BY_SENTINEL)

        def proc_rows():
            for u in used:
                row = g_proc.get(u)
                if row and row["subjectType"] != "SUBJECT_UNIT":
                    row = dict(row)
                    row["execCmdLines"] = g_exec.get(u, [])
                    yield row

        def file_rows():
            for u in used:
                row = g_file.get(u)
                if row:
                    if not row["path"] and u in g_path:
                        row = dict(row, path=g_path[u])
                    yield row

        def edge_rows():
            for (subj, obj, obj2, etype), (cnt, first, last, size) in edges.items():
                if obj in MERGED_BY_SENTINEL:
                    obj_uuid, obj_type = None, MERGED_BY_SENTINEL[obj]
                elif obj == ZERO_UUID:
                    obj_uuid, obj_type = None, None
                else:
                    obj_uuid, obj_type = _u(obj), g_kind.get(obj, "unknown")
                yield {
                    "processUuid": _u(subj),
                    "eventType": etype,
                    "objectUuid": obj_uuid,
                    "objectType": obj_type,
                    "object2Uuid": _u(obj2),
                    "object2Type": g_kind.get(obj2, "unknown") if obj2 != ZERO_UUID else None,
                    "count": cnt,
                    "firstTimestampNanos": first,
                    "lastTimestampNanos": last,
                    "totalBytes": size,
                }

        principal_ids = {uuid.UUID(g_proc[u]["principalUuid"]).bytes
                         for u in used if u in g_proc and g_proc[u]["principalUuid"]}
        n_proc = _write_jsonl(os.path.join(out_dir, "processes.jsonl"), proc_rows())
        n_file = _write_jsonl(os.path.join(out_dir, "files.jsonl"), file_rows())
        n_net = _write_jsonl(os.path.join(out_dir, "netflows.jsonl"),
                             (g_net[u] for u in used if u in g_net))
        n_prin = _write_jsonl(os.path.join(out_dir, "principals.jsonl"),
                              (g_prin[u] for u in principal_ids if u in g_prin))
        n_edge = _write_jsonl(os.path.join(out_dir, "edges.jsonl"), edge_rows())

        subjects = {k[0] for k in edges}
        rec_types, ev_types = collections.Counter(), collections.Counter()
        for res in parts:
            rec_types.update(res["record_types"])
            ev_types.update(res["event_types"])
        summary = {
            "source": source,
            "split": split,
            "record_limit_per_file": limit,
            "raw_records": sum(r["records"] for r in parts),
            "raw_events": rec_types.get("RECORD_EVENT", 0),
            "rows": {"processes": n_proc, "files": n_file, "netflows": n_net,
                     "principals": n_prin, "edges": n_edge},
            "event_subjects": len(subjects),
            "execution_units_folded_into_processes": len(owner),
            "files_recovered_from_event_paths": recovered,
            "event_subjects_without_process_record": sum(1 for s in subjects if s not in g_proc),
            "edges_with_unknown_object": sum(
                1 for k in edges if k[1] != ZERO_UUID and k[1] not in g_kind
                and k[1] not in MERGED_BY_SENTINEL),
            "hosts": sorted({h for r in parts for h in r["hosts"]}),
            "record_types": dict(rec_types.most_common()),
            "event_types": dict(ev_types.most_common()),
            "raw_files": [{"file": os.path.basename(r["member"]), "records": r["records"],
                           "edges": len(r["edges"]), "seconds": r["seconds"]} for r in parts],
        }
        with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"[clean_darpa] {split:5}: {summary['raw_events']:>12,} events -> "
              f"{n_edge:,} edges | {n_proc:,} processes, {n_file:,} files, "
              f"{n_net:,} netflows -> {out_dir}")

    print(f"[clean_darpa] done in {time.time() - t0:.0f}s")


def main():
    ap = argparse.ArgumentParser(description="Clean DARPA TC E5 raw data into graph tables.")
    ap.add_argument("--source", choices=["theia", "trace"], default="theia")
    ap.add_argument("--splits", nargs="+", choices=list(SPLITS), default=list(SPLITS))
    ap.add_argument("--workers", type=int, default=min(17, os.cpu_count() or 4))
    ap.add_argument("--limit", type=int, default=None,
                    help="Stop after N records per raw file (for quick trials).")
    args = ap.parse_args()
    run(args.source, args.splits, args.workers, args.limit)


if __name__ == "__main__":
    main()
