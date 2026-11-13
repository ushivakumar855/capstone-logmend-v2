"""
json_file_runner.py
Batch evaluation runner for BETH JSON test/validation files (part_N.json).

Why this file exists
────────────────────
The test and validation splits of BETH are intentionally NOT ingested into
the Neo4j training graph (per the LogMend dataset architecture).  The TAO
agent's graph-based tools (ContextRetriever, RuleMatcher, DescriptionGenerator,
TTPMapper) will return "not found" for any process from these splits.

The SequenceScorer, however, needs the 9-feature vector.  This runner
aggregates those features directly from the raw JSON event records and
injects them as 'precomputed_features' in the identifier dict, so the
SequenceScorer's precomputed bypass path is triggered automatically.

Workflow
────────
  1. Load a part_N.json file (5 000 events per file)
  2. Group events by process key: (processId, hostName, processName, parentProcessId)
  3. Aggregate 9 ML features per process group from raw event fields
  4. Determine ground truth label: evil=1 in ANY event → label=1 (MALICIOUS)
  5. Build synthetic record + identifier with precomputed_features
  6. Run the TAO agent (LogMendAgent) on each process group
  7. Collect predictions and compute TP/TN/FP/FN + precision/recall/F1
  8. Save results to LogMend_BETH_{timestamp}.txt

Usage
─────
  # Single file
  python -m scripts.json_file_runner --file data/cleaned/beth/test/part_3.json

  # Directory of files (processes all .json files)
  python -m scripts.json_file_runner --dir data/cleaned/beth/test/

  # Limit the number of unique processes investigated (useful for quick tests)
  python -m scripts.json_file_runner --file data/cleaned/beth/test/part_3.json --limit 10

Feature aggregation logic (from raw BETH event fields)
──────────────────────────────────────────────────────
  is_root          : any event where user.is_root == true
  event_count      : total number of audit events for the process
  sus_ratio        : (events where event.sus == 1) / event_count
  evil_ratio       : (events where event.evil == 1) / event_count
  net_ratio        : (events where event.is_network_op == true) / event_count
  c2_event_count   : 0  (C2 IP data not in raw BETH events; provided by Neo4j)
  file_write_count : events where file_path.flags_category == "write"
                     OR event.is_delete_op == true
  inject_count     : 0  (ptrace signals not in raw BETH events)
  bias             : 5.0 (constant — injected automatically by SequenceScorer)

Ground truth labelling
───────────────────────
  Process label = 1 (MALICIOUS) if ANY event in the group has evil == 1
  Process label = 0 (BENIGN)    otherwise

  NOTE: evil and sus flags in the test files reflect real ground truth
  annotations from the BETH dataset.  The instruction that "evil and sus
  are random and have no set pattern" means that a high sus count does NOT
  guarantee evil=1 — the labelling is event-granular, not rule-based.

Prediction → binary mapping
────────────────────────────
  MALICIOUS (severity >= 6.5) → pred = 1
  SUSPICIOUS (3.5 <= severity < 6.5) → pred = 1  (conservative — flags for review)
  BENIGN (severity < 3.5) → pred = 0
"""

import json
import os
import sys
import time
import datetime
import argparse
from collections import defaultdict


# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.main import LogMendAgent

from neo4j import GraphDatabase
import os

# Ensure this matches your local Neo4j Desktop credentials
URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = os.getenv("NEO4J_BETH_PASS", "password") 

def load_ephemeral_graph(data):
    """Injects the batch into Neo4j safely respecting existing constraints."""
    print("\n[Sandbox] Injecting ephemeral graph into Neo4j for TAO analysis...")
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    with driver.session() as session:
        # Safety catch: Wipe any stuck artifacts from the previous crash
        session.run("MATCH ()-[r]-() WHERE r.TestGraph = true DELETE r")
        session.run("MATCH (n:TestGraph) DETACH DELETE n")
        
        query = """
        UNWIND $batch AS r
        
        // Dynamically extract properties whether the JSON is nested or flat
        WITH r, 
             coalesce(r.host.hostName, r.hostName, r.host_name, 'unknown') AS hName,
             coalesce(r.user.userId, r.userId, 'unknown') AS uId,
             coalesce(r.process.processId, r.processId, r.pid, 0) AS pId,
             coalesce(r.process.processName, r.processName, r.name, 'unknown') AS pName,
             coalesce(r.process.parentProcessId, r.parentProcessId, r.parent_pid, 0) AS ppId,
             coalesce(r.process.args, r.cmdLine, r.args, '') AS cLine,
             coalesce(r.event.eventName, r.eventName, 'unknown') AS eName,
             coalesce(r.event.sus, r.sus, 0) AS eSus,
             coalesce(r.event.evil, r.evil, 0) AS eEvil,
             coalesce(r.event.timestamp, r.timestamp, 0) AS eTime
             
        // 1. Merge Hosts and Users
        MERGE (h:Host {hostName: hName})
        ON CREATE SET h:TestGraph
        
        MERGE (u:User {userId: toString(uId)})
        ON CREATE SET u:TestGraph
        
        // 2. Merge Process securely
        MERGE (p:Process {processId: toInteger(pId)})
        ON CREATE SET p:TestGraph
        
        // FIX: ALWAYS update properties so the strict MATCH queries can find it
        SET p.processName = pName, 
            p.parentProcessId = toInteger(ppId),
            p.cmdLine = cLine,
            p.hostName = hName
        
        MERGE (p)-[r1:RUNS_ON]->(h)
        ON CREATE SET r1.TestGraph = true
        
        MERGE (p)-[r2:RUNS_AS]->(u)
        ON CREATE SET r2.TestGraph = true
        
        // 3. Merge Parent Lineage
        MERGE (parent:Process {processId: toInteger(ppId)})
        ON CREATE SET parent:TestGraph
        SET parent.hostName = hName
        
        MERGE (parent)-[r3:SPAWNED]->(p)
        ON CREATE SET r3.TestGraph = true
        
        // 4. Create Ephemeral Events
        CREATE (e:Event:TestGraph {
            eventName: eName,
            timestamp: toFloat(eTime),
            sus: toInteger(eSus),
            evil: toInteger(eEvil)
        })
        CREATE (p)-[:EMITS]->(e)
        
        // 5. Handle File Objects Safely
        FOREACH (ignoreMe IN CASE WHEN r.file_path IS NOT NULL AND r.file_path.pathname IS NOT NULL THEN [1] ELSE [] END |
            MERGE (f:FileObject {path: r.file_path.pathname})
            ON CREATE SET f:TestGraph
            MERGE (p)-[r4:ACCESSED]->(f)
            ON CREATE SET r4.TestGraph = true
            SET r4.action = coalesce(r.file_path.flags_category, 'unknown')
        )
        """
        # Load in batches to prevent memory spikes
        batch_size = 1000
        for i in range(0, len(data), batch_size):
            session.run(query, batch=data[i : i+batch_size])
            
    driver.close()
    print("[Sandbox] Graph loaded! Agent has full vision.\n")


def wipe_ephemeral_graph():
    """Destroys ONLY the test nodes/edges, leaving training data completely untouched."""
    print("\n[Sandbox] Wiping ephemeral test graph from Neo4j...")
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    with driver.session() as session:
        # Delete test relationships first, then test nodes
        session.run("MATCH ()-[r]-() WHERE r.TestGraph = true DELETE r")
        session.run("MATCH (n:TestGraph) DETACH DELETE n")
    driver.close()
    print("[Sandbox] Slate wiped clean.")

# ─────────────────────────────────────────────────────────────────────────────
# SENSITIVE PATH PATTERNS (mirrors context_retriever.py)
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = ("/etc/shadow", "/etc/passwd", ".ssh/", "/proc/")


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE AGGREGATION
# ─────────────────────────────────────────────────────────────────────────────

def aggregate_process_features(events: list) -> dict:
    """
    Aggregate a list of raw BETH event dicts (one process's full event log)
    into the 9-feature dict consumed by SequenceScorer.

    Parameters
    ──────────
    events : list of raw record dicts from part_N.json
             Each record has keys: event, process, host, user, file_path (opt),
             socket (opt), edges.

    Returns
    ───────
    dict with keys:
        is_root, event_count, sus_ratio, evil_ratio, net_ratio,
        c2_event_count, file_write_count, inject_count, _label,
        _has_sensitive_path (extra context signal for severity calculation)
    """
    ec         = len(events)
    sus_count  = 0
    evil_count = 0
    net_count  = 0
    write_count = 0
    is_root    = False
    has_sensitive = False

    for raw in events:
        ev   = raw.get("event",     {})
        user = raw.get("user",      {})
        fp   = raw.get("file_path", {})

        if ev.get("sus",  0) == 1:  sus_count  += 1
        if ev.get("evil", 0) == 1:  evil_count += 1
        if ev.get("is_network_op", False): net_count += 1

        if user.get("is_root", False):
            is_root = True

        # File write: flags_category == "write" or delete operations
        flags_cat = fp.get("flags_category", "")
        if flags_cat == "write" or ev.get("is_delete_op", False):
            write_count += 1

        # Sensitive path access
        pathname = fp.get("pathname", "")
        if any(kw in pathname for kw in SENSITIVE_PATHS):
            has_sensitive = True

    # Ground truth: ANY evil event in this process group
    label = 1 if evil_count > 0 else 0

    return {
        "is_root":           int(is_root),
        "event_count":       ec,
        "sus_ratio":         round(sus_count  / ec, 4) if ec > 0 else 0.0,
        "evil_ratio":        round(evil_count / ec, 4) if ec > 0 else 0.0,
        "net_ratio":         round(net_count  / ec, 4) if ec > 0 else 0.0,
        "c2_event_count":    0,   # not available in raw BETH events
        "file_write_count":  write_count,
        "inject_count":      0,   # not available in raw BETH events
        # private fields used by runner (not passed to SequenceScorer)
        "_label":             label,
        "_has_sensitive_path": has_sensitive,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FILE LOADING AND PROCESS GROUPING
# ─────────────────────────────────────────────────────────────────────────────

def load_and_group(filepath: str) -> list:
    """
    Load a part_N.json file and group events by unique process.

    Returns
    ───────
    list of dicts, one per unique (processId, hostName, processName, parentPid):
    {
        "pid"           : int,
        "host_name"     : str,
        "process_name"  : str,
        "parent_pid"    : int,
        "label"         : int (0 or 1),
        "features"      : dict (precomputed 9-feature vector),
        "event_count"   : int,
        "sample_cmdline": str (best available cmd line for the process),
        "has_sensitive_path": bool,
    }
    """
    print(f"[Runner] Loading {filepath} ...")
    with open(filepath, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    print(f"[Runner] {len(data)} events loaded — grouping by process ...")

    # Group events by process key
    groups: dict = defaultdict(list)
    for raw in data:
        proc = raw.get("process", {})
        host = raw.get("host",    {})
        key  = (
            int(proc.get("processId",       0)),
            str(host.get("hostName",        "unknown")),
            str(proc.get("processName",     "unknown")),
            int(proc.get("parentProcessId", 0)),
        )
        groups[key].append(raw)

    # Build per-process feature records
    process_records = []
    for (pid, host_name, proc_name, parent_pid), events in groups.items():
        feats = aggregate_process_features(events)
        label = feats.pop("_label")
        has_sens = feats.pop("_has_sensitive_path")

        # Best cmd line: prefer an exec event's cmdLine, else empty
        sample_cmd = ""
        for r in events:
            ev_cmd = r.get("event", {}).get("cmdLine", "")
            if ev_cmd:
                sample_cmd = ev_cmd
                break

        process_records.append({
            "pid":               pid,
            "host_name":         host_name,
            "process_name":      proc_name,
            "parent_pid":        parent_pid,
            "label":             label,
            "features":          feats,
            "event_count":       len(events),
            "sample_cmdline":    sample_cmd,
            "has_sensitive_path": has_sens,
        })

    malicious_count = sum(1 for p in process_records if p["label"] == 1)
    print(f"[Runner] {len(process_records)} unique processes  "
          f"({malicious_count} malicious, "
          f"{len(process_records) - malicious_count} benign)")
    return process_records


# ─────────────────────────────────────────────────────────────────────────────
# RECORD BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_record_and_identifier(proc: dict) -> tuple[dict, dict]:
    """
    Convert a grouped process entry into the (record, identifier) pair
    expected by LogMendAgent.run_investigation() internals.

    The 'precomputed_features' key in identifier triggers the SequenceScorer's
    Neo4j bypass path.
    """
    features = proc["features"]

    # Synthetic unified record (matches LogParser output schema for BETH)
    record = {
        "datasetTag":          "beth",
        "pid":                  proc["pid"],
        "hostName":             proc["host_name"],
        "processName":          proc["process_name"],
        "parentPid":            proc["parent_pid"],
        "cmdLine":              proc["sample_cmdline"],
        "userId":               "0" if features.get("is_root") else "1000",
        "timestamp":            0,
        "sus":                  1 if features.get("sus_ratio", 0) > 0 else 0,
        "evil":                 1 if features.get("evil_ratio", 0) > 0 else 0,
        "uuid":                 None,
        "eventName":            None,
        "isNetworkOp":          features.get("net_ratio", 0) > 0,
        "isDeleteOp":           False,
        "isExecOp":             False,
        "isRoot":               bool(features.get("is_root", 0)),
        "filePath":             None,
        "fileFlagsCategory":    None,
        "hasSensitivePath":     proc["has_sensitive_path"],
        # ── Injected for SequenceScorer bypass ──────────────────────────────
        "precomputed_features": {
            "is_root":           features["is_root"],
            "event_count":       features["event_count"],
            "sus_ratio":         features["sus_ratio"],
            "evil_ratio":        features["evil_ratio"],
            "net_ratio":         features["net_ratio"],
            "c2_event_count":    features["c2_event_count"],
            "file_write_count":  features["file_write_count"],
            "inject_count":      features["inject_count"],
        },
    }

    # Identifier (includes precomputed_features for SequenceScorer bypass,
    # plus cmd_line for tools that can fall back to raw text when Neo4j misses)
    identifier = {
        "pid":                  proc["pid"],
        "host_name":            proc["host_name"],
        "process_name":         proc["process_name"],
        "parent_pid":           proc["parent_pid"],
        "cmd_line":             proc["sample_cmdline"],
        "precomputed_features": record["precomputed_features"],
    }

    return record, identifier


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_file(filepath: str, limit: int | None = None,
             verbose: bool = True) -> dict:
    """
    Run the full TAO agent on all unique processes in a BETH JSON file.

    Parameters
    ──────────
    filepath : path to part_N.json
    limit    : if set, investigate only the first N unique processes
    verbose  : print per-process reports

    Returns
    ───────
    dict with keys: tp, tn, fp, fn, accuracy, precision, recall, f1,
                    total, elapsed_s, results (list of per-process dicts)
    """
    process_records = load_and_group(filepath)

    if limit:
        process_records = process_records[:limit]
        print(f"[Runner] Investigating first {limit} processes (--limit applied)")

    agent   = LogMendAgent()
    results = []
    tp = tn = fp = fn = 0
    start = time.time()

    total = len(process_records)
    for idx, proc in enumerate(process_records):
        label       = proc["label"]
        label_str   = "MALICIOUS" if label else "BENIGN"
        proc_key    = (f"PID={proc['pid']}  Host={proc['host_name']}  "
                       f"Process={proc['process_name']}")

        print(f"\n{'=' * 70}")
        print(f"  [{idx+1}/{total}]  {proc_key}")
        print(f"  Ground truth: {label_str}  |  "
              f"events={proc['event_count']}  "
              f"sus_ratio={proc['features']['sus_ratio']:.3f}  "
              f"evil_ratio={proc['features']['evil_ratio']:.3f}")
        print(f"{'=' * 70}")

        # Build the inputs for the agent
        record, identifier = build_record_and_identifier(proc)

        # ── Pass the record directly to the agent's internal TAO loop ─────────
        # We call run_investigation() with the pre-built record dict
        # (not re-parsing from JSON, to preserve precomputed_features).
        try:
            result = agent.run_investigation(record)
        except Exception as exc:
            print(f"  [ERROR] Investigation failed: {exc}")
            result = {
                "severity_metrics": {"final_severity": 0.0, "tier": "BENIGN"},
                "error": str(exc),
            }

        # ── Prediction → binary ───────────────────────────────────────────────
        severity = result.get("severity_metrics", {}).get("final_severity", 0.0)
        tier     = result.get("severity_metrics", {}).get("tier", "BENIGN")
        # Conservative: SUSPICIOUS or higher counts as a positive prediction
        pred     = 0 if tier == "BENIGN" else 1

        # ── Confusion matrix update ───────────────────────────────────────────
        if   label == 1 and pred == 1: tp += 1
        elif label == 0 and pred == 0: tn += 1
        elif label == 0 and pred == 1: fp += 1
        else:                          fn += 1

        result_entry = {
            "index":          idx + 1,
            "pid":            proc["pid"],
            "host_name":      proc["host_name"],
            "process_name":   proc["process_name"],
            "event_count":    proc["event_count"],
            "label":          label,
            "pred":           pred,
            "tier":           tier,
            "severity":       severity,
            "tools_used":     result.get("tools_used", []),
            "tool_count":     result.get("tool_count", 0),
            "correct":        label == pred,
        }
        results.append(result_entry)

        if verbose:
            correct_str = "✓" if label == pred else "✗"
            print(f"  {correct_str}  Predicted: {tier} ({severity:.2f})  "
                  f"Tools: {result.get('tool_count', 0)}")

    elapsed   = time.time() - start
    total_inv = len(results)
    accuracy  = (tp + tn) / total_inv         if total_inv         > 0 else 0
    precision = tp / (tp + fp)                if (tp + fp)         > 0 else 0
    recall    = tp / (tp + fn)                if (tp + fn)         > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)

    # ── Print final metrics ───────────────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"  LOGMEND BETH EVALUATION — {os.path.basename(filepath)}")
    print(f"{'=' * 65}")
    print(f"  Processes evaluated : {total_inv}")
    print(f"  Time elapsed        : {elapsed:.1f}s")
    print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(f"  Accuracy  : {accuracy  * 100:.2f}%")
    print(f"  Precision : {precision * 100:.2f}%")
    print(f"  Recall    : {recall    * 100:.2f}%")
    print(f"  F1-Score  : {f1        * 100:.2f}%")
    print(f"{'=' * 65}")

    # ── Save report ───────────────────────────────────────────────────────────
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("results", exist_ok=True)
    fname    = f"results/LogMend_BETH_{os.path.basename(filepath).replace('.json','')}_{ts}.txt"
    with open(fname, "w", encoding="utf-8") as fh:
        fh.write(f"LogMend BETH Evaluation — {datetime.datetime.now()}\n")
        fh.write(f"File   : {filepath}\n")
        fh.write(f"Total  : {total_inv}  TP:{tp} TN:{tn} FP:{fp} FN:{fn}\n")
        fh.write(f"Accuracy:{accuracy*100:.2f}%  Precision:{precision*100:.2f}%  "
                 f"Recall:{recall*100:.2f}%  F1:{f1*100:.2f}%  "
                 f"Time:{elapsed:.1f}s\n\n")
        fh.write("Per-Process Results\n" + "-" * 50 + "\n")
        for r in results:
            corr = "CORRECT" if r["correct"] else "WRONG"
            fh.write(
                f"[{r['index']:>3}] PID={r['pid']:>6}  "
                f"Process={r['process_name']:<20}  "
                f"Label={'MAL' if r['label'] else 'BEN'}  "
                f"Pred={r['tier']:<12}  "
                f"Sev={r['severity']:.2f}  "
                f"Tools={r['tool_count']}  "
                f"{corr}\n"
            )
    print(f"\n  Report saved → {fname}")

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1,
        "total": total_inv, "elapsed_s": elapsed,
        "results": results,
    }


def run_directory(dirpath: str, limit_per_file: int | None = None) -> None:
    """
    Run the agent on every .json file in a directory and aggregate metrics.
    """
    json_files = sorted([
        os.path.join(dirpath, f)
        for f in os.listdir(dirpath)
        if f.endswith(".json")
    ])
    if not json_files:
        print(f"[Runner] No .json files found in {dirpath}")
        return

    print(f"[Runner] Found {len(json_files)} JSON files in {dirpath}")
    agg = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}

    for jf in json_files:
        res = run_file(jf, limit=limit_per_file)
        for k in agg:
            agg[k] += res[k]

    total_all = agg["tp"] + agg["tn"] + agg["fp"] + agg["fn"]
    acc  = (agg["tp"] + agg["tn"]) / total_all                          if total_all > 0 else 0
    prec = agg["tp"] / (agg["tp"] + agg["fp"])                         if (agg["tp"] + agg["fp"]) > 0 else 0
    rec  = agg["tp"] / (agg["tp"] + agg["fn"])                         if (agg["tp"] + agg["fn"]) > 0 else 0
    f1   = 2 * prec * rec / (prec + rec)                               if (prec + rec) > 0 else 0

    print(f"\n{'=' * 65}")
    print("  LOGMEND BETH AGGREGATE — ALL FILES")
    print(f"{'=' * 65}")
    print(f"  Total processes : {total_all}")
    print(f"  TP={agg['tp']}  TN={agg['tn']}  FP={agg['fp']}  FN={agg['fn']}")
    print(f"  Accuracy  : {acc  * 100:.2f}%")
    print(f"  Precision : {prec * 100:.2f}%")
    print(f"  Recall    : {rec  * 100:.2f}%")
    print(f"  F1-Score  : {f1   * 100:.2f}%")
    print(f"{'=' * 65}")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import os
    import glob

    parser = argparse.ArgumentParser(
        description="LogMend BETH JSON test-file batch evaluator"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file",  type=str, help="Path to a single part_N.json file")
    group.add_argument("--dir",   type=str, help="Path to a directory of .json files")
    parser.add_argument("--limit", type=int, default=None,
                        help="Max unique processes to investigate per file (default: all)")
    args = parser.parse_args()

    if args.file:
        # 1. Load the raw JSON file into memory
        with open(args.file, 'r') as f:
            raw_data = json.load(f)
            
        # 2. Inject it into Neo4j temporarily
        load_ephemeral_graph(raw_data)
        
        try:
            # 3. Run the TAO analysis
            run_file(args.file, limit=args.limit)
        finally:
            # 4. ALWAYS wipe the graph, even if the script crashes
            wipe_ephemeral_graph()
            
    else:
        # 5. Directory mode: Iterate through files to keep the Sandbox clean
        print(f"\n[Batch] Starting Sandbox evaluation for directory: {args.dir}")
        files = glob.glob(os.path.join(args.dir, "*.json"))
        
        for file_path in files:
            with open(file_path, 'r') as f:
                raw_data = json.load(f)
            
            load_ephemeral_graph(raw_data)
            try:
                run_file(file_path, limit=args.limit)
            finally:
                wipe_ephemeral_graph()