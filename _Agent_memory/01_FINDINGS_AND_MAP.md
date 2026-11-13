## 1. Session 2026-11-13 — Inventory of existing memory, docs, and layout

Scope: read-only scout pass. Excluded: logs/, .git/, venv/, __pycache__/, CSV/Parquet, .db, *.bak*, .env. raw_dataset/, cleaned_dataset/, beth_test_data/ listed by name/count/size only.

### 1.1 Memory and docs
- _Agent_memory/: does not exist and could not be created (mkdir: Permission denied). This section was intended for _Agent_memory/01_FINDINGS_AND_MAP.md and is saved here instead. No prior numbered sections exist, so this is section 1.
- _quant_brain/: does not exist. docs/: does not exist.
- CLAUDE.md / AGENTS.md: neither exists at repo root.
- Other markdown: README.md (root, 6.3 KB, 2025-09-29) and LOGMEND2_FLOW_GUIDE.md (root, 19.8 KB, 2026-11-13, untracked).

### 1.2 LOGMEND2_FLOW_GUIDE.md summary
- Purpose: end-to-end flow of LogMend 2.0 from BETH/DARPA raw logs through parsing and tools to severity tier and report.
- Entry routes: main.py single record (LogMendAgent.run_investigation); json_file_runner.py BETH batch (groups events by (processId, hostName, processName, parentProcessId), 9-feature vector, temporary Neo4j graph tagged TestGraph, wiped per file).
- Loop: Thought/Action/Observation with Ollama planner; six tools (SequenceScorer, DescriptionGenerator, RuleMatcher, ContextRetriever, TTPMapper, ThreatLookup), each used once; thresholds 0.75 malicious / 0.85 benign.
- Scoring: BETH GraphCL 0.40 / IsolationForest 0.30 / DeepSAD 0.30; DARPA MAGIC 0.40 / FLASH 0.35 / ORTHRUS 0.25.
- Severity: 0.60 x (anomaly x 10) + 0.40 x impact; BENIGN < 3.5, SUSPICIOUS 3.5 to < 6.5, MALICIOUS >= 6.5.
- Status: describes implemented code; no done/pending section. Inferred gap: BETH batch sets c2_event_count and inject_count to 0.

### 1.3 Git state at session start
- Branch logmend-full-upload-20260831; main is main. Last commits: 4b9ef2a "Pushing latest updates", 401c74a "Add LogMend security log analysis project".
- Unstaged deletions: 38 files under beth_test_data/ (part_1..part_38.json).
- Untracked: LOGMEND2_FLOW_GUIDE.md, cleaned_dataset/, raw_dataset/.

### 1.4 Top-level directory map
| Path | Purpose (guess) | Files |
|---|---|---|
| agent/ | LogMend agent loop | 2 |
| database/ | Neo4j router | 2 |
| models/ | architectures, saved_models/ | 11 |
| tools/ | six investigation tools, parser, threat KB | 14 |
| utils/ | severity calculator, helpers | 4 |
| Research papers used/ | reference PDFs | 11 |
| venv/ | virtualenv (ignored) | ~35,962 |
| raw_dataset/ | raw BETH CSV zips and DARPA zips | 9 files, 7.98 GB |
| cleaned_dataset/ | beth_cleaned_dataset/{train,val,test}, darpa_cleaned_dataset/ | 231 files, 1.07 GB |
| beth_test_data/ | BETH test event JSON parts (38 deleted in git) | not inspected |
| logs/ | run logs (ignored) | not inspected |
| __pycache__/ | bytecode (ignored) | 1 |

Root files: main.py, json_file_runner.py, train_beth_models.py, train_darpa_models.py, evaluate_metrics.py, test_batch2.py, test_connections.py, test_tools.py, README.md, LOGMEND2_FLOW_GUIDE.md, .env (not opened), .gitignore, .gitattributes.

raw_dataset/ (names only): beth/ with Training-NTNZ-N-N.zip (2), Validation-NTNZ-N-N.zip (2), Testing-NTNZ-N-N.zip (2), labelled_{training,validation,testing}_data.csv; DARPA raw data/ with theia_E5_prototype/ and trace_E5_prototype/.

cleaned_dataset/ (names only): 229 x part_N.json; 2 x extracted DARPA src_taN-theia-N-eN-official-N.bin.N-NTNZ-N-N.zip pattern.

### 1.5 Tech stack (manifests only)
- No requirements.txt, pyproject.toml, setup.py, setup.cfg, Pipfile, or package.json at root. Stack inferred from venv dist-info names (not authoritative).
- Python; torch, torch_geometric, scikit-learn, xgboost, numpy, scipy, sentence_transformers, transformers, huggingface_hub, networkx, joblib; neo4j driver; httpx, requests, aiohttp, python_dotenv, typer, rich.
- Ollama client not confirmed in the first 60 dist-info names.
- Entry points: main.py, json_file_runner.py, train_beth_models.py, train_darpa_models.py, evaluate_metrics.py.

### 1.6 Open items and ambiguities
- No status tracker in repo. Phase inferred as "pipeline implemented, BETH batch evaluation in use". Confirm with owner.
- beth_test_data/ has 38 deletions in git, yet the guide still references it. Confirm intent.
- .env exists at root; keep it out of commits.
- raw_dataset/ (8 GB) and cleaned_dataset/ (1.1 GB) are untracked; confirm the .gitignore policy.
