# LogMend_2 — Project Understanding (Brain-maintained)

Source: Scout inventory 2026-11-13 (01_FINDINGS_AND_MAP.md §1) + LOGMEND2_FLOW_GUIDE.md. Update in place.

## What it is
Agentic security-log analysis: detects anomalous host/provenance behaviour, scores severity, explains it.

## Execution routes
- `main.py` — analyse a single record.
- `json_file_runner.py` — BETH batch: groups records by process, builds a temporary Neo4j graph per batch.

## Reasoning loop
Thought → Action → Observation loop; Ollama-hosted planner LLM; 6 tools (in `tools/`).

## Detection ensemble
- BETH: GraphCL, IsolationForest, DeepSAD.
- DARPA (THEIA/TRACE): MAGIC, FLASH, ORTHRUS.

## Severity
`severity = 0.60 × (anomaly × 10) + 0.40 × impact`; tiers split at 3.5 and 6.5 (low / medium / high).

## Layout
agent/ (2), database/ (2), models/ (11), tools/ (14), utils/ (4), "Research papers used/" (11), venv/ (ignored).
raw_dataset/ 9 files ≈ 8 GB (BETH zips/CSVs, DARPA theia/trace). cleaned_dataset/ 231 files ≈ 1.07 GB (229 part_N.json + 2 DARPA extracts).

## Stack (inferred from venv; no manifest at root)
Python, torch, torch_geometric, scikit-learn, xgboost, transformers, sentence_transformers, neo4j, httpx/requests.

## Known gaps / risks
- BETH batch hard-codes `c2_event_count = 0` and `inject_count = 0`.
- 38 `beth_test_data/part_*.json` deleted in git while guide still references them.
- No requirements.txt / pyproject.
- ~9 GB untracked datasets; .gitignore policy unconfirmed.
- `.env` present (never opened).

## Open questions for user (unanswered as of 2026-11-13)
2. Today's goal.
3. beth_test_data deletion intentional? replaced by cleaned_dataset?
4. Should c2_event_count / inject_count be computed for BETH — definitions?
5. Keep datasets out of git via .gitignore?
