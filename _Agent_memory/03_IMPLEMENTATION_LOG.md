# Current Implementation (update in place)

## DARPA cleaning (started 2026-11-14)
- Repo restructured 2026-11-13: code in `logmend/`, entry points in `scripts/` (run as `python -m scripts.<name>`), data in `data/raw` + `data/cleaned`, models in `artifacts/saved_models`, papers in `references/papers`.
- `scripts/clean_darpa.py` added (needs `fastavro`). Streams zip -> gzip -> Avro CDM20, aggregates repeated events into edges.
- THEIA cleaned 2026-11-14: 155.3M raw records -> 20.5M edges, 6.2 GB in `data/cleaned/darpa/theia/{train,val,test}` (7 min, 17 workers).
- NOT done: TRACE cleaning (field mapping unverified), Neo4j loader for cleaned DARPA, labels (C2 IPs / attack processes), user decision on loading every event vs collapsed graph.
- 2026-11-14: single Neo4j instance `22-04-2026_beth` (Enterprise, 127.0.0.1:7687) now has databases `neo4j` (BETH), `theia`, `trace`. Router picks database per dataset (`NEO4J_BETH_DB` default `neo4j`, `NEO4J_THEIA_DB` default `theia`).
- `scripts/load_darpa_neo4j.py` added. THEIA train loaded into `theia`: 205,794 Process, 292,428 FileObject, 7,027 NetFlowObject; 3,599,023 ACCESSED, 199,177 SPAWNED, 10,755 CONNECTED_TO (249 s, 1.1 GB store).
- OPEN: `.env` NEO4J_THEIA_PASS does not match this instance (user must set it to the BETH instance password). None of the 4 C2 IPs in code occur in THEIA netflows. `train_darpa_models.py` file_write_count reads `f.mode/f.action`; new graph stores `writeCount` on the ACCESSED relationship. val/test not loaded. Neo4j heap 1 GB / page cache 512 MB (defaults).
