# data/

Large datasets are NOT tracked in git (see .gitignore).

- `raw/beth/`            BETH labelled CSVs (training / validation / testing)
- `raw/darpa/theia|trace/` DARPA TC E5 raw archives (training / validation / testing zips)
- `cleaned/beth/{train,val,test}/` BETH nested-JSON event parts (`part_N.json`)
- `cleaned/darpa/theia/{train,val,test}/` cleaned DARPA THEIA graph tables, built by
  `python -m scripts.clean_darpa --source theia`:
  `processes.jsonl`, `files.jsonl`, `netflows.jsonl`, `principals.jsonl`,
  `edges.jsonl` (one row per process / object / event type, with a count), `summary.json`
- `cleaned/darpa/trace/` not built yet (`--source trace`)
