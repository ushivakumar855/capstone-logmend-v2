# _Agent_memory — READ THIS FOLDER FIRST

Every agent (Claude Code, Antigravity, Codex, sub-agents) must read this folder before doing anything.
Work is already under way — do NOT restart discovery.

## Files
| File | Owner | Rule |
|---|---|---|
| 00_README.md | Brain | This index + operating protocol |
| 01_FINDINGS_AND_MAP.md | Scout appends | Numbered sections; codebase/data map and findings |
| 02_PROJECT_UNDERSTANDING.md | Brain | Deep understanding of LogMend (pipeline, scoring, decisions, open questions) |
| 03_IMPLEMENTATION_LOG.md | Builder | CURRENT task only — update in place, do not append history |
| completed_implementation.md | Brain/Builder | Finished tasks move here from 03 |

Daily design/plans: `docs/<YYYY-MM-DD>/design/` then `docs/<YYYY-MM-DD>/plans/`.

## Operating protocol
1. **Brain** (main agent): design, failure analysis, specs, decisions; owns this folder. Never reads raw source, large configs, data or logs itself; short greps of test summaries and `ps` are fine.
2. **Scout** (Haiku, low effort): all inspection; read-only; narrow prompts; appends to 01 as a new numbered section; replies with a short summary. Ignores `logs/ .git/ venv/ node_modules/ __pycache__/`, CSV/Parquet, `.db`, `*.bak*`, `data/ results/` contents; never opens `.env` unless a narrow exception is granted.
3. **Builder** (Sonnet, medium effort): all code and tests, only after the user approves a spec. Snapshots every existing file before first edit (e.g. `file.py` → `_snapshots/<date>/file.py`), never runs tests, never restarts services, logs to 03. Resume the same builder for follow-ups.
4. **Human-in-the-loop**: never guess business logic, risk rules or execution flow — ask numbered questions and wait.
5. User may execute plans with **Antigravity or Codex**; plans must be self-contained.

## Environment notes
- Windows 11. Folder ACL was restricted to `CodexSandboxUsers`; user granted Student Modify on 2026-11-13. If writes fail with EPERM again, check `icacls` first.
