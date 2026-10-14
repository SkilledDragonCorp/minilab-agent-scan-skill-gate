---
name: gate-new-skill
description: Before installing any Claude Code or Cursor skill or MCP server, run skill-gate check on the path and refuse install on exit 1 or 2.
---

# Gate new skill / MCP server

Front-door lock for this repository.

## Before install

1. Identify the skill directory (contains `SKILL.md`) or MCP config path.
2. From the repository root run:

```bash
uv run skill-gate check <path>
```

3. Interpret the exit code:
   - `0` — pass; safe to install for this gate
   - `1` — risk at or above `--fail-on` (default `medium`); do not install
   - `2` — tool error (fail closed); do not install

## Optional live analysis

When `SNYK_TOKEN` is set in the environment (or `.env`), `skill-gate check` also runs `snyk-agent-scan scan` and merges scored risks. Analysis sends component content to Snyk per upstream `TERMS.md`.

## Changed files only

```bash
uv run skill-gate changed --base origin/main
```
