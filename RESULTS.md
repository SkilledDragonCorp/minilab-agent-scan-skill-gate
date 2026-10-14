# RESULTS

Filled with real numbers from the local ship gate (2026-10-13 CT / 2026-10-14 UTC). CI run URL filled after the first green GitHub Actions run on `main`.

## Pins

| Item | Value |
| --- | --- |
| Upstream SHA | `2d244047643decb874a197bc64cbe6fc3e586f2a` |
| Upstream tag | `v0.6.8` |
| PyPI | `snyk-agent-scan==0.6.8` |
| gitleaks | `v8.30.1` (linux_x64 SHA256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`) |
| Python (lab / CI) | `3.12.14` (`.python-version`) |
| uv | `0.12.17` |
| cryptography (locked) | `50.0.2` |

## Local ship gate

| Check | Result |
| --- | --- |
| `uv run pytest -q` | **7 passed, 1 skipped** in 28.98s (`live` skipped without `SNYK_TOKEN`) |
| `uv run ruff check .` | exit 0 |
| `uv run ruff format --check .` | exit 0 |
| `python3 scripts/check-skills` | skills-layout OK |
| `python3 scripts/check-banned-phrases` | banned-phrases OK |
| `python3 scripts/check-upstream-parity` | upstream-parity OK |
| `uv export --frozen --format requirements-txt --no-emit-project` + `uvx pip-audit --strict` | No known vulnerabilities found |
| `uv run skill-gate check tests/fixtures/malicious-skill` | exit **1** (fail closed; findings include `base64-pipe-shell`, `hidden-instruction`) |
| `uv run skill-gate check tests/fixtures/clean-skill` | exit **0** |
| Report | `reports/skill-gate.json` |
| CI run URL | pending first green `main` run |

## Upstream unit (A2 / A2b)

Reproduced at the pin with `AGENT_SCAN_ENVIRONMENT=test` and `SNYK_TOKEN=lab-placeholder-not-a-token`:

```text
FAILED tests/unit/test_consent.py::test_collect_consent_redacts_url_query_values_without_changing_destination
  [https://example.test:8443/Mcp%2fPath?api_key=...]
  AssertionError: assert '      URL    : ' == '      URL    : https://example.test:8443/Mcp%2fPath?api_key=***&token=***&sig=***'
```

Rich wraps the long URL onto the next line, leaving `URL    : ` empty. Documented as deviation **A2b**; `upstream-unit` deselects that node id.

## Deviation log

| Id | Note |
| --- | --- |
| A1 | Checkout uses `submodules: recursive`, `persist-credentials: false`; upstream steps use `working-directory: upstream`; uv cache glob `upstream/uv.lock`. Pre-commit runs inside `upstream/` (lab wrapper for `pre-commit/action`). |
| A2 | Keyless job `upstream-unit` on `ubuntu-latest` only; `AGENT_SCAN_ENVIRONMENT=test`; `SNYK_TOKEN=lab-placeholder-not-a-token`; pytest unit command with `--frozen`. |
| A2b | `--deselect tests/unit/test_consent.py::test_collect_consent_redacts_url_query_values_without_changing_destination` (rich URL wrap). |
| A3 | Artifact upload steps removed. |
