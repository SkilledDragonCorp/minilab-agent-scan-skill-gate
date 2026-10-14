# Security Policy

**Built by [SkilledDragon LLC](https://skilleddragon.com)**

This is a **SkilledDragon educational minilab**, not a production product. We do **not** maintain these repos on a regular schedule and we do **not** operate a vulnerability response program for them.

## Contact

General questions: **hello@skilleddragon.com**  
Do not use a dedicated security mailbox for this repo — none exists.

## If you find an issue

- Prefer reporting **upstream** when the issue is in [snyk/agent-scan](https://github.com/snyk/agent-scan) or [snyk-agent-scan on PyPI](https://pypi.org/project/snyk-agent-scan/).
- For something specific to this minilab’s gate scripts or CI, you may email hello@skilleddragon.com. There is **no SLA**, and we may not patch or reply quickly.

## Supported versions

Only the commit currently on `main` is considered current for this educational lab.

## Secret handling

- Never commit `.env`, API keys, or tokens.
- Secrets are read from environment variables (local `.env` loaded at startup; GitHub Actions secrets in CI).
- Optional `SNYK_TOKEN` enables the live analysis slice; without it, keyless `inspect` + local rules still run.
- Minimum scope for `SNYK_TOKEN`: a personal Snyk account API token able to call Agent Scan analysis (free tier is enough for the lab).

## Tooling pins

| Control | Pin |
| --- | --- |
| Upstream | `snyk/agent-scan` @ `2d244047643decb874a197bc64cbe6fc3e586f2a` (tag `v0.6.8`, Apache-2.0) |
| gitleaks | `v8.30.1` (pre-commit hook + CI binary with SHA256 verify) |
| Dependency audit | `uv export --frozen --format requirements-txt --no-emit-project > /tmp/req.txt` then `uvx pip-audit --strict -r /tmp/req.txt` |

## Upstream license

`snyk/agent-scan` / `snyk-agent-scan` is Apache-2.0. Analysis sends component content to Snyk; see upstream `TERMS.md` at the pin.

Use at your own risk. Pin versions, review the code, and treat this as sample material.
