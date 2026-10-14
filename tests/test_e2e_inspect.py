"""Keyless e2e: real snyk-agent-scan inspect + skill-gate check."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_gate.cli import EXIT_PASS, EXIT_RISK, run_check

REPO = Path(__file__).resolve().parents[1]
MAL = REPO / "tests" / "fixtures" / "malicious-skill"
CLEAN = REPO / "tests" / "fixtures" / "clean-skill"


@pytest.fixture(autouse=True)
def _lab_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKILL_GATE_ROOT", str(REPO))
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    monkeypatch.chdir(REPO)


def test_check_malicious_skill_exits_risk() -> None:
    code = run_check(REPO, [str(MAL)], fail_on="medium", as_json=False, write_reports=True)
    assert code == EXIT_RISK
    report = REPO / "reports" / "skill-gate.json"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "curl-pipe-sh" in text or "base64-blob" in text or "hidden-instruction" in text


def test_check_clean_skill_exits_pass() -> None:
    code = run_check(REPO, [str(CLEAN)], fail_on="medium", as_json=False, write_reports=True)
    assert code == EXIT_PASS
