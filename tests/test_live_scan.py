"""Optional live slice: requires SNYK_TOKEN."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from skill_gate.runner import run_agent_scan

REPO = Path(__file__).resolve().parents[1]
MAL = REPO / "tests" / "fixtures" / "malicious-skill"


@pytest.mark.live
def test_scan_returns_scan_path_responses() -> None:
    if not os.environ.get("SNYK_TOKEN", "").strip():
        pytest.skip("SNYK_TOKEN unset; live slice skipped")

    result = run_agent_scan("scan", [MAL], timeout=180)
    assert result.payload is not None
    assert isinstance(result.payload, dict)
    assert "scan_path_responses" in result.payload
    assert isinstance(result.payload["scan_path_responses"], list)
    assert len(result.payload["scan_path_responses"]) >= 1
