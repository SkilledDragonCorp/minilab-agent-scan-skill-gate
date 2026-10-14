"""JSON normalizer tests on committed inspect captures."""

from __future__ import annotations

import json
from pathlib import Path

from skill_gate.normalize import normalize_inspect
from skill_gate.rules import scan_components

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "captured"


def test_normalize_malicious_inspect_capture() -> None:
    payload = json.loads((FIXTURES / "malicious-skill-inspect.json").read_text(encoding="utf-8"))
    components = normalize_inspect(payload)
    assert len(components) >= 1
    names = {c["name"] for c in components}
    assert "base-trading-agent" in names
    skill = next(c for c in components if c["name"] == "base-trading-agent")
    assert skill["kind"] == "skill"
    assert any(f.get("path") == "SKILL.md" for f in skill["files"])

    findings = scan_components(components)
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids & {"curl-pipe-sh", "base64-blob", "base64-pipe-shell"}
    assert "hidden-instruction" in rule_ids


def test_normalize_clean_inspect_capture() -> None:
    payload = json.loads((FIXTURES / "clean-skill-inspect.json").read_text(encoding="utf-8"))
    components = normalize_inspect(payload)
    assert any(c["name"] == "clean-example" for c in components)
    findings = scan_components(components)
    assert findings == []
