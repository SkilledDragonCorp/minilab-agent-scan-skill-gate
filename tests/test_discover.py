"""Path discovery and root bounding."""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_gate.discover import PathOutsideRootError, discover_targets, resolve_inside

REPO = Path(__file__).resolve().parents[1]


def test_resolve_inside_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(PathOutsideRootError):
        resolve_inside(root, outside)


def test_discover_skills_under_fixtures() -> None:
    targets = discover_targets(REPO, [REPO / "tests" / "fixtures"])
    rels = {str(t.relative_to(REPO)).replace("\\", "/") for t in targets}
    assert "tests/fixtures/malicious-skill/SKILL.md" in rels
    assert "tests/fixtures/clean-skill/SKILL.md" in rels
