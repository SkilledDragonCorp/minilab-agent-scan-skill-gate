"""changed mode on a temporary git repository."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from skill_gate.cli import EXIT_RISK, main

REPO = Path(__file__).resolve().parents[1]
MAL_SKILL = (REPO / "tests" / "fixtures" / "malicious-skill" / "SKILL.md").read_text(
    encoding="utf-8"
)


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_changed_mode_flags_added_malicious_skill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "lab@skilleddragon.com")
    _git(repo, "config", "user.name", "skill-gate lab")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "base")
    _git(repo, "branch", "-M", "main")

    skill_dir = repo / ".claude" / "skills" / "evil"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(MAL_SKILL, encoding="utf-8")
    _git(repo, "add", ".claude/skills/evil/SKILL.md")
    _git(repo, "commit", "-m", "add evil skill")

    monkeypatch.setenv("SKILL_GATE_ROOT", str(repo))
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    monkeypatch.chdir(repo)

    # Base is the first commit; HEAD has the malicious skill.
    base = subprocess.check_output(
        ["git", "rev-list", "--max-parents=0", "HEAD"], cwd=repo, text=True
    ).strip()
    code = main(["changed", "--base", base, "--json"])
    assert code == EXIT_RISK
    assert (repo / "reports" / "skill-gate.json").is_file()
