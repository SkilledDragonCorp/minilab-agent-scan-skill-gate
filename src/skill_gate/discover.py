"""Discover SKILL.md files and MCP config paths under a repo root."""

from __future__ import annotations

from pathlib import Path

SKILL_NAME = "SKILL.md"
MCP_CONFIG_NAMES = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
)


class PathOutsideRootError(ValueError):
    """Raised when a user path escapes the allowed repository root."""


def resolve_inside(root: Path, raw: str | Path) -> Path:
    root = root.resolve()
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate).resolve()
    else:
        candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PathOutsideRootError(f"path escapes repository root: {candidate}") from exc
    return candidate


def discover_targets(root: Path, paths: list[Path]) -> list[Path]:
    """Return SKILL.md files and MCP configs under the given paths."""
    found: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        if path not in seen and path.is_file():
            seen.add(path)
            found.append(path)

    for path in paths:
        if path.is_file():
            name = path.name
            rel = str(path.relative_to(root)).replace("\\", "/")
            if (
                name == SKILL_NAME
                or rel in MCP_CONFIG_NAMES
                or name
                in {
                    ".mcp.json",
                    "mcp.json",
                    "settings.json",
                }
            ):
                # Accept known MCP filenames even outside the exact relative list
                # when the basename matches (settings.json only under .claude/).
                if name == SKILL_NAME:
                    add(path)
                elif name == ".mcp.json" or path.name == "mcp.json":
                    add(path)
                elif name == "settings.json" and ".claude" in path.parts:
                    add(path)
            continue

        if not path.is_dir():
            continue

        for skill in path.rglob(SKILL_NAME):
            add(skill)

        for rel in MCP_CONFIG_NAMES:
            candidate = path / rel if not rel.startswith(".") else path / rel
            # Also search recursively for .mcp.json
            pass

        for mcp_name in (".mcp.json", "mcp.json"):
            for candidate in path.rglob(mcp_name):
                add(candidate)

        for settings in path.rglob("settings.json"):
            if ".claude" in settings.parts:
                add(settings)

        cursor_mcp = path / ".cursor" / "mcp.json"
        if cursor_mcp.is_file():
            add(cursor_mcp)

    return sorted(found)


def group_inspect_paths(targets: list[Path]) -> list[Path]:
    """Prefer skill directories over SKILL.md files for agent-scan inspect."""
    result: list[Path] = []
    seen: set[Path] = set()
    for target in targets:
        if target.name == SKILL_NAME:
            skill_dir = target.parent
            if skill_dir not in seen:
                seen.add(skill_dir)
                result.append(skill_dir)
        else:
            if target not in seen:
                seen.add(target)
                result.append(target)
    return result
