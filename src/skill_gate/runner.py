"""Invoke snyk-agent-scan inspect/scan and collect results."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ToolError(RuntimeError):
    """Raised when the featured tool fails or is missing."""


@dataclass(frozen=True)
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    payload: dict[str, Any] | list[Any] | None


def _which_cli() -> str:
    found = shutil.which("snyk-agent-scan")
    if found:
        return found
    raise ToolError(
        "snyk-agent-scan not found on PATH; run `uv sync --locked` then `uv run skill-gate ...`"
    )


def run_agent_scan(
    subcommand: str,
    paths: list[Path],
    *,
    storage_file: Path | None = None,
    timeout: int = 120,
    extra_env: dict[str, str] | None = None,
) -> ToolResult:
    if subcommand not in {"inspect", "scan"}:
        raise ToolError(f"unsupported subcommand: {subcommand}")
    if not paths:
        raise ToolError("no paths to scan")

    cli = _which_cli()
    # Isolate HOME so inspect/scan never prompts for consent against the
    # developer's real MCP server configs. Preserve SNYK_TOKEN via env copy.
    tmp_home = tempfile.TemporaryDirectory(prefix="skill-gate-home-")
    if storage_file is None:
        storage_file = Path(tmp_home.name) / ".mcp-scan"

    cmd = [
        cli,
        subcommand,
        *[str(p) for p in paths],
        "--json",
        "--storage-file",
        str(storage_file),
    ]
    # Never pass --dangerously-run-mcp-servers (lab policy).

    env = os.environ.copy()
    env.setdefault("AGENT_SCAN_ENVIRONMENT", "test")
    env["HOME"] = tmp_home.name
    env["XDG_CONFIG_HOME"] = str(Path(tmp_home.name) / ".config")
    if extra_env:
        env.update(extra_env)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"snyk-agent-scan {subcommand} timed out after {timeout}s") from exc
    finally:
        tmp_home.cleanup()

    payload: dict[str, Any] | list[Any] | None = None
    stdout = proc.stdout or ""
    if stdout.strip():
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ToolError(
                f"snyk-agent-scan {subcommand} returned non-JSON stdout: {exc}"
            ) from exc

    if proc.returncode not in (0, 1):
        # inspect normally exits 0; scan may exit non-zero on findings depending on flags.
        # Treat hard failures (missing binary args, crashes) as tool errors when no JSON.
        if payload is None:
            raise ToolError(
                f"snyk-agent-scan {subcommand} failed (exit {proc.returncode}): "
                f"{(proc.stderr or '')[:400]}"
            )

    return ToolResult(
        command=cmd,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=proc.stderr or "",
        payload=payload,
    )
