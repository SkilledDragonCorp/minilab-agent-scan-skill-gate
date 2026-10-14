"""CLI: skill-gate check / changed."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from skill_gate.discover import (
    PathOutsideRootError,
    discover_targets,
    group_inspect_paths,
    resolve_inside,
)
from skill_gate.normalize import highest_severity, merge_scan_risks, normalize_inspect
from skill_gate.report import write_report
from skill_gate.rules import Finding, scan_components, severity_at_least
from skill_gate.runner import ToolError, run_agent_scan

EXIT_PASS = 0
EXIT_RISK = 1
EXIT_TOOL = 2


def _repo_root() -> Path:
    env_root = os.environ.get("SKILL_GATE_ROOT")
    if env_root:
        return Path(env_root).resolve()
    return Path.cwd().resolve()


def _load_dotenv(root: Path) -> None:
    env_path = root / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _git_changed_files(root: Path, base: str) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "diff", "--name-only", f"{base}...HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError("git not found on PATH") from exc
    if proc.returncode != 0:
        # Fallback: unstaged + staged against base without triple-dot
        proc = subprocess.run(
            ["git", "diff", "--name-only", base],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        raise ToolError(f"git diff failed: {(proc.stderr or proc.stdout)[:300]}")
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _changed_targets(root: Path, base: str) -> list[Path]:
    names = _git_changed_files(root, base)
    candidates: list[Path] = []
    for name in names:
        path = root / name
        if not path.exists():
            continue
        rel = name.replace("\\", "/")
        if path.name == "SKILL.md":
            candidates.append(path)
        elif rel.endswith(".mcp.json") or rel.endswith("/mcp.json") or rel == ".mcp.json":
            candidates.append(path)
        elif rel.endswith(".claude/settings.json") or rel.endswith("/.claude/settings.json"):
            candidates.append(path)
        elif rel.endswith(".cursor/mcp.json"):
            candidates.append(path)
    return candidates


def run_check(
    root: Path,
    raw_paths: list[str],
    *,
    fail_on: str,
    as_json: bool,
    write_reports: bool = True,
) -> int:
    try:
        paths = [resolve_inside(root, p) for p in raw_paths]
    except PathOutsideRootError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_TOOL

    targets = discover_targets(root, paths)
    if not targets:
        print("error: no SKILL.md or MCP config files found under given paths", file=sys.stderr)
        return EXIT_TOOL

    inspect_paths = group_inspect_paths(targets)
    try:
        inspect_result = run_agent_scan("inspect", inspect_paths)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_TOOL

    if inspect_result.payload is None:
        print("error: inspect returned empty JSON payload", file=sys.stderr)
        return EXIT_TOOL

    components = normalize_inspect(inspect_result.payload)
    findings: list[Finding] = scan_components(components)

    scan_payload: dict[str, Any] | list[Any] | None = None
    snyk_token = os.environ.get("SNYK_TOKEN", "").strip()
    if snyk_token:
        try:
            with tempfile.TemporaryDirectory(prefix="skill-gate-scan-") as tmp:
                storage = Path(tmp) / "storage"
                scan_result = run_agent_scan(
                    "scan",
                    inspect_paths,
                    storage_file=storage,
                    extra_env={"SNYK_TOKEN": snyk_token},
                )
                scan_payload = scan_result.payload
                if scan_payload is not None:
                    components = merge_scan_risks(components, scan_payload)
        except ToolError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_TOOL

    finding_dicts = [f.to_dict() for f in findings]
    # Map scan issues without numeric severity into medium when present.
    for comp in components:
        for risk in comp.get("scan_risks") or []:
            if "_scan_path_response" in risk:
                continue
            sev = str(risk.get("severity") or risk.get("level") or "medium").lower()
            finding_dicts.append(
                {
                    "rule_id": "snyk-agent-scan",
                    "severity": sev if sev in {"low", "medium", "high", "critical"} else "medium",
                    "message": str(risk.get("message") or risk.get("title") or risk),
                    "path": str(comp.get("path") or ""),
                    "evidence": str(risk.get("id") or risk.get("code") or "")[:160],
                }
            )

    blocked = [f for f in finding_dicts if severity_at_least(str(f["severity"]), fail_on)]
    report = {
        "tool": "skill-gate",
        "mode": "check",
        "fail_on": fail_on,
        "snyk_token_configured": bool(snyk_token),
        "targets": [str(t.relative_to(root)) for t in targets],
        "inspect_paths": [str(p) for p in inspect_paths],
        "components": [
            {
                "kind": c.get("kind"),
                "name": c.get("name"),
                "path": c.get("path"),
                "file_count": len(c.get("files") or []),
                "scan_risk_count": len(
                    [r for r in (c.get("scan_risks") or []) if "_scan_path_response" not in r]
                ),
            }
            for c in components
        ],
        "findings": finding_dicts,
        "blocked_findings": blocked,
        "highest_severity": highest_severity(finding_dicts),
        "passed": len(blocked) == 0,
        "scan_path_responses_present": bool(
            isinstance(scan_payload, dict) and scan_payload.get("scan_path_responses")
        )
        if scan_payload is not None
        else False,
    }

    if write_reports:
        write_report(root, "skill-gate", report)

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print(f"targets: {len(targets)}")
        print(f"findings: {len(finding_dicts)} (blocked at {fail_on}+: {len(blocked)})")
        for finding in blocked[:20]:
            print(
                f"  [{finding['severity']}] {finding['rule_id']}: "
                f"{finding['message']} ({finding['path']})"
            )
        if report["passed"]:
            print("PASS")
        else:
            print("FAIL")

    return EXIT_PASS if report["passed"] else EXIT_RISK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill-gate",
        description="Gate new skills/MCP configs with Snyk Agent Scan + local rules",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Inspect paths and apply local (and optional live) rules")
    check.add_argument("paths", nargs="+", help="Files or directories inside the repository")
    check.add_argument("--json", action="store_true", help="Emit JSON report on stdout")
    check.add_argument(
        "--fail-on",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="Fail when a finding reaches this severity (default: medium)",
    )

    changed = sub.add_parser("changed", help="Check skills/MCP configs changed vs a git base")
    changed.add_argument(
        "--base",
        default="origin/main",
        help="Git base ref for diff (default: origin/main)",
    )
    changed.add_argument("--json", action="store_true", help="Emit JSON report on stdout")
    changed.add_argument(
        "--fail-on",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="Fail when a finding reaches this severity (default: medium)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = _repo_root()
    _load_dotenv(root)

    try:
        if args.command == "check":
            return run_check(
                root,
                args.paths,
                fail_on=args.fail_on,
                as_json=args.json,
            )
        if args.command == "changed":
            targets = _changed_targets(root, args.base)
            if not targets:
                report = {
                    "tool": "skill-gate",
                    "mode": "changed",
                    "base": args.base,
                    "targets": [],
                    "findings": [],
                    "passed": True,
                    "message": "no changed skill/MCP paths",
                }
                write_report(root, "skill-gate", report)
                if args.json:
                    print(json.dumps(report, indent=2))
                else:
                    print("PASS (no changed skill/MCP paths)")
                return EXIT_PASS
            return run_check(
                root,
                [str(t) for t in targets],
                fail_on=args.fail_on,
                as_json=args.json,
            )
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_TOOL

    parser.error(f"unknown command {args.command}")
    return EXIT_TOOL


if __name__ == "__main__":
    raise SystemExit(main())
