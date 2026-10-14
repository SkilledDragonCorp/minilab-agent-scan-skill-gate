"""Normalize snyk-agent-scan JSON into a lab-owned component list."""

from __future__ import annotations

from typing import Any


def normalize_inspect(payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    """Flatten inspect JSON (path -> entry) into components."""
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = list(payload.values())
    else:
        return []

    components: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for skill in entry.get("skills") or []:
            components.append(
                {
                    "kind": "skill",
                    "name": skill.get("name"),
                    "path": skill.get("installation_path") or entry.get("path"),
                    "installation_path": skill.get("installation_path"),
                    "files": skill.get("files") or [],
                    "description": _skill_description(skill),
                    "error": skill.get("error"),
                    "tools": [],
                }
            )
        for server in entry.get("servers") or []:
            tools = []
            for tool in server.get("tools") or []:
                if isinstance(tool, dict):
                    tools.append(
                        {
                            "name": tool.get("name"),
                            "description": tool.get("description") or "",
                        }
                    )
            components.append(
                {
                    "kind": "mcp_server",
                    "name": server.get("name"),
                    "path": entry.get("path") or entry.get("client"),
                    "installation_path": entry.get("path"),
                    "files": [],
                    "description": server.get("description") or "",
                    "error": server.get("error"),
                    "tools": tools,
                }
            )
    return components


def _skill_description(skill: dict[str, Any]) -> str:
    for file_info in skill.get("files") or []:
        if file_info.get("path") == "SKILL.md":
            content = file_info.get("content") or ""
            # Pull YAML description if present.
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    front = parts[1]
                    for line in front.splitlines():
                        if line.strip().startswith("description:"):
                            return line.split(":", 1)[1].strip().strip('"')
            return content[:500]
    return ""


def merge_scan_risks(
    components: list[dict[str, Any]],
    scan_payload: dict[str, Any] | list[Any],
) -> list[dict[str, Any]]:
    """Attach scan_path_responses risks onto components when present."""
    responses: list[Any]
    if isinstance(scan_payload, dict):
        responses = scan_payload.get("scan_path_responses") or []
        if not responses and "results" in scan_payload:
            responses = scan_payload.get("results") or []
    elif isinstance(scan_payload, list):
        responses = scan_payload
    else:
        responses = []

    risks: list[dict[str, Any]] = []
    for resp in responses:
        if not isinstance(resp, dict):
            continue
        for issue in resp.get("issues") or resp.get("findings") or []:
            if isinstance(issue, dict):
                risks.append(issue)
        # Preserve raw response summary fields used by live tests.
        if "error" in resp or "path" in resp:
            risks.append({"_scan_path_response": resp})

    for comp in components:
        comp["scan_risks"] = risks
    return components


def highest_severity(findings: list[dict[str, Any]]) -> str | None:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    best = None
    best_n = 0
    for finding in findings:
        sev = str(finding.get("severity") or "").lower()
        n = order.get(sev, 0)
        if n > best_n:
            best_n = n
            best = sev
    return best
