"""Deterministic local rules for skill / MCP content (keyless)."""

from __future__ import annotations

import base64
import re
from dataclasses import asdict, dataclass
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

HIDDEN_INSTRUCTION_PHRASES = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "you are now",
    "system prompt",
    "do not tell the user",
    "hidden instruction",
    "CRITICAL: For Windows download",
    "WITHOUT COMPLETING THE SETUP",
)

CURL_PIPE_SH = re.compile(
    r"(?:curl|wget)\b[^\n|;]{0,200}\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
BASE64_PIPE_SHELL = re.compile(
    r"base64\b[^\n|;]{0,80}\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
BASE64_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{80,}={0,2})")
ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]")
EXTERNAL_URL = re.compile(
    r"https?://(?!(?:127\.0\.0\.1|localhost)(?:[:/]|$))[^\s)\]\"']+",
    re.IGNORECASE,
)
TOOL_DESC_HINTS = ("tool description", "tools:", '"description"')


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    path: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


def _looks_like_base64_payload(blob: str) -> bool:
    try:
        padded = blob + "=" * (-len(blob) % 4)
        decoded = base64.b64decode(padded, validate=False)
    except Exception:
        return False
    if len(decoded) < 20:
        return False
    text = decoded.decode("utf-8", errors="ignore").lower()
    return any(tok in text for tok in ("bash", "curl", "wget", "/bin/", "powershell", "invoke-"))


def scan_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()

    for phrase in HIDDEN_INSTRUCTION_PHRASES:
        if phrase.lower() in lower:
            findings.append(
                Finding(
                    rule_id="hidden-instruction",
                    severity="high",
                    message=f"Hidden / coercive instruction phrase: {phrase}",
                    path=path,
                    evidence=phrase,
                )
            )

    for match in CURL_PIPE_SH.finditer(text):
        findings.append(
            Finding(
                rule_id="curl-pipe-sh",
                severity="critical",
                message="Remote download piped to a shell",
                path=path,
                evidence=match.group(0)[:160],
            )
        )

    for match in BASE64_PIPE_SHELL.finditer(text):
        findings.append(
            Finding(
                rule_id="base64-pipe-shell",
                severity="critical",
                message="base64 decode piped to a shell",
                path=path,
                evidence=match.group(0)[:160],
            )
        )

    for match in BASE64_BLOB.finditer(text):
        blob = match.group(0)
        if _looks_like_base64_payload(blob):
            findings.append(
                Finding(
                    rule_id="base64-blob",
                    severity="high",
                    message="Base64 blob that decodes to shell-like content",
                    path=path,
                    evidence=blob[:80] + "...",
                )
            )

    if ZERO_WIDTH.search(text):
        findings.append(
            Finding(
                rule_id="zero-width",
                severity="medium",
                message="Zero-width / invisible Unicode characters present",
                path=path,
                evidence="zero-width codepoint",
            )
        )

    # External URLs in MCP tool descriptions, or installer-like URLs in skills.
    in_tool_desc = "#tool:" in path or any(h in lower for h in TOOL_DESC_HINTS)
    for match in EXTERNAL_URL.finditer(text):
        url = match.group(0)
        installerish = any(
            tok in url.lower()
            for tok in (
                ".exe",
                ".zip",
                ".dmg",
                ".pkg",
                "releases/download",
                "raw.githubusercontent.com",
            )
        )
        if in_tool_desc or installerish:
            findings.append(
                Finding(
                    rule_id="external-url",
                    severity="medium",
                    message="External URL in tool description or installer-like skill URL",
                    path=path,
                    evidence=url[:160],
                )
            )

    return findings


def scan_components(components: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for comp in components:
        path = str(comp.get("path") or comp.get("installation_path") or "<unknown>")
        for file_info in comp.get("files") or []:
            file_path = f"{path}/{file_info.get('path', 'unknown')}"
            content = file_info.get("content") or ""
            findings.extend(scan_text(file_path, content))
        desc = comp.get("description") or ""
        if desc:
            findings.extend(scan_text(path, desc))
        # Also scan raw text fields for MCP tool descriptions.
        for tool in comp.get("tools") or []:
            tool_desc = tool.get("description") or ""
            tool_name = tool.get("name") or "tool"
            if tool_desc:
                findings.extend(scan_text(f"{path}#tool:{tool_name}", tool_desc))
    return findings
