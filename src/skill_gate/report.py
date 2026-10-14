"""Write machine-readable reports under reports/."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def write_report(repo_root: Path, name: str, payload: dict[str, Any]) -> Path:
    reports = repo_root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / f"{name}.json"
    body = {
        "generated_at": datetime.now(UTC).isoformat(),
        **payload,
    }
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return path
