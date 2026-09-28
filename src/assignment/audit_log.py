"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store request data until the corresponding output is recorded."""
        key = request_id or user_id

        self._open[key] = {
            "request_id": request_id or key,
            "user_id": user_id,
            "input": text or "",
            "started_at": utc_now_iso(),
            "started_perf": time.perf_counter(),
        }

        return key

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store the completed request and append it to the audit log."""

        key = request_id or user_id
        pending = self._open.pop(key, None)

        latency_ms = None
        if pending is not None:
            elapsed = max(
                0.0,
                time.perf_counter() - pending["started_perf"],
            )
            latency_ms = round(elapsed * 1000, 3)

        entry = {
            "request_id": request_id or key,
            "user_id": user_id,
            "input": pending["input"] if pending else None,
            "started_at": pending["started_at"] if pending else None,
            "completed_at": utc_now_iso(),
            "output": text or "",
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": latency_ms,
        }

        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write the audit log as a JSON array."""

        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(
            json.dumps(
                self.logs,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
