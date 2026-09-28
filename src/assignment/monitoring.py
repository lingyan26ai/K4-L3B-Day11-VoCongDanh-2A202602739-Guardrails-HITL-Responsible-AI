"""
Assignment 11 — Monitoring & Alerts starter (TODO).

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def check_metrics(self) -> list[Alert]:
        """Compute rates and create alerts for exceeded thresholds."""

        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )

        judge_fail_rate = (
            self.judge_fails / self.judge_checks
            if self.judge_checks
            else 0.0
        )

        current_alerts: list[Alert] = []

        if block_rate > self.block_rate_threshold:
            current_alerts.append(
                Alert(
                    metric="block_rate",
                    value=block_rate,
                    threshold=self.block_rate_threshold,
                    message=(
                        f"Block rate {block_rate:.2%} exceeded "
                        f"threshold {self.block_rate_threshold:.2%}."
                    ),
                )
            )

        if self.rate_limit_hits > self.rate_limit_hit_threshold:
            current_alerts.append(
                Alert(
                    metric="rate_limit_hits",
                    value=float(self.rate_limit_hits),
                    threshold=float(self.rate_limit_hit_threshold),
                    message=(
                        f"Rate-limit hits {self.rate_limit_hits} exceeded "
                        f"threshold {self.rate_limit_hit_threshold}."
                    ),
                )
            )

        if judge_fail_rate > self.judge_fail_rate_threshold:
            current_alerts.append(
                Alert(
                    metric="judge_fail_rate",
                    value=judge_fail_rate,
                    threshold=self.judge_fail_rate_threshold,
                    message=(
                        f"Judge fail rate {judge_fail_rate:.2%} exceeded "
                        f"threshold {self.judge_fail_rate_threshold:.2%}."
                    ),
                )
            )

        # Keep the latest alert state instead of duplicating alerts
        # every time check_metrics() is called.
        self.alerts = current_alerts
        return current_alerts

    def export_json(self, filepath: str | None = None):
        """Write metrics and alerts to JSON."""

        self.check_metrics()

        path = Path(filepath or default_metrics_path())
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(
            json.dumps(
                self.snapshot(),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return path

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
