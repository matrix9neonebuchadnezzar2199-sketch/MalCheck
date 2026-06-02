"""Helpers for normalizing Phase 1 scanner result shapes."""

from __future__ import annotations

from typing import Any

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_scanner_results(raw: Any) -> list[dict[str, Any]]:
    """Normalize arbitrary scanner result payload to a stable list shape."""
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        scanner_name = str(row.get("scanner_name") or "").strip()
        if not scanner_name:
            continue
        success = bool(row.get("success", True))
        risk = str(row.get("risk", "safe")).strip().lower() or "safe"
        if risk not in _RISK_ORD:
            risk = "safe"
        findings = row.get("findings")
        if not isinstance(findings, list):
            findings = []
        metadata = row.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        error = row.get("error")
        if error is not None:
            error = str(error)
        out.append(
            {
                "scanner_name": scanner_name,
                "success": success,
                "risk": risk,
                "findings": findings,
                "metadata": metadata,
                "error": error,
            }
        )
    return out


def count_findings(scanner_results: list[dict[str, Any]], scanner_name: str) -> int:
    total = 0
    for row in scanner_results:
        if row.get("scanner_name") != scanner_name:
            continue
        findings = row.get("findings") or []
        if isinstance(findings, list):
            total += len(findings)
    return total


def overall_risk(scanner_results: list[dict[str, Any]]) -> str:
    best = "safe"
    best_ord = _RISK_ORD[best]
    for row in scanner_results:
        risk = str(row.get("risk", "safe")).lower()
        cur = _RISK_ORD.get(risk, -1)
        if cur > best_ord:
            best = risk
            best_ord = cur
    return best
