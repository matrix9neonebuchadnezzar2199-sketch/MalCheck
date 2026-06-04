"""Reduce duplicate YARA/capa noise in surface scanner_results."""

from __future__ import annotations

from typing import Any


def dedupe_scanner_results(scanner_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse capa findings whose rule name already appears in yara findings."""
    if not scanner_results:
        return scanner_results
    yara_rules: set[str] = set()
    for sr in scanner_results:
        if str(sr.get("scanner_name")) != "yara":
            continue
        for f in sr.get("findings") or []:
            if isinstance(f, dict) and f.get("rule"):
                yara_rules.add(str(f["rule"]).lower())

    out: list[dict[str, Any]] = []
    for sr in scanner_results:
        if str(sr.get("scanner_name")) != "capa":
            out.append(sr)
            continue
        findings = sr.get("findings") or []
        kept = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            rule = str(f.get("rule") or "").lower()
            if rule and rule in yara_rules:
                continue
            kept.append(f)
        sr = dict(sr)
        sr["findings"] = kept
        sr["metadata"] = dict(sr.get("metadata") or {})
        sr["metadata"]["deduped_from_yara"] = len(findings) - len(kept)
        if not kept and not sr.get("error"):
            sr["risk"] = "safe"
        out.append(sr)
    return out
