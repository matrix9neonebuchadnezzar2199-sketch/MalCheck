"""Extract highlights and malicious_findings from phase outputs."""

from __future__ import annotations

from typing import Any

from mau.surface_schema import normalize_scanner_results

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MEDIUM_PLUS = {"medium", "high", "critical"}


def _finding_severity(risk: str) -> str:
    r = (risk or "safe").lower()
    if r in ("critical", "high"):
        return "high"
    if r == "medium":
        return "medium"
    if r == "low":
        return "low"
    return "info"


def extract_highlights(surface: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(surface, dict):
        return out
    for sr in normalize_scanner_results(surface.get("scanner_results")):
        name = str(sr.get("scanner_name", ""))
        for f in sr.get("findings") or []:
            if not isinstance(f, dict):
                continue
            risk = str(f.get("risk", "safe")).lower()
            if _RISK_ORD.get(risk, 0) < _RISK_ORD["medium"]:
                continue
            out.append(
                {
                    "source": name,
                    "rule": f.get("rule"),
                    "risk": risk,
                    "description": f.get("description"),
                }
            )
    for m in surface.get("yara_matches") or []:
        if isinstance(m, dict) and m.get("rule"):
            out.append(
                {
                    "source": "yara",
                    "rule": m.get("rule"),
                    "risk": "high",
                    "description": "YARA match detected",
                }
            )
    return out[:50]


def extract_malicious_findings(
    child_name: str,
    surface: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for h in extract_highlights(surface):
        sev = _finding_severity(str(h.get("risk", "medium")))
        if sev == "info":
            continue
        findings.append(
            {
                "child": child_name,
                "severity": sev,
                "source": h.get("source"),
                "summary": h.get("description") or h.get("rule"),
                "evidence": {
                    "rule": h.get("rule"),
                    "risk": h.get("risk"),
                },
            }
        )
    return findings


def score_from_surface(surface: dict[str, Any]) -> tuple[int, list[str]]:
    """Heuristic score from surface (mirrors report_generator.calculate_verdict)."""
    from mau.surface_schema import count_findings, normalize_scanner_results

    reasons: list[str] = []
    score = 0
    if not isinstance(surface, dict):
        return 0, reasons
    scanner_results = normalize_scanner_results(surface.get("scanner_results"))
    yara_count = count_findings(scanner_results, "yara")
    capa_count = count_findings(scanner_results, "capa")
    if capa_count > 0:
        score += min(40, capa_count * 5)
        reasons.append(f"capa-like indicators: {capa_count}")
    if yara_count > 0:
        score += min(30, yara_count * 10)
        reasons.append(f"yara matches: {yara_count}")
    for sr in scanner_results:
        for f in sr.get("findings") or []:
            if not isinstance(f, dict):
                continue
            r = str(f.get("risk", "")).lower()
            if r in ("high", "critical"):
                score += 15
                reasons.append(f"{sr.get('scanner_name')}: {f.get('rule')}")
            elif r == "medium" and score < 20:
                score += 8
    packer = surface.get("packer") or {}
    if isinstance(packer, dict) and packer.get("detected"):
        score += 15
        reasons.append("packer/heuristic flag")
    yara = surface.get("yara_matches") or []
    if isinstance(yara, list) and len(yara) > 0 and yara_count == 0:
        score += min(30, len(yara) * 10)
        reasons.append(f"yara matches: {len(yara)}")
    capa = surface.get("capa_matches") or []
    if isinstance(capa, list) and len(capa) > 0 and capa_count == 0:
        score += min(40, len(capa) * 5)
        reasons.append(f"capa-like indicators: {len(capa)}")
    return min(100, score), reasons
