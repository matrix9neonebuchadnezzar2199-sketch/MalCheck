"""Tests for malicious findings extraction and rollup."""

from __future__ import annotations

from mau.findings_extract import extract_malicious_findings, score_from_surface
from mau.report_generator import REPORT_SCHEMA_VERSION, rollup_verdict


def test_score_from_yara_finding() -> None:
    surface = {
        "scanner_results": [
            {
                "scanner_name": "yara",
                "success": True,
                "risk": "high",
                "findings": [{"rule": "test_rule", "risk": "high", "description": "match"}],
            }
        ],
        "yara_matches": [{"rule": "test_rule"}],
    }
    score, reasons = score_from_surface(surface)
    assert score >= 20
    assert reasons


def test_extract_malicious_findings() -> None:
    surface = {
        "scanner_results": [
            {
                "scanner_name": "pefile",
                "success": True,
                "risk": "high",
                "findings": [
                    {
                        "rule": "pe_suspicious_imports",
                        "risk": "high",
                        "description": "VirtualAlloc",
                    }
                ],
            }
        ],
    }
    mal = extract_malicious_findings("evil.exe", surface)
    assert len(mal) >= 1
    assert mal[0]["severity"] == "high"


def test_rollup_verdict_takes_max_child() -> None:
    children = [
        {"path": "a.txt", "verdict": {"label": "benign_or_insufficient_data", "score": 0, "reasons": []}, "highlights": []},
        {
            "path": "b.exe",
            "verdict": {"label": "suspicious", "score": 25, "reasons": ["yara"]},
            "highlights": [{"risk": "high"}],
        },
    ]
    v = rollup_verdict(children)
    assert v["score"] == 25
    assert v["label"] in ("suspicious", "high_risk_indicators")


def test_schema_version_bumped() -> None:
    assert REPORT_SCHEMA_VERSION == "2.1"
