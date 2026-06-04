"""Tests for anti-analysis / obfuscation rollup."""

from __future__ import annotations

import json
from pathlib import Path

from mau.re_insights import enrich_summary, rollup_decompile_insights
from mau.report_generator import build_re_analysis, calculate_verdict
from mau.static_normalize import build_summary


def _fixture(name: str) -> dict:
    path = Path(__file__).parent / "fixtures" / "static" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_rollup_decompile_insights() -> None:
    data = _fixture("analysis_anti.json")
    rolled = rollup_decompile_insights(data)
    signals = rolled["anti_analysis_signals"]
    assert any(s["id"] == "anti_debug" for s in signals)
    assert rolled["obfuscation_stats"]["heavy_goto_flattening_count"] >= 1


def test_enrich_summary() -> None:
    data = _fixture("analysis_anti.json")
    summary = enrich_summary(build_summary(data), data)
    assert summary["anti_analysis_count"] >= 1
    assert len(summary["top_anti_analysis_signals"]) >= 1


def test_verdict_includes_anti_analysis() -> None:
    data = _fixture("analysis_anti.json")
    static = {"summary": enrich_summary(build_summary(data), data)}
    v = calculate_verdict({}, {}, static)
    assert any("anti-analysis" in r for r in v["reasons"])


def test_build_re_analysis() -> None:
    surface = {
        "scanner_results": [
            {
                "scanner_name": "pefile",
                "findings": [
                    {
                        "rule": "pe_anti_analysis_imports",
                        "risk": "high",
                        "description": "Anti-analysis imports",
                    }
                ],
            }
        ]
    }
    data = _fixture("analysis_anti.json")
    static = {"summary": enrich_summary(build_summary(data), data)}
    re = build_re_analysis(surface, static)
    assert len(re["surface_anti_analysis"]) >= 1
    assert len(re["static_anti_analysis"]) >= 1
