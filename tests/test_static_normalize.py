"""Tests for Ghidra output normalization (no Docker/Ghidra required)."""

from __future__ import annotations

import json
from pathlib import Path

from mau.static_normalize import build_summary, load_static_outputs, static_failed


def test_build_summary_from_fixture() -> None:
    raw = json.loads(
        (Path(__file__).parent / "fixtures" / "static" / "analysis_minimal.json").read_text(encoding="utf-8")
    )
    s = build_summary(raw)
    assert s["function_count"] == 1
    assert s["suspicious_api_count"] == 1
    assert s["truncated"] is False


def test_load_static_outputs_analysis_json(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "static" / "analysis_minimal.json"
    (tmp_path / "analysis.json").write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    out = load_static_outputs(tmp_path, image="ghidra-headless:test")
    assert out["engine"] == "ghidra_headless"
    assert out["status"] == "completed"
    assert out["analysis_json"] is not None
    assert out["summary"]["function_count"] == 1
    assert out["summary"]["suspicious_api_count"] == 1
    apis = (out.get("analysis_json") or {}).get("suspicious_apis") or []
    assert any(a.get("name") == "VirtualAlloc" for a in apis)


def test_load_static_outputs_empty_dir(tmp_path: Path) -> None:
    out = load_static_outputs(tmp_path)
    assert out["status"] == "failed"
    assert out["analysis_json"] is None


def test_static_failed_shape() -> None:
    out = static_failed("Ghidra image not loaded", "docker load", image="missing:latest")
    assert out["status"] == "failed"
    assert out["engine"] == "ghidra_headless"
