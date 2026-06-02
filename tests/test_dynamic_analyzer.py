from __future__ import annotations

from pathlib import Path

import pytest

from mau.dynamic_analyzer import run_dynamic_analysis
from mau.errors import DynamicError


def test_dynamic_disabled_returns_skipped():
    out = run_dynamic_analysis("sample.exe", enabled=False)
    assert out["status"] == "skipped"


def test_dynamic_enabled_without_hook_returns_not_implemented(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MAU_DYNAMIC_HOOK", raising=False)
    out = run_dynamic_analysis("sample.exe", enabled=True)
    assert out["status"] == "not_implemented"


def test_dynamic_hook_success_normalizes_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import json\n"
        "print(json.dumps({'network': {'dns': []}}))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAU_DYNAMIC_HOOK", str(hook))
    out = run_dynamic_analysis("sample.exe", enabled=True, timeout_sec=42)
    assert out["status"] == "completed"
    assert out["sample"] == "sample.exe"
    assert out["timeout_sec"] == 42
    assert "timestamp" in out
    assert "network" in out


def test_dynamic_hook_failure_raises_dynamic_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    hook = tmp_path / "hook_fail.py"
    hook.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    monkeypatch.setenv("MAU_DYNAMIC_HOOK", str(hook))
    with pytest.raises(DynamicError):
        run_dynamic_analysis("sample.exe", enabled=True)
