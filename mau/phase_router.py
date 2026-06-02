"""Run analysis phases with per-phase error isolation."""

from __future__ import annotations

import logging
import traceback
from typing import Any, Optional

from mau.config import get_phase_config, load_config
from mau.dynamic_analyzer import run_dynamic_analysis
from mau.errors import MauError, PhaseError
from mau.report_generator import generate_report
from mau.static_analyzer import run_static_analysis
from mau.surface_runner import run_surface_analysis

log = logging.getLogger(__name__)


def _err_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, MauError):
        return {"error": True, "type": exc.__class__.__name__, "message": exc.message, "detail": exc.detail}
    return {
        "error": True,
        "type": exc.__class__.__name__,
        "message": str(exc),
        "detail": traceback.format_exc()[-8000:],
    }


def run_pipeline(
    sample_path: str,
    *,
    config_path: Optional[str] = None,
    sample_name: Optional[str] = None,
) -> dict[str, Any]:
    """
    Execute enabled phases; failures are recorded in phase dicts instead of aborting whole run.
    """
    cfg = load_config(config_path)
    name = sample_name or __import__("os").path.basename(sample_path)

    surface: dict[str, Any] = {}
    dynamic: dict[str, Any] = {}
    static: dict[str, Any] = {}

    sp = get_phase_config(cfg, "surface")
    if sp.get("enabled", True):
        try:
            surface = run_surface_analysis(
                sample_path,
                container=(sp.get("container") or None) or None,
                timeout_sec=int(sp.get("timeout_sec", 600)),
            )
        except Exception as e:
            log.exception("Surface phase failed")
            surface = _err_payload(e)
    else:
        surface = {"status": "skipped", "reason": "surface disabled in config"}

    dp = get_phase_config(cfg, "dynamic")
    try:
        dynamic = run_dynamic_analysis(
            sample_path,
            enabled=bool(dp.get("enabled", False)),
            timeout_sec=int(dp.get("timeout_sec", 120)),
        )
    except Exception as e:
        log.exception("Dynamic phase failed")
        dynamic = _err_payload(e)

    stp = get_phase_config(cfg, "static")
    if stp.get("enabled", True):
        try:
            static = run_static_analysis(
                sample_path,
                image=str(stp.get("ghidra_image") or "ghidra-headless:latest"),
                timeout_sec=int(stp.get("timeout_sec", 600)),
            )
        except Exception as e:
            log.exception("Static phase failed")
            static = _err_payload(e)
    else:
        static = {"status": "skipped", "reason": "static disabled in config"}

    rep_cfg = cfg.get("report") or {}
    ollama_cfg = cfg.get("ollama") or {}
    try:
        report = generate_report(
            surface,
            dynamic,
            static,
            sample_name=name,
            html=bool(rep_cfg.get("html", True)),
            executive_summary_llm=bool(rep_cfg.get("executive_summary_llm", False)),
            ollama_base_url=str(ollama_cfg.get("base_url", "http://127.0.0.1:11434")),
            ollama_model=str(ollama_cfg.get("model", "llama3.2")),
        )
    except Exception as e:
        log.exception("Report generation failed")
        raise PhaseError("Report generation failed", str(e)) from e

    return {"report": report, "surface": surface, "dynamic": dynamic, "static": static}
