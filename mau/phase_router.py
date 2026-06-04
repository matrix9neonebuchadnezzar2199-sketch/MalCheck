"""Run analysis phases with per-phase error isolation."""

from __future__ import annotations

import logging
import os
import shutil
import traceback
import uuid
from pathlib import Path
from typing import Any, Optional

from mau.config import get_phase_config, load_config
from mau.dynamic_analyzer import run_dynamic_analysis
from mau.errors import MauError, PhaseError
from mau.findings_extract import (
    extract_highlights,
    extract_malicious_findings,
    score_from_surface,
)
from mau.intake import process_intake
from mau.report_generator import calculate_verdict, generate_aggregated_report, generate_report
from mau.static_analyzer import run_static_analysis
from mau.static_normalize import static_failed
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


def _child_verdict(surface: dict[str, Any], dynamic: dict[str, Any], static: dict[str, Any]) -> dict[str, Any]:
    return calculate_verdict(surface, dynamic, static)


def _stage_leaves_for_analysis(leaves: list[Path], samples_dir: Path) -> list[Path]:
    """Copy extracted files under SAMPLES_DIR so surface docker exec can read them."""
    staged: list[Path] = []
    bucket = samples_dir / "_intake" / uuid.uuid4().hex[:12]
    bucket.mkdir(parents=True, exist_ok=True)
    for leaf in leaves:
        leaf = leaf.resolve()
        try:
            leaf.relative_to(samples_dir)
            staged.append(leaf)
            continue
        except ValueError:
            pass
        dest = bucket / leaf.name
        counter = 1
        while dest.exists():
            dest = bucket / f"{leaf.stem}_{counter}{leaf.suffix}"
            counter += 1
        shutil.copy2(leaf, dest)
        staged.append(dest)
    return staged


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
            static = static_failed(str(e), detail=getattr(e, "detail", "") or "")
            if isinstance(e, MauError):
                static["type"] = e.__class__.__name__
    else:
        static = {"status": "skipped", "reason": "static disabled in config", "engine": "ghidra_headless"}

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


def run_pipeline_with_intake(
    sample_path: str,
    *,
    config_path: Optional[str] = None,
    sample_name: Optional[str] = None,
    archive_password: Optional[str] = None,
) -> dict[str, Any]:
    """Intake (archive extract) then analyze each leaf; aggregate into one parent report."""
    cfg = load_config(config_path)
    name = sample_name or Path(sample_path).name
    path = Path(sample_path).resolve()

    intake = process_intake(path, cfg, archive_password=archive_password)
    leaf_paths = [Path(p) for p in intake.get("leaf_paths") or []]
    samples_dir = Path(os.environ.get("SAMPLES_DIR", "/samples")).resolve()
    leaf_paths = _stage_leaves_for_analysis(leaf_paths, samples_dir)

    if intake.get("status") == "failed" and not leaf_paths:
        surface = {"status": "skipped", "reason": "intake failed", "intake": intake}
        dynamic: dict[str, Any] = {"status": "skipped"}
        static: dict[str, Any] = {"status": "skipped"}
        rep_cfg = cfg.get("report") or {}
        ollama_cfg = cfg.get("ollama") or {}
        report = generate_aggregated_report(
            sample_name=name,
            intake_meta=intake,
            children=[],
            primary_surface=surface,
            primary_dynamic=dynamic,
            primary_static=static,
            html=bool(rep_cfg.get("html", True)),
            executive_summary_llm=bool(rep_cfg.get("executive_summary_llm", False)),
            ollama_base_url=str(ollama_cfg.get("base_url", "http://127.0.0.1:11434")),
            ollama_model=str(ollama_cfg.get("model", "llama3.2")),
        )
        report["verdict"] = {
            "label": "benign_or_insufficient_data",
            "score": 0,
            "reasons": [f"intake failed: {intake.get('error')}"],
        }
        return {"report": report, "surface": surface, "dynamic": dynamic, "static": static, "intake": intake}

    children: list[dict[str, Any]] = []
    sp = get_phase_config(cfg, "surface")
    dp = get_phase_config(cfg, "dynamic")
    stp = get_phase_config(cfg, "static")

    for leaf in leaf_paths:
        if not leaf.is_file():
            continue
        child_name = leaf.name
        surface: dict[str, Any] = {}
        dynamic: dict[str, Any] = {}
        static: dict[str, Any] = {}

        if sp.get("enabled", True):
            try:
                surface = run_surface_analysis(
                    str(leaf),
                    container=(sp.get("container") or None) or None,
                    timeout_sec=int(sp.get("timeout_sec", 600)),
                )
            except Exception as e:
                log.exception("Surface failed for %s", leaf)
                surface = _err_payload(e)
        else:
            surface = {"status": "skipped"}

        try:
            dynamic = run_dynamic_analysis(
                str(leaf),
                enabled=bool(dp.get("enabled", False)),
                timeout_sec=int(dp.get("timeout_sec", 120)),
            )
        except Exception as e:
            dynamic = _err_payload(e)

        if stp.get("enabled", True):
            try:
                static = run_static_analysis(
                    str(leaf),
                    image=str(stp.get("ghidra_image") or "ghidra-headless:latest"),
                    timeout_sec=int(stp.get("timeout_sec", 600)),
                )
            except Exception as e:
                log.exception("Static failed for %s", leaf)
                static = static_failed(str(e), detail=getattr(e, "detail", "") or "")
        else:
            static = {"status": "skipped", "engine": "ghidra_headless"}

        verdict = _child_verdict(surface, dynamic, static)
        mal = extract_malicious_findings(child_name, surface)
        children.append(
            {
                "path": child_name,
                "verdict": verdict,
                "highlights": extract_highlights(surface),
                "malicious_findings": mal,
                "phase1_surface": surface,
                "phase2_dynamic": dynamic,
                "phase3_static": static,
            }
        )

    if not children:
        return run_pipeline(str(path), config_path=config_path, sample_name=name)

    def _child_rank(ch: dict[str, Any]) -> int:
        return int((ch.get("verdict") or {}).get("score", 0))

    primary = max(children, key=_child_rank)
    rep_cfg = cfg.get("report") or {}
    ollama_cfg = cfg.get("ollama") or {}
    report = generate_aggregated_report(
        sample_name=name,
        intake_meta=intake,
        children=children,
        primary_surface=primary.get("phase1_surface") or {},
        primary_dynamic=primary.get("phase2_dynamic") or {},
        primary_static=primary.get("phase3_static") or {},
        html=bool(rep_cfg.get("html", True)),
        executive_summary_llm=bool(rep_cfg.get("executive_summary_llm", False)),
        ollama_base_url=str(ollama_cfg.get("base_url", "http://127.0.0.1:11434")),
        ollama_model=str(ollama_cfg.get("model", "llama3.2")),
    )

    return {
        "report": report,
        "surface": primary.get("phase1_surface"),
        "dynamic": primary.get("phase2_dynamic"),
        "static": primary.get("phase3_static"),
        "intake": intake,
        "children": children,
    }
