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
from mau.unpack_stage import run_unpack_stage

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


def _run_phases_for_sample(
    sample_path: str,
    cfg: dict[str, Any],
    *,
    run_static: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Surface → unpack → dynamic → static for one file."""
    sp = get_phase_config(cfg, "surface")
    up = get_phase_config(cfg, "unpack")
    dp = get_phase_config(cfg, "dynamic")
    stp = get_phase_config(cfg, "static")

    surface: dict[str, Any] = {}
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

    unpack: dict[str, Any] = {"status": "skipped", "reason": "not run"}
    try:
        unpack = run_unpack_stage(
            sample_path,
            surface,
            enabled=bool(up.get("enabled", True)),
            timeout_sec=int(up.get("timeout_sec", 180)),
            max_attempts=int(up.get("max_attempts_per_sample", 2)),
        )
    except Exception as e:
        log.exception("Unpack stage failed")
        unpack = {"status": "failed", "error": str(e)}

    static_input = sample_path
    oep_rva: Optional[str] = None
    unpack_meta: Optional[dict[str, Any]] = None
    if unpack.get("status") == "completed" and unpack.get("unpacked_path"):
        static_input = str(unpack["unpacked_path"])
        oep_rva = unpack.get("oep_rva")
        unpack_meta = dict(unpack)

    try:
        dynamic = run_dynamic_analysis(
            sample_path,
            enabled=bool(dp.get("enabled", False)),
            timeout_sec=int(dp.get("timeout_sec", 120)),
        )
    except Exception as e:
        log.exception("Dynamic phase failed")
        dynamic = _err_payload(e)

    static: dict[str, Any] = {}
    if stp.get("enabled", True) and run_static:
        try:
            static = run_static_analysis(
                static_input,
                image=str(stp.get("ghidra_image") or "ghidra-headless:latest"),
                timeout_sec=int(stp.get("timeout_sec", 600)),
                oep_rva=oep_rva,
                unpack_meta=unpack_meta,
            )
        except Exception as e:
            log.exception("Static phase failed")
            static = static_failed(str(e), detail=getattr(e, "detail", "") or "")
            if isinstance(e, MauError):
                static["type"] = e.__class__.__name__
    elif not run_static:
        static = {
            "status": "skipped",
            "reason": "static max_children limit reached for this archive",
            "engine": "ghidra_headless",
        }
    else:
        static = {"status": "skipped", "reason": "static disabled in config", "engine": "ghidra_headless"}

    return surface, unpack, dynamic, static


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

    surface, unpack, dynamic, static = _run_phases_for_sample(sample_path, cfg)

    rep_cfg = cfg.get("report") or {}
    ollama_cfg = cfg.get("ollama") or {}
    try:
        report = generate_report(
            surface,
            dynamic,
            static,
            sample_name=name,
            unpack=unpack,
            html=bool(rep_cfg.get("html", True)),
            executive_summary_llm=bool(rep_cfg.get("executive_summary_llm", False)),
            ollama_base_url=str(ollama_cfg.get("base_url", "http://127.0.0.1:11434")),
            ollama_model=str(ollama_cfg.get("model", "llama3.2")),
        )
    except Exception as e:
        log.exception("Report generation failed")
        raise PhaseError("Report generation failed", str(e)) from e

    return {"report": report, "surface": surface, "unpack": unpack, "dynamic": dynamic, "static": static}


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
    stp = get_phase_config(cfg, "static")
    max_static = int(stp.get("max_children", 0) or 0)
    static_runs = 0

    for leaf in leaf_paths:
        if not leaf.is_file():
            continue
        child_name = leaf.name
        allow_static = max_static == 0 or static_runs < max_static
        surface, unpack, dynamic, static = _run_phases_for_sample(
            str(leaf), cfg, run_static=allow_static
        )
        if allow_static and stp.get("enabled", True) and static.get("status") != "skipped":
            static_runs += 1

        verdict = _child_verdict(surface, dynamic, static)
        mal = extract_malicious_findings(child_name, surface, static)
        children.append(
            {
                "path": child_name,
                "verdict": verdict,
                "highlights": extract_highlights(surface),
                "malicious_findings": mal,
                "phase1_surface": surface,
                "phase1b_unpack": unpack,
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
        primary_unpack=primary.get("phase1b_unpack") or {"status": "skipped"},
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
