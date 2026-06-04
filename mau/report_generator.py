"""Aggregate phases into JSON + HTML (Jinja2). Optional Ollama executive summary."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from jinja2 import Environment, FileSystemLoader, select_autoescape

from mau.errors import ReportError
from mau.findings_extract import (
    extract_highlights,
    extract_malicious_findings,
    score_from_surface,
)
from mau.report_export import write_exports

log = logging.getLogger(__name__)

REPORT_SCHEMA_VERSION = "2.1"


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name)[:200] or "report"


def _finalize_report_paths(
    report: dict[str, Any],
    out_dir: Path,
    base: str,
    json_path: Path,
    html_path: Optional[Path],
) -> None:
    paths: dict[str, Optional[str]] = {
        "json": str(json_path),
        "html": str(html_path) if html_path else None,
    }
    if os.environ.get("MAU_EXPORT_REPORTS", "1") not in ("0", "false", "False"):
        try:
            paths.update(write_exports(report, out_dir, base))
        except OSError as e:
            log.warning("Export write failed: %s", e)
    report["_paths"] = paths


def _phase_status(payload: Any) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    status = str(payload.get("status", "")).strip().lower()
    if status in ("skipped", "not_implemented", "completed", "failed"):
        return status
    if payload.get("error") is True:
        return "failed"
    return "completed"


def aggregate_iocs(surface: dict[str, Any], dynamic: dict[str, Any], static: dict[str, Any]) -> dict[str, Any]:
    urls: list[str] = []
    ips: list[str] = []
    domains: list[str] = []
    emails: list[str] = []
    registry_keys: list[str] = []
    mutexes: list[str] = []
    hashes: dict[str, str] = {}
    if isinstance(surface, dict):
        h = surface.get("hashes") or {}
        if isinstance(h, dict):
            for k in ("md5", "sha1", "sha256", "ssdeep", "tlsh", "imphash"):
                v = h.get(k)
                if isinstance(v, str) and v:
                    hashes[k] = v
        for src, dest in (
            ("urls", urls),
            ("ips", ips),
            ("domains", domains),
            ("emails", emails),
            ("registry_keys", registry_keys),
            ("mutexes", mutexes),
        ):
            vals = surface.get(src)
            if isinstance(vals, list):
                dest.extend(str(x) for x in vals if x)
    return {
        "hashes": hashes,
        "urls": sorted(set(urls)),
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "emails": sorted(set(emails)),
        "registry_keys": sorted(set(registry_keys)),
        "mutexes": sorted(set(mutexes)),
    }


def build_re_analysis(surface: dict[str, Any], static: dict[str, Any]) -> dict[str, Any]:
    """Surface + static anti-analysis / obfuscation rollup for reports."""
    surface_anti: list[dict[str, Any]] = []
    for h in extract_highlights(surface):
        rule = str(h.get("rule") or "")
        if rule in (
            "pe_anti_analysis_imports",
            "pe_tls_callbacks",
            "capa_anti_analysis",
        ) or "anti" in rule.lower():
            surface_anti.append(h)
    static_signals: list[dict[str, Any]] = []
    obfuscation_stats: dict[str, Any] = {}
    summ = static.get("summary") if isinstance(static, dict) else None
    if isinstance(summ, dict):
        static_signals = list(summ.get("top_anti_analysis_signals") or [])
        obfuscation_stats = summ.get("obfuscation_stats") or {}
    return {
        "surface_anti_analysis": surface_anti[:20],
        "static_anti_analysis": static_signals[:20],
        "obfuscation_stats": obfuscation_stats,
    }


def calculate_verdict(
    surface: dict[str, Any],
    dynamic: dict[str, Any],
    static: dict[str, Any],
) -> dict[str, Any]:
    """Lightweight heuristic verdict (not AV)."""
    reasons: list[str] = []
    score = 0
    if isinstance(surface, dict):
        s_score, s_reasons = score_from_surface(surface)
        score += s_score
        reasons.extend(s_reasons)
    if isinstance(static, dict):
        summ = static.get("summary")
        if isinstance(summ, dict):
            sus = int(summ.get("suspicious_api_count") or 0)
            if sus > 0:
                score += min(25, sus * 5)
                reasons.append(f"static: suspicious APIs ({sus})")
            anti_n = int(summ.get("anti_analysis_count") or 0)
            if anti_n > 0:
                score += min(20, anti_n * 8)
                reasons.append(f"static: anti-analysis signals ({anti_n})")
            if summ.get("truncated"):
                score += 5
                reasons.append("static: Ghidra export truncated")
        elif static.get("metadata"):
            score += 5
            reasons.append("static metadata present")
    label = "unknown"
    if score >= 50:
        label = "high_risk_indicators"
    elif score >= 20:
        label = "suspicious"
    elif score > 0:
        label = "low"
    else:
        label = "benign_or_insufficient_data"
    return {"label": label, "score": min(100, score), "reasons": reasons}


def _ollama_summarize(report: dict[str, Any], base_url: str, model: str, timeout: float = 120.0) -> Optional[str]:
    prompt = (
        "Summarize this malware analysis JSON in 5 bullet points for executives. "
        "Focus on risk, behaviors, and IOCs. JSON follows:\n"
        + json.dumps(report, default=str)[:12000]
    )
    try:
        r = requests.post(
            f"{base_url.rstrip('/')}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json()
        return (data.get("response") or data.get("text") or "").strip() or None
    except requests.RequestException as e:
        log.warning("Ollama summary failed: %s", e)
        return None


def generate_report(
    surface: dict[str, Any],
    dynamic: dict[str, Any],
    static: dict[str, Any],
    *,
    sample_name: str,
    unpack: Optional[dict[str, Any]] = None,
    out_dir: Optional[Path] = None,
    html: bool = True,
    executive_summary_llm: bool = False,
    ollama_base_url: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2",
) -> dict[str, Any]:
    out_dir = out_dir or Path(os.environ.get("RESULTS_DIR", "results")) / "reports"
    try:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise ReportError(f"Cannot create report directory: {out_dir}", str(e)) from e

    ts = datetime.now(timezone.utc).isoformat()
    iocs = aggregate_iocs(surface, dynamic, static)
    verdict = calculate_verdict(surface, dynamic, static)
    report: dict[str, Any] = {
        "meta": {"schema_version": REPORT_SCHEMA_VERSION, "timestamp": ts, "sample_name": sample_name},
        "verdict": verdict,
        "phase1_surface": surface,
        "phase1b_unpack": unpack or {"status": "skipped"},
        "phase2_dynamic": dynamic,
        "phase3_static": static,
        "phase_status": {
            "surface": _phase_status(surface),
            "unpack": _phase_status(unpack or {"status": "skipped"}),
            "dynamic": _phase_status(dynamic),
            "static": _phase_status(static),
        },
        "iocs": iocs,
        "mitre_mapping": surface.get("mitre") if isinstance(surface, dict) else None,
        "re_analysis": build_re_analysis(surface, static),
    }

    if executive_summary_llm:
        summary = _ollama_summarize(report, ollama_base_url, ollama_model)
        report["executive_summary"] = summary

    base = _safe_name(sample_name)
    json_path = out_dir / f"{base}.json"
    try:
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    except OSError as e:
        raise ReportError(f"Cannot write {json_path}", str(e)) from e

    html_path: Optional[Path] = None
    if html:
        html_path = out_dir / f"{base}.html"
        try:
            _render_html(report, html_path)
        except Exception as e:
            raise ReportError(f"HTML render failed: {html_path}", str(e)) from e

    _finalize_report_paths(report, out_dir, base, json_path, html_path)
    return report


def _verdict_label_from_score(score: int, has_high_finding: bool) -> str:
    if has_high_finding or score >= 50:
        return "high_risk_indicators"
    if score >= 20:
        return "suspicious"
    if score > 0:
        return "low"
    return "benign_or_insufficient_data"


def rollup_verdict(children: list[dict[str, Any]]) -> dict[str, Any]:
    max_score = 0
    reasons: list[str] = []
    has_high = False
    for ch in children:
        v = ch.get("verdict") or {}
        max_score = max(max_score, int(v.get("score", 0)))
        for r in v.get("reasons") or []:
            reasons.append(f"child:{ch.get('path', '?')}: {r}")
        for h in ch.get("highlights") or []:
            if str(h.get("risk", "")).lower() in ("high", "critical"):
                has_high = True
    label = _verdict_label_from_score(max_score, has_high)
    return {"label": label, "score": max_score, "reasons": reasons[:30]}


def generate_aggregated_report(
    *,
    sample_name: str,
    intake_meta: dict[str, Any],
    children: list[dict[str, Any]],
    primary_surface: dict[str, Any],
    primary_dynamic: dict[str, Any],
    primary_static: dict[str, Any],
    primary_unpack: Optional[dict[str, Any]] = None,
    out_dir: Optional[Path] = None,
    html: bool = True,
    executive_summary_llm: bool = False,
    ollama_base_url: str = "http://127.0.0.1:11434",
    ollama_model: str = "llama3.2",
) -> dict[str, Any]:
    """Parent report with intake.children[] and rolled-up verdict."""
    malicious: list[dict[str, Any]] = []
    for ch in children:
        malicious.extend(ch.get("malicious_findings") or [])

    verdict = rollup_verdict(children) if len(children) > 1 else (children[0].get("verdict") if children else calculate_verdict(primary_surface, primary_dynamic, primary_static))

    if len(children) == 1:
        iocs = aggregate_iocs(primary_surface, primary_dynamic, primary_static)
    else:
        iocs: dict[str, Any] = {
            "hashes": {},
            "urls": [],
            "ips": [],
            "domains": [],
            "emails": [],
            "registry_keys": [],
            "mutexes": [],
        }
        for ch in children:
            sub = aggregate_iocs(ch.get("phase1_surface") or {}, {}, {})
            iocs["hashes"].update(sub.get("hashes") or {})
            for key in ("urls", "ips", "domains", "emails", "registry_keys", "mutexes"):
                iocs[key] = sorted(set(iocs[key]) | set(sub.get(key) or []))

    ts = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "meta": {"schema_version": REPORT_SCHEMA_VERSION, "timestamp": ts, "sample_name": sample_name},
        "verdict": verdict,
        "intake": {
            "status": intake_meta.get("status"),
            "archive": intake_meta.get("archive"),
            "archive_type": intake_meta.get("archive_type"),
            "password_used": intake_meta.get("password_used"),
            "extracted_count": intake_meta.get("extracted_count"),
            "error": intake_meta.get("error"),
            "children": [
                {
                    "path": ch.get("path"),
                    "sha256": (ch.get("phase1_surface") or {}).get("hashes", {}).get("sha256"),
                    "verdict": ch.get("verdict"),
                    "highlights": ch.get("highlights"),
                    "phase1_surface": ch.get("phase1_surface"),
                    "phase1b_unpack": ch.get("phase1b_unpack"),
                    "phase2_dynamic": ch.get("phase2_dynamic"),
                    "phase3_static": ch.get("phase3_static"),
                }
                for ch in children
            ],
        },
        "malicious_findings": malicious,
        "phase1_surface": primary_surface,
        "phase1b_unpack": primary_unpack or {"status": "skipped"},
        "phase2_dynamic": primary_dynamic,
        "phase3_static": primary_static,
        "phase_status": {
            "surface": _phase_status(primary_surface),
            "unpack": _phase_status(primary_unpack or {"status": "skipped"}),
            "dynamic": _phase_status(primary_dynamic),
            "static": _phase_status(primary_static),
        },
        "iocs": iocs,
        "mitre_mapping": primary_surface.get("mitre") if isinstance(primary_surface, dict) else None,
        "re_analysis": build_re_analysis(primary_surface, primary_static),
    }

    out_dir = out_dir or Path(os.environ.get("RESULTS_DIR", "results")) / "reports"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if executive_summary_llm:
        report["executive_summary"] = _ollama_summarize(report, ollama_base_url, ollama_model)

    base = _safe_name(sample_name)
    json_path = out_dir / f"{base}.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    html_path: Optional[Path] = None
    if html:
        html_path = out_dir / f"{base}.html"
        _render_html(report, html_path)
    _finalize_report_paths(report, out_dir, base, json_path, html_path)
    return report


def _render_html(report: dict[str, Any], dest: Path) -> None:
    here = Path(__file__).resolve().parent
    tpl_dir = here / "templates"
    if not tpl_dir.is_dir():
        raise ReportError(f"Template dir missing: {tpl_dir}")
    env = Environment(
        loader=FileSystemLoader(str(tpl_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    def _tojson_filter(value: Any) -> str:
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)

    env.filters["tojson"] = _tojson_filter
    tpl = env.get_template("report.html")
    html = tpl.render(report=report, json_pretty=json.dumps(report, indent=2, default=str)[:50000])
    dest.write_text(html, encoding="utf-8")
