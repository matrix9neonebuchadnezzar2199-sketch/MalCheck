"""FastAPI Web UI — upload sample, run pipeline, show report links."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.templating import Jinja2Templates

from mau.phase_router import run_pipeline_with_intake

log = logging.getLogger(__name__)

app = FastAPI(title="Malware Unified Analyzer", version="1.0.0")

_here = Path(__file__).resolve().parent
_tpl_dir = _here / "templates_web"
_jinja_env = Environment(
    loader=FileSystemLoader(str(_tpl_dir)),
    autoescape=select_autoescape(["html", "xml"]),
    cache_size=0,
)
templates = Jinja2Templates(env=_jinja_env)

_SAFE_BASE = re.compile(r"^[\w.\-]+$")


def _samples_dir() -> Path:
    return Path(os.environ.get("SAMPLES_DIR", "/samples"))


def _results_dir() -> Path:
    return Path(os.environ.get("RESULTS_DIR", "/results"))


def _reports_dir() -> Path:
    return _results_dir() / "reports"


def _safe_report_base(name: str) -> str:
    base = Path(name).name
    for suffix in (".html", ".json", ".csv", ".misp.json", ".stix.json"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    if not base or not _SAFE_BASE.match(base):
        raise HTTPException(status_code=400, detail="Invalid report name")
    return base


def _resolve_report_file(base: str, suffix: str) -> Path:
    reports = _reports_dir().resolve()
    path = (reports / f"{base}{suffix}").resolve()
    if reports not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return path


def _list_reports(limit: int = 50) -> list[dict[str, Any]]:
    rd = _reports_dir()
    if not rd.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for jp in sorted(rd.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        if jp.name.startswith("."):
            continue
        base = jp.stem
        try:
            _safe_report_base(base)
        except HTTPException:
            continue
        meta: dict[str, Any] = {}
        try:
            data = json.loads(jp.read_text(encoding="utf-8"))
            meta = data.get("meta") or {}
            verdict = data.get("verdict") or {}
        except (OSError, json.JSONDecodeError):
            verdict = {}
        mtime = datetime.fromtimestamp(jp.stat().st_mtime, tz=timezone.utc).isoformat()
        rows.append(
            {
                "base": base,
                "sample_name": meta.get("sample_name") or base,
                "timestamp": meta.get("timestamp") or mtime,
                "verdict_label": verdict.get("label"),
                "verdict_score": verdict.get("score"),
                "view_url": f"/reports/{base}.html",
                "json_url": f"/reports/{base}.json",
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _export_urls(base: str) -> dict[str, str]:
    return {
        "csv": f"/export/{base}/csv",
        "misp": f"/export/{base}/misp",
        "stix": f"/export/{base}/stix",
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "title": "Malware Unified Analyzer",
            "recent_reports": _list_reports(20),
        },
    )


@app.get("/api/reports")
async def api_reports() -> JSONResponse:
    return JSONResponse({"reports": _list_reports(50)})


@app.get("/reports/{base}.html", response_class=FileResponse)
async def report_html(base: str) -> FileResponse:
    safe = _safe_report_base(base)
    return FileResponse(_resolve_report_file(safe, ".html"), media_type="text/html; charset=utf-8")


@app.get("/reports/{base}.json", response_class=FileResponse)
async def report_json(base: str) -> FileResponse:
    safe = _safe_report_base(base)
    return FileResponse(_resolve_report_file(safe, ".json"), media_type="application/json")


@app.get("/export/{base}/csv", response_class=FileResponse)
async def export_csv(base: str) -> FileResponse:
    safe = _safe_report_base(base)
    return FileResponse(_resolve_report_file(safe, ".csv"), media_type="text/csv")


@app.get("/export/{base}/misp", response_class=FileResponse)
async def export_misp(base: str) -> FileResponse:
    safe = _safe_report_base(base)
    return FileResponse(_resolve_report_file(safe, ".misp.json"), media_type="application/json")


@app.get("/export/{base}/stix", response_class=FileResponse)
async def export_stix(base: str) -> FileResponse:
    safe = _safe_report_base(base)
    return FileResponse(_resolve_report_file(safe, ".stix.json"), media_type="application/json")


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    archive_password: str = Form(default="infected"),
) -> JSONResponse:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename")
    safe_name = Path(file.filename).name
    if ".." in safe_name or safe_name.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid filename")

    samples = _samples_dir()
    samples.mkdir(parents=True, exist_ok=True)
    dest = samples / safe_name

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = Path(tmp.name)
        shutil.move(str(tmp_path), dest)
    except OSError as e:
        log.exception("Upload failed")
        raise HTTPException(status_code=500, detail=str(e)) from e
    finally:
        file.file.close()

    try:
        out = run_pipeline_with_intake(
            str(dest),
            sample_name=safe_name,
            archive_password=archive_password.strip() or None,
        )
    except Exception as e:
        log.exception("Pipeline failed")
        try:
            dest.unlink(missing_ok=True)  # type: ignore[arg-type]
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=str(e)) from e

    report = out.get("report") or {}
    paths = report.get("_paths") or {}
    intake = out.get("intake") or {}
    malicious = report.get("malicious_findings") or []
    from mau.report_generator import _safe_name

    base = _safe_name(safe_name)
    return JSONResponse(
        {
            "ok": True,
            "sample": safe_name,
            "report_json": paths.get("json"),
            "report_html": paths.get("html"),
            "report_view_url": f"/reports/{base}.html",
            "report_json_url": f"/reports/{base}.json",
            "exports": _export_urls(base),
            "export_paths": {
                k: paths.get(k) for k in ("csv", "misp", "stix") if paths.get(k)
            },
            "verdict": report.get("verdict"),
            "intake": {
                "status": intake.get("status"),
                "archive": intake.get("archive"),
                "extracted_count": intake.get("extracted_count"),
                "password_used": intake.get("password_used"),
            },
            "malicious_findings_count": len(malicious),
            "malicious_findings": malicious[:20],
        }
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
