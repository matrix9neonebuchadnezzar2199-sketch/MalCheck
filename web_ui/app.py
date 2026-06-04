"""FastAPI Web UI — upload sample, run pipeline, show report links."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.templating import Jinja2Templates

from mau.phase_router import run_pipeline_with_intake

log = logging.getLogger(__name__)

app = FastAPI(title="Malware Unified Analyzer", version="1.0.0")

_here = Path(__file__).resolve().parent
_tpl_dir = _here / "templates_web"
# Jinja2 の環境キャッシュが絡む例外を避けるため cache_size=0 にして無効化。
_jinja_env = Environment(
    loader=FileSystemLoader(str(_tpl_dir)),
    autoescape=select_autoescape(["html", "xml"]),
    cache_size=0,
)
templates = Jinja2Templates(env=_jinja_env)


def _samples_dir() -> Path:
    return Path(os.environ.get("SAMPLES_DIR", "/samples"))


def _results_dir() -> Path:
    return Path(os.environ.get("RESULTS_DIR", "/results"))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "title": "Malware Unified Analyzer",
        },
    )


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
    return JSONResponse(
        {
            "ok": True,
            "sample": safe_name,
            "report_json": paths.get("json"),
            "report_html": paths.get("html"),
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
