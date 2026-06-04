"""Normalize Ghidra headless outputs into phase3_static contract."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Cannot read JSON %s: %s", path, e)
        return None


def _read_text(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", path, e)
        return None


def _find_analysis_json(static_dir: Path) -> Optional[dict[str, Any]]:
    primary = static_dir / "analysis.json"
    data = _read_json(primary)
    if isinstance(data, dict):
        return data
    for p in sorted(static_dir.glob("*_analysis.json")):
        data = _read_json(p)
        if isinstance(data, dict):
            return data
    return None


def build_summary(analysis_json: dict[str, Any]) -> dict[str, Any]:
    funcs = analysis_json.get("functions")
    if not isinstance(funcs, list):
        funcs = []
    suspicious = analysis_json.get("suspicious_apis")
    if not isinstance(suspicious, list):
        suspicious = []
    return {
        "function_count": len(funcs),
        "suspicious_api_count": len(suspicious),
        "truncated": bool(analysis_json.get("truncated")),
        "architecture": analysis_json.get("architecture"),
        "compiler": analysis_json.get("compiler"),
        "file_name": analysis_json.get("file_name"),
        "suspicious_apis_top": suspicious[:10],
    }


def _metadata_from_analysis(analysis_json: dict[str, Any]) -> dict[str, Any]:
    return {
        "program": analysis_json.get("file_name"),
        "language": analysis_json.get("architecture"),
        "compiler": analysis_json.get("compiler"),
        "imports": analysis_json.get("imports") or [],
        "exports": analysis_json.get("exports") or [],
        "strings_sample": (analysis_json.get("strings") or [])[:200],
    }


def _decompiled_c_from_analysis(analysis_json: dict[str, Any], max_functions: int = 40) -> Optional[str]:
    parts: list[str] = []
    funcs = analysis_json.get("functions")
    if not isinstance(funcs, list):
        return None
    for fn in funcs[:max_functions]:
        if not isinstance(fn, dict):
            continue
        name = fn.get("name") or "?"
        addr = fn.get("address") or ""
        body = fn.get("decompiled_c")
        if isinstance(body, str) and body.strip():
            parts.append(f"// {name} @ {addr}\n{body}\n")
    return "\n".join(parts) if parts else None


def load_static_outputs(static_dir: Path, *, image: str = "") -> dict[str, Any]:
    """Read container output directory and return phase3_static-shaped dict."""
    logs: dict[str, str] = {}
    for log_name in (
        "ghidra_analysis.log",
        "ghidra_decompile.log",
        "ghidra_functions.log",
        "ghidra_metadata.log",
    ):
        text = _read_text(static_dir / log_name)
        if text:
            logs[log_name] = text

    analysis_json = _find_analysis_json(static_dir)
    decompiled_c = _read_text(static_dir / "decompiled.c")
    decompiled_summary = _read_json(static_dir / "decompiled_summary.json")
    functions = _read_json(static_dir / "functions.json")
    metadata = _read_json(static_dir / "metadata.json")

    if analysis_json:
        summary = build_summary(analysis_json)
        if not decompiled_c:
            decompiled_c = _decompiled_c_from_analysis(analysis_json)
        if not metadata:
            metadata = _metadata_from_analysis(analysis_json)
        if functions is None:
            functions = {
                "program": analysis_json.get("file_name"),
                "function_count": summary["function_count"],
                "functions": analysis_json.get("functions") or [],
            }
        status = "completed"
        error = None
    elif functions or metadata or decompiled_c:
        fn_list = []
        if isinstance(functions, dict):
            fn_list = functions.get("functions") or []
        summary = {
            "function_count": len(fn_list) if isinstance(fn_list, list) else 0,
            "suspicious_api_count": 0,
            "truncated": False,
            "architecture": (metadata or {}).get("language") if isinstance(metadata, dict) else None,
            "compiler": (metadata or {}).get("compiler") if isinstance(metadata, dict) else None,
            "file_name": (metadata or {}).get("program") if isinstance(metadata, dict) else None,
            "suspicious_apis_top": [],
        }
        status = "completed"
        error = None
    else:
        summary = {
            "function_count": 0,
            "suspicious_api_count": 0,
            "truncated": False,
            "suspicious_apis_top": [],
        }
        status = "failed"
        error = "No analysis.json or legacy Ghidra outputs in output directory"

    return {
        "engine": "ghidra_headless",
        "status": status,
        "analysis_json": analysis_json,
        "summary": summary,
        "decompiled_c": decompiled_c,
        "decompiled_summary": decompiled_summary,
        "functions": functions,
        "metadata": metadata,
        "error": error,
        "image": image,
        "output_dir": str(static_dir.resolve()),
        "logs": logs,
    }


def static_failed(message: str, detail: str = "", *, image: str = "") -> dict[str, Any]:
    return {
        "engine": "ghidra_headless",
        "status": "failed",
        "analysis_json": None,
        "summary": {
            "function_count": 0,
            "suspicious_api_count": 0,
            "truncated": False,
            "suspicious_apis_top": [],
        },
        "decompiled_c": None,
        "decompiled_summary": None,
        "functions": None,
        "metadata": None,
        "error": message,
        "detail": detail,
        "image": image,
        "logs": {},
    }
