"""Phase 2: dynamic analysis — stub / optional hooks (v0.6)."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from mau.errors import DynamicError

log = logging.getLogger(__name__)


def _normalize_dynamic_result(payload: Any, sample_path: str, timeout_sec: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    if not isinstance(payload, dict):
        return {
            "status": "error",
            "error": True,
            "reason": "dynamic hook output is not a JSON object",
            "sample": sample_path,
            "timeout_sec": timeout_sec,
            "timestamp": now,
        }
    result = dict(payload)
    status = str(result.get("status", "")).strip().lower()
    if status not in ("completed", "failed", "skipped", "not_implemented", "error"):
        status = "completed"
    result["status"] = status
    result.setdefault("sample", sample_path)
    result.setdefault("timeout_sec", timeout_sec)
    result.setdefault("timestamp", now)
    if status in ("failed", "error"):
        result.setdefault("error", True)
    return result


def run_dynamic_analysis(
    sample_path: str,
    *,
    enabled: bool = False,
    timeout_sec: int = 120,
) -> dict[str, Any]:
    """
    Placeholder for VM + INetSim / CAPE integration.
    When disabled, returns a structured skip record without raising.
    """
    if not enabled:
        return {
            "status": "skipped",
            "reason": "phases.dynamic.enabled is false or not configured",
            "sample": sample_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    hook = os.environ.get("MAU_DYNAMIC_HOOK", "").strip()
    if hook:
        # Optional external script: MAU_DYNAMIC_HOOK=/scripts/dynamic_hook.py
        try:
            import subprocess
            import sys

            proc = subprocess.run(
                [sys.executable, hook, sample_path, str(timeout_sec)],
                capture_output=True,
                text=True,
                timeout=timeout_sec + 30,
                check=False,
            )
            if proc.returncode != 0:
                raise DynamicError(
                    "Dynamic hook failed",
                    (proc.stderr or proc.stdout or "")[:4000],
                )
            import json

            data = json.loads(proc.stdout or "{}")
            return _normalize_dynamic_result(data, sample_path, timeout_sec)
        except Exception as e:
            log.exception("Dynamic hook error")
            raise DynamicError("Dynamic hook execution failed", str(e)) from e

    return {
        "status": "not_implemented",
        "reason": "Enable phases.dynamic and set MAU_DYNAMIC_HOOK to a JSON-emitting script, or integrate CAPE/VM in a future release",
        "sample": sample_path,
        "timeout_sec": timeout_sec,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
