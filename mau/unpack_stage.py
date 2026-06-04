"""Optional unpack stage between surface and static (PE, packer-suspected)."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

_PE_SUFFIX = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_pe_path(path: Path) -> bool:
    return path.suffix.lower() in _PE_SUFFIX


def packer_suspected(surface: dict[str, Any]) -> bool:
    if not isinstance(surface, dict) or surface.get("error"):
        return False
    packer = surface.get("packer") or {}
    if isinstance(packer, dict) and packer.get("detected"):
        return True
    ent = surface.get("entropy")
    if isinstance(ent, (int, float)) and ent > 7.2:
        return True
    for sr in surface.get("scanner_results") or []:
        if not isinstance(sr, dict):
            continue
        for f in sr.get("findings") or []:
            if not isinstance(f, dict):
                continue
            if f.get("rule") in (
                "pe_high_entropy_section",
                "pe_packer_section_name",
                "high_entropy",
                "die_detected",
            ):
                return True
    if isinstance(packer, dict):
        detail = packer.get("detail")
        if isinstance(detail, dict):
            raw = str(detail.get("raw") or "").lower()
            if any(x in raw for x in ("upx", "pack", "themida", "vmprotect", "aspack", "mpress")):
                return True
    return False


def _pe_oep_rva(path: Path) -> Optional[str]:
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path))
        rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pe.close()
        return hex(int(rva))
    except Exception:
        return None


def _try_upx(sample: Path, out_path: Path, timeout: int) -> Optional[dict[str, Any]]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sample, out_path)
    proc = subprocess.run(
        ["upx", "-d", "-o", str(out_path), str(sample)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0 or not out_path.is_file():
        if out_path.is_file():
            out_path.unlink(missing_ok=True)
        return None
    oep = _pe_oep_rva(out_path)
    return {
        "tool": "upx",
        "unpacked_path": str(out_path.resolve()),
        "oep_rva": oep,
        "packer_hint": "UPX",
        "detail": (proc.stdout or proc.stderr or "")[:500],
    }


def _try_unipacker(sample: Path, out_dir: Path, timeout: int) -> Optional[dict[str, Any]]:
    try:
        from unipacker import UnpackerEngine  # type: ignore
    except ImportError:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        engine = UnpackerEngine(str(sample.resolve()), str(out_dir.resolve()))
        engine.unpack()
    except Exception as e:
        log.debug("unipacker failed: %s", e)
        return None
    candidates = sorted(out_dir.glob("*.exe")) + sorted(out_dir.glob("*.dll"))
    if not candidates:
        candidates = [p for p in out_dir.iterdir() if p.is_file() and p.suffix.lower() in _PE_SUFFIX]
    if not candidates:
        return None
    out_path = candidates[0]
    return {
        "tool": "unipacker",
        "unpacked_path": str(out_path.resolve()),
        "oep_rva": _pe_oep_rva(out_path),
        "packer_hint": "unipacker",
        "detail": f"output under {out_dir}",
    }


def run_unpack_stage(
    sample_path: str,
    surface: dict[str, Any],
    *,
    enabled: bool = True,
    timeout_sec: int = 180,
    max_attempts: int = 2,
) -> dict[str, Any]:
    """
    When packer is suspected on a PE, try UPX then unipacker.
    Returns phase1b_unpack contract (never raises).
    """
    path = Path(sample_path).resolve()
    base: dict[str, Any] = {
        "status": "not_attempted",
        "sample": str(path),
        "input_sha256": None,
        "unpacked_path": None,
        "oep_rva": None,
        "oep_va": None,
        "tool": None,
        "packer_hint": None,
        "error": None,
    }

    if not enabled:
        base["status"] = "skipped"
        base["error"] = "phases.unpack.enabled is false"
        return base

    if not path.is_file() or not is_pe_path(path):
        base["status"] = "skipped"
        base["error"] = "not a PE file"
        return base

    if not packer_suspected(surface):
        base["status"] = "skipped"
        base["error"] = "packer not suspected from surface"
        return base

    try:
        base["input_sha256"] = _sha256_file(path)
    except OSError as e:
        base["status"] = "failed"
        base["error"] = str(e)
        return base

    results_root = Path(os.environ.get("RESULTS_DIR", Path.cwd() / "results")).resolve()
    out_dir = results_root / "unpack" / uuid.uuid4().hex[:12]
    out_path = out_dir / f"{path.stem}_unpacked{path.suffix}"
    per_tool_timeout = max(30, timeout_sec // max(1, max_attempts))

    attempts: list[dict[str, Any]] = []
    if max_attempts >= 1:
        upx = _try_upx(path, out_path, per_tool_timeout)
        if upx:
            attempts.append(upx)
    if not attempts and max_attempts >= 2:
        uni = _try_unipacker(path, out_dir / "unipacker", per_tool_timeout)
        if uni:
            attempts.append(uni)

    if not attempts:
        base["status"] = "failed"
        base["error"] = "UPX and unipacker could not unpack sample"
        return base

    best = attempts[0]
    base["status"] = "completed"
    base["unpacked_path"] = best.get("unpacked_path")
    base["oep_rva"] = best.get("oep_rva")
    base["tool"] = best.get("tool")
    base["packer_hint"] = best.get("packer_hint")
    if base["oep_rva"]:
        try:
            import pefile

            pe = pefile.PE(str(base["unpacked_path"]))
            base["oep_va"] = hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            pe.close()
        except Exception:
            pass
    return base
