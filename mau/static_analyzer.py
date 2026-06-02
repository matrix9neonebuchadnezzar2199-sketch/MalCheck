"""Phase 3: Ghidra headless via Docker SDK (network none, auto-remove)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

import docker
from docker.errors import APIError, DockerException, ImageNotFound

from mau.errors import DockerError, StaticError

log = logging.getLogger(__name__)


def _client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except DockerException as e:
        raise DockerError("Cannot connect to Docker", str(e)) from e


def run_static_analysis(
    sample_path: str,
    *,
    image: str = "ghidra-headless:latest",
    timeout_sec: int = 600,
    output_subdir: Optional[str] = None,
) -> dict[str, Any]:
    """
    Run ghidra-headless container once; collect decompiled.c, functions.json, metadata.json.
    """
    host_sample = Path(sample_path).resolve()
    if not host_sample.is_file():
        raise StaticError(f"Sample not found: {host_sample}")

    results_root = Path(os.environ.get("RESULTS_DIR", Path.cwd() / "results")).resolve()
    static_dir = results_root / "static"
    if output_subdir:
        static_dir = static_dir / output_subdir
    static_dir.mkdir(parents=True, exist_ok=True)

    client = _client()
    try:
        client.images.get(image)
    except ImageNotFound as e:
        raise StaticError(
            f"Ghidra image not loaded: {image}",
            "Run docker build or docker load first.",
        ) from e

    volumes = {
        str(host_sample): {"bind": "/samples/target.bin", "mode": "ro"},
        str(static_dir): {"bind": "/output", "mode": "rw"},
    }

    kwargs: dict[str, Any] = {
        "image": image,
        "command": ["target.bin", str(timeout_sec)],
        "volumes": volumes,
        "remove": True,
        "detach": False,
        "stdout": True,
        "stderr": True,
    }
    if os.environ.get("MAU_GHIDRA_NETWORK_NONE", "1") not in ("0", "false", "False"):
        kwargs["network_mode"] = "none"
    mem = os.environ.get("MAU_GHIDRA_MEM", "4g")
    kwargs["mem_limit"] = mem

    log.info("Starting Ghidra container image=%s sample=%s", image, host_sample)
    try:
        out = client.containers.run(**kwargs)
    except APIError as e:
        raise StaticError("Docker API error running Ghidra container", str(e)) from e
    except DockerException as e:
        raise DockerError("Docker error running Ghidra container", str(e)) from e

    log_text = out.decode("utf-8", errors="replace") if isinstance(out, bytes) else str(out)
    if log_text:
        log.debug("Ghidra container output (tail): %s", log_text[-2000:])

    result: dict[str, Any] = {
        "image": image,
        "output_dir": str(static_dir),
        "decompiled_c": None,
        "decompiled_summary": None,
        "functions": None,
        "metadata": None,
        "logs": {},
    }

    def _read_json(p: Path) -> Any:
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("Invalid JSON: %s", p)
            return None

    def _read_text(p: Path) -> Optional[str]:
        if not p.is_file():
            return None
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("Cannot read %s: %s", p, e)
            return None

    dc = static_dir / "decompiled.c"
    if dc.is_file():
        result["decompiled_c"] = _read_text(dc)
    ds = static_dir / "decompiled_summary.json"
    if ds.is_file():
        result["decompiled_summary"] = _read_json(ds)
    fn = static_dir / "functions.json"
    if fn.is_file():
        result["functions"] = _read_json(fn)
    meta = static_dir / "metadata.json"
    if meta.is_file():
        result["metadata"] = _read_json(meta)
    for log_name in ("ghidra_decompile.log", "ghidra_functions.log", "ghidra_metadata.log"):
        lp = static_dir / log_name
        if lp.is_file():
            result["logs"][log_name] = _read_text(lp)

    return result
