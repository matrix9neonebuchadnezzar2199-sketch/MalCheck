"""Phase 3: Ghidra headless via Docker SDK (network none, auto-remove)."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

import docker
from docker.errors import APIError, DockerException, ImageNotFound

from mau.errors import DockerError, StaticError
from mau.static_normalize import load_static_outputs, static_failed

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
    Run ghidra-headless container once; collect analysis.json (auto_analyze) and optional legacy files.
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

    result = load_static_outputs(static_dir, image=image)
    if result.get("status") == "failed" and log_text and "analysis.json" not in log_text:
        result["logs"] = {**result.get("logs", {}), "container_tail": log_text[-4000:]}
    return result
