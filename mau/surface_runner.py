"""Phase 1: surface analysis via docker exec (REMnux/surface) or subprocess fallback."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

import docker
from docker.errors import DockerException, NotFound

from mau.errors import DockerError, SurfaceError

log = logging.getLogger(__name__)


def _docker_sdk_exec(
    container_name: str,
    script: str,
    sample_in_container: str,
) -> dict[str, Any]:
    try:
        client = docker.from_env()
    except DockerException as e:
        raise DockerError("Cannot connect to Docker", str(e)) from e
    try:
        c = client.containers.get(container_name)
    except NotFound as e:
        raise SurfaceError(f"Container not running: {container_name}", str(e)) from e
    cmd = ["python3", script, sample_in_container]
    try:
        result = c.exec_run(cmd, demux=False)
    except DockerException as e:
        raise SurfaceError("docker exec_run failed", str(e)) from e

    if hasattr(result, "exit_code"):
        exit_code = result.exit_code
        output = result.output
    else:
        exit_code, output = result[0], result[1]
    if isinstance(output, bytes):
        text = output.decode("utf-8", errors="replace")
    else:
        text = str(output)

    if exit_code != 0:
        raise SurfaceError(
            f"Surface script failed (exit {exit_code})",
            text[:8000] if text else None,
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise SurfaceError("Surface output is not valid JSON", text[:2000]) from e


def _subprocess_local(analyze_py: Path, sample_path: Path, timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            [sys.executable, str(analyze_py), str(sample_path)],
            capture_output=True,
            text=True,
            timeout=timeout + 60,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise SurfaceError("Local surface analysis timed out", str(e)) from e
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise SurfaceError(
            f"Local analyze.py failed (exit {proc.returncode})",
            err[:8000] if err else None,
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise SurfaceError("Local surface output is not valid JSON", proc.stdout[:2000]) from e


def run_surface_analysis(
    sample_path: str,
    *,
    container: Optional[str] = None,
    timeout_sec: int = 600,
    script_in_container: str = "/scripts/analyze.py",
    sample_mount_path: str = "/samples",
) -> dict[str, Any]:
    """
    Run surface analyzer. Prefer docker exec into `container` when set.
    """
    path = Path(sample_path).resolve()
    if not path.is_file():
        raise SurfaceError(f"Sample not found: {path}")

    container = container or os.environ.get("REMNUX_CONTAINER") or os.environ.get("SURFACE_CONTAINER")

    if container:
        rel = path.name
        in_container = f"{sample_mount_path.rstrip('/')}/{rel}"
        try:
            return _docker_sdk_exec(container, script_in_container, in_container)
        except (DockerError, SurfaceError):
            log.warning("docker exec surface failed, trying local analyze.py fallback", exc_info=True)

    here = Path(__file__).resolve().parent
    repo_root = here.parent
    analyze_py = repo_root / "scripts" / "remnux" / "analyze.py"
    if not analyze_py.is_file():
        raise SurfaceError(
            "Surface analysis unavailable: no container and scripts/remnux/analyze.py missing",
            str(analyze_py),
        )
    return _subprocess_local(analyze_py, path, timeout_sec)
