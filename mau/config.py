"""Load analyzer.yaml with validation and safe defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional, Union

import yaml

from mau.errors import ConfigError


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


DEFAULT_CONFIG: dict[str, Any] = {
    "phases": {
        "surface": {"enabled": True, "timeout_sec": 600, "container": ""},
        "dynamic": {"enabled": False, "timeout_sec": 120},
        "static": {"enabled": True, "timeout_sec": 600, "ghidra_image": "ghidra-headless:latest"},
    },
    "docker": {
        "socket_url": "unix://var/run/docker.sock",
        "network_none": True,
        "mem_limit": "4g",
    },
    "ollama": {"enabled": False, "base_url": "http://host.docker.internal:11434", "model": "llama3.2"},
    "report": {"html": True, "executive_summary_llm": False},
    "intake": {
        "enabled": True,
        "passwords": ["", "infected", "malware", "virus"],
        "max_extract_mb": 500,
        "max_files": 200,
        "max_nested_depth": 8,
    },
}


def get_intake_config(cfg: dict[str, Any]) -> dict[str, Any]:
    from mau.intake import get_intake_config as _gic

    return _gic(cfg)


def load_config(path: Optional[Union[str, Path]] = None) -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    config_path = path or os.environ.get("MAU_CONFIG", "")
    if not config_path:
        for candidate in (
            Path("/config/analyzer.yaml"),
            Path(__file__).resolve().parents[1] / "compose" / "config" / "analyzer.yaml",
        ):
            if candidate.is_file():
                config_path = str(candidate)
                break
    if not config_path:
        return cfg
    p = Path(config_path)
    if not p.is_file():
        raise ConfigError(f"Config not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {p}", str(e)) from e
    if not isinstance(raw, dict):
        raise ConfigError("analyzer.yaml must be a mapping at root")
    merged = _deep_merge(cfg, raw)
    return merged


def get_phase_config(cfg: dict[str, Any], phase: str) -> dict[str, Any]:
    phases = cfg.get("phases") or {}
    if not isinstance(phases, dict):
        return {}
    p = phases.get(phase)
    return p if isinstance(p, dict) else {}
