"""Structured errors for orchestrator phases."""

from __future__ import annotations

from typing import Optional


class MauError(Exception):
    """Base error."""

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


class ConfigError(MauError):
    """Invalid configuration or missing files."""


class DockerError(MauError):
    """Docker daemon or container operation failed."""


class PhaseError(MauError):
    """A single analysis phase failed (partial result may exist)."""


class SurfaceError(PhaseError):
    """Surface / Phase 1 analysis failed."""


class DynamicError(PhaseError):
    """Dynamic / Phase 2 analysis failed."""


class StaticError(PhaseError):
    """Static / Ghidra phase failed."""


class ReportError(MauError):
    """Report generation failed."""
