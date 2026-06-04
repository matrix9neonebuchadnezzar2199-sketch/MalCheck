"""Tests for archive intake."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from mau.config import DEFAULT_CONFIG
from mau.intake import _is_archive, process_intake


def test_is_archive_zip(tmp_path: Path) -> None:
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("hello.txt", b"test content")
    assert _is_archive(z) == "zip"


def test_process_intake_plain_file(tmp_path: Path) -> None:
    f = tmp_path / "plain.txt"
    f.write_text("hello", encoding="utf-8")
    cfg = dict(DEFAULT_CONFIG)
    out = process_intake(f, cfg)
    assert out["archive"] is False
    assert len(out["leaf_paths"]) == 1


def test_process_intake_zip_extracts(tmp_path: Path) -> None:
    z = tmp_path / "bundle.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("inner.txt", b"payload data")
    cfg = dict(DEFAULT_CONFIG)
    out = process_intake(z, cfg)
    assert out["status"] == "completed"
    assert out["archive"] is True
    assert out["extracted_count"] >= 1
    leaves = [Path(p) for p in out["leaf_paths"]]
    assert any(p.name == "inner.txt" for p in leaves)


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("pyzipper"),
    reason="pyzipper not installed",
)
def test_process_intake_encrypted_zip_infected(tmp_path: Path) -> None:
    import pyzipper

    z = tmp_path / "locked.zip"
    with pyzipper.AESZipFile(
        z,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"infected")
        zf.writestr("secret.exe", b"MZ" + b"\x00" * 64)

    cfg = dict(DEFAULT_CONFIG)
    out = process_intake(z, cfg)
    assert out["status"] == "completed"
    assert out.get("password_used") == "infected"
    names = [Path(p).name for p in out["leaf_paths"]]
    assert "secret.exe" in names
