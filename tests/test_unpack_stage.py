"""Tests for unpack stage (no real malware samples)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from mau.unpack_stage import is_pe_path, packer_suspected, run_unpack_stage


def test_packer_suspected_entropy() -> None:
    surface = {"entropy": 7.5, "packer": {"detected": False}}
    assert packer_suspected(surface) is True


def test_packer_suspected_negative() -> None:
    surface = {"entropy": 5.0, "packer": {"detected": False}, "scanner_results": []}
    assert packer_suspected(surface) is False


def test_unpack_skipped_not_pe(tmp_path: Path) -> None:
    f = tmp_path / "readme.txt"
    f.write_text("hello", encoding="utf-8")
    out = run_unpack_stage(str(f), {"packer": {"detected": True}}, enabled=True)
    assert out["status"] == "skipped"


def test_unpack_skipped_no_packer(tmp_path: Path) -> None:
    f = tmp_path / "app.exe"
    f.write_bytes(b"MZ" + b"\x00" * 64)
    surface = {"entropy": 5.0, "packer": {"detected": False}, "scanner_results": []}
    out = run_unpack_stage(str(f), surface, enabled=True)
    assert out["status"] == "skipped"


def test_unpack_disabled(tmp_path: Path) -> None:
    f = tmp_path / "app.exe"
    f.write_bytes(b"MZ")
    out = run_unpack_stage(str(f), {"packer": {"detected": True}}, enabled=False)
    assert out["status"] == "skipped"


def test_unpack_upx_success_mock(tmp_path: Path) -> None:
    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZpacked")
    unpacked = tmp_path / "packed_unpacked.exe"
    unpacked.write_bytes(b"MZunpacked")

    surface = {"packer": {"detected": True}, "entropy": 7.8}

    def fake_upx(s: Path, o: Path, timeout: int):
        o.parent.mkdir(parents=True, exist_ok=True)
        o.write_bytes(unpacked.read_bytes())
        return {
            "tool": "upx",
            "unpacked_path": str(o),
            "oep_rva": "0x1000",
            "packer_hint": "UPX",
        }

    with patch("mau.unpack_stage._try_upx", side_effect=fake_upx):
        with patch("mau.unpack_stage._sha256_file", return_value="abc"):
            out = run_unpack_stage(str(sample), surface, enabled=True, timeout_sec=60)
    assert out["status"] == "completed"
    assert out["tool"] == "upx"
    assert out["oep_rva"] == "0x1000"


def test_is_pe_path() -> None:
    assert is_pe_path(Path("x.exe")) is True
    assert is_pe_path(Path("x.txt")) is False
