"""Optional fuzzy hashes and PE imphash."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def _imphash_pefile(path: Path) -> str | None:
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ]
        )
    except Exception:
        return None

    entries: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace").lower()
        for imp in entry.imports or []:
            if imp.name:
                func = imp.name.decode("utf-8", errors="replace").lower()
            else:
                func = f"ord{imp.ordinal}"
            entries.append(f"{dll}.{func}")
    pe.close()
    if not entries:
        return None
    return hashlib.md5(",".join(entries).encode()).hexdigest()


def compute_fuzzy_hashes(path: Path, *, max_bytes: int = 50_000_000) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        data = path.read_bytes()[:max_bytes]
    except OSError:
        return out
    try:
        import ssdeep  # type: ignore

        out["ssdeep"] = ssdeep.hash(data)
    except Exception:
        pass
    try:
        import tlsh  # type: ignore

        h = tlsh.hash(data)
        if h:
            out["tlsh"] = h
    except Exception:
        pass
    imp = _imphash_pefile(path)
    if imp:
        out["imphash"] = imp
    return out
