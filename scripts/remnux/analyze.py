#!/usr/bin/env python3
"""
Surface analysis script — prints one JSON object to stdout.
Works in REMnux, slim surface container, or host with optional tools.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional, Tuple


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _strings_blob(path: Path, max_bytes: int = 4_000_000) -> bytes:
    try:
        data = path.read_bytes()[:max_bytes]
    except OSError:
        return b""
    return data


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    pat = rb"[\x20-\x7e]{%d,}" % min_len
    return [m.group().decode("ascii", errors="ignore") for m in re.finditer(pat, data)]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    ln = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / ln
        ent -= p * math.log2(p)
    return round(ent, 4)


def _run_cmd(cmd: list[str], timeout: int = 120) -> Tuple[Optional[str], int]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        out = (proc.stdout or "") + (proc.stderr or "")
        return out.strip() or None, proc.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, -1


def _yara_scan(sample: Path, rules_dir: Path) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    if not rules_dir.is_dir():
        return matches
    rules = list(rules_dir.glob("**/*.yar")) + list(rules_dir.glob("**/*.yara"))
    if not rules:
        return matches
    try:
        import yara  # type: ignore
    except ImportError:
        return matches
    for rf in rules[:200]:
        try:
            ru = yara.compile(filepath=str(rf))
            for m in ru.match(str(sample)):
                matches.append({"rule": m.rule, "file": str(rf), "strings": [str(x) for x in (m.strings or [])][:20]})
        except Exception:
            continue
    return matches


def _capa_scan(sample: Path) -> list[dict[str, Any]]:
    out, code = _run_cmd(["capa", str(sample), "-j"], timeout=300)
    if code != 0 or not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            rows = data.get("rows") or data.get("matches") or []
            return rows if isinstance(rows, list) else []
    except json.JSONDecodeError:
        pass
    return []


def _die_scan(sample: Path) -> Optional[dict[str, Any]]:
    for exe in ("diec", "die", "detect-it-easy"):
        out, code = _run_cmd([exe, str(sample)], timeout=60)
        if code == 0 and out:
            return {"tool": exe, "raw": out[:4000]}
    return None


def analyze(sample_path: str) -> dict[str, Any]:
    path = Path(sample_path)
    result: dict[str, Any] = {
        "sample": str(path),
        "error": None,
        "hashes": {},
        "file_type": None,
        "strings_sample": [],
        "urls": [],
        "ips": [],
        "entropy": None,
        "packer": None,
        "yara_matches": [],
        "capa_matches": [],
        "mitre": [],
    }

    if not path.is_file():
        result["error"] = "not a file"
        return result

    try:
        result["hashes"] = {"md5": _md5(path), "sha256": _sha256(path)}
    except OSError as e:
        result["error"] = str(e)
        return result

    try:
        import magic  # type: ignore

        result["file_type"] = magic.from_file(str(path))
    except Exception:
        ft, _ = _run_cmd(["file", "-b", str(path)])
        result["file_type"] = ft

    blob = _strings_blob(path)
    result["entropy"] = _entropy(blob)
    strs = _extract_ascii_strings(blob)[:500]
    result["strings_sample"] = strs[:80]

    url_re = re.compile(r"https?://[^\s\x00-\x1f\"'<>]+|ftp://[^\s\x00-\x1f\"'<>]+", re.I)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    urls: set[str] = set()
    ips: set[str] = set()
    for s in strs:
        urls.update(url_re.findall(s)[:5])
        ips.update(ip_re.findall(s)[:5])
    result["urls"] = sorted(urls)[:50]
    result["ips"] = sorted(ips)[:50]

    result["packer"] = {"detected": False, "detail": _die_scan(path)}

    rules_dir = Path(os.environ.get("RULES_DIR", "/rules"))
    if not rules_dir.is_dir():
        rr = Path(__file__).resolve().parents[2] / "rules" / "yara"
        if rr.is_dir():
            rules_dir = rr
    result["yara_matches"] = _yara_scan(path, rules_dir)

    capa = _capa_scan(path)
    result["capa_matches"] = capa[:200]

    if result["entropy"] and result["entropy"] > 7.2:
        result["packer"] = {"detected": True, "detail": result["packer"].get("detail"), "note": "high entropy"}

    for m in result["capa_matches"][:50]:
        if isinstance(m, dict) and m.get("rule"):
            result["mitre"].append({"source": "capa", "rule": m.get("rule")})

    return result


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: analyze.py <sample_path>"}), file=sys.stderr)
        return 2
    try:
        out = analyze(sys.argv[1])
        print(json.dumps(out, ensure_ascii=False, default=str))
        return 0 if not out.get("error") else 1
    except Exception as e:
        print(json.dumps({"error": True, "message": str(e)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
