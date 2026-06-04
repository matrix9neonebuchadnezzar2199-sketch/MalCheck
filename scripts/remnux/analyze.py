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

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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


_CAPA_ANTI_KEYWORDS = (
    "anti-analysis",
    "anti analysis",
    "anti-debug",
    "anti debug",
    "anti-vm",
    "anti vm",
    "anti-sandbox",
    "debugger",
    "virtualization",
)


def _capa_anti_analysis_matches(capa_matches: list[Any]) -> list[dict[str, Any]]:
    """Filter capa rows whose rule/namespace suggests anti-analysis or anti-VM."""
    out: list[dict[str, Any]] = []
    for m in capa_matches:
        if not isinstance(m, dict):
            continue
        rule = str(m.get("rule") or m.get("name") or "")
        ns = str(m.get("namespace") or m.get("meta", {}).get("namespace") if isinstance(m.get("meta"), dict) else "")
        blob = f"{rule} {ns}".lower()
        if any(kw in blob for kw in _CAPA_ANTI_KEYWORDS):
            out.append(m)
    return out[:25]


_PE_SUFFIX = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}


def _is_pe_sample(path: Path, file_type: Optional[str]) -> bool:
    if path.suffix.lower() in _PE_SUFFIX:
        return True
    ft = (file_type or "").lower()
    return "executable" in ft or "dosexec" in ft or "msdownload" in ft


def _packer_suspected(result: dict[str, Any]) -> bool:
    packer = result.get("packer") or {}
    if isinstance(packer, dict) and packer.get("detected"):
        return True
    ent = result.get("entropy")
    if isinstance(ent, (int, float)) and ent > 7.2:
        return True
    for sr in result.get("scanner_results") or []:
        if not isinstance(sr, dict):
            continue
        for f in sr.get("findings") or []:
            if isinstance(f, dict) and f.get("rule") in (
                "pe_high_entropy_section",
                "pe_packer_section_name",
                "high_entropy",
            ):
                return True
    die = packer.get("detail") if isinstance(packer, dict) else None
    if isinstance(die, dict):
        raw = str(die.get("raw") or "").lower()
        if raw and any(x in raw for x in ("upx", "pack", "themida", "vmprotect", "aspack")):
            return True
    return False


def _floss_scan(sample: Path, timeout: int = 120) -> dict[str, Any]:
    """Run FLOSS CLI when installed; return scanner-shaped metadata."""
    for cmd in (
        ["floss", str(sample)],
        [sys.executable, "-m", "floss", str(sample)],
    ):
        out, code = _run_cmd(cmd, timeout=timeout)
        if code == 0 and out:
            lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("---")]
            decoded = [ln for ln in lines if len(ln) >= 4 and not ln.startswith("[")][:500]
            return {
                "success": True,
                "strings": decoded,
                "stdout_sample": out[:2000],
            }
        if code == -1:
            continue
    return {"success": False, "error": "floss not installed or timed out"}


def _die_scan(sample: Path) -> Optional[dict[str, Any]]:
    for exe in ("diec", "die", "detect-it-easy"):
        out, code = _run_cmd([exe, str(sample)], timeout=60)
        if code == 0 and out:
            return {"tool": exe, "raw": out[:4000]}
    return None


def _risk_max(*levels: str) -> str:
    best = "safe"
    best_ord = _RISK_ORD[best]
    for level in levels:
        if not level:
            continue
        cur = _RISK_ORD.get(level, -1)
        if cur > best_ord:
            best = level
            best_ord = cur
    return best


def _build_scanner_result(
    name: str,
    *,
    success: bool,
    risk: str = "safe",
    findings: Optional[list[dict[str, Any]]] = None,
    metadata: Optional[dict[str, Any]] = None,
    error: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "scanner_name": name,
        "success": success,
        "risk": risk,
        "findings": findings or [],
        "metadata": metadata or {},
        "error": error,
    }


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
        "domains": [],
        "emails": [],
        "registry_keys": [],
        "mutexes": [],
        "entropy": None,
        "packer": None,
        "yara_matches": [],
        "capa_matches": [],
        "mitre": [],
        "scanner_results": [],
        "overall_risk": "safe",
    }

    if not path.is_file():
        result["error"] = "not a file"
        return result

    try:
        result["hashes"] = {"md5": _md5(path), "sha256": _sha256(path)}
        try:
            from fuzzy_hash import compute_fuzzy_hashes

            result["hashes"].update(compute_fuzzy_hashes(path))
        except ImportError:
            pass
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

    try:
        from ioc_extract import merge_surface_iocs

        merge_surface_iocs(result)
    except ImportError:
        result.setdefault("domains", [])
        result.setdefault("emails", [])
        result.setdefault("registry_keys", [])
        result.setdefault("mutexes", [])

    result["packer"] = {"detected": False, "detail": _die_scan(path)}
    die_detail = result["packer"].get("detail")
    if die_detail:
        result["scanner_results"].append(
            _build_scanner_result(
                "die",
                success=True,
                risk="low",
                findings=[
                    {
                        "rule": "die_detected",
                        "description": "Detect It Easy returned a detection detail",
                        "risk": "low",
                        "details": die_detail,
                    }
                ],
            )
        )
    else:
        result["scanner_results"].append(_build_scanner_result("die", success=True, risk="safe"))

    rules_dir = Path(os.environ.get("RULES_DIR", "/rules"))
    if not rules_dir.is_dir():
        rr = Path(__file__).resolve().parents[2] / "rules" / "yara"
        if rr.is_dir():
            rules_dir = rr
    result["yara_matches"] = _yara_scan(path, rules_dir)
    result["scanner_results"].append(
        _build_scanner_result(
            "yara",
            success=True,
            risk="high" if result["yara_matches"] else "safe",
            findings=[
                {
                    "rule": str(m.get("rule", "yara_match")),
                    "description": "YARA match detected",
                    "risk": "high",
                    "details": {"file": m.get("file"), "strings": m.get("strings", [])},
                }
                for m in result["yara_matches"]
                if isinstance(m, dict)
            ],
            metadata={"rules_dir": str(rules_dir)},
        )
    )

    capa = _capa_scan(path)
    result["capa_matches"] = capa[:200]
    result["scanner_results"].append(
        _build_scanner_result(
            "capa",
            success=True,
            risk="medium" if result["capa_matches"] else "safe",
            findings=[
                {
                    "rule": str(m.get("rule", "capa_match")),
                    "description": "capa capability matched",
                    "risk": "medium",
                    "details": m if isinstance(m, dict) else {"value": m},
                }
                for m in result["capa_matches"][:50]
            ],
            metadata={"total_matches": len(result["capa_matches"])},
        )
    )

    if result["entropy"] and result["entropy"] > 7.2:
        result["packer"] = {"detected": True, "detail": result["packer"].get("detail"), "note": "high entropy"}
        result["scanner_results"].append(
            _build_scanner_result(
                "entropy",
                success=True,
                risk="medium",
                findings=[
                    {
                        "rule": "high_entropy",
                        "description": "Sample entropy exceeded threshold",
                        "risk": "medium",
                        "details": {"entropy": result["entropy"], "threshold": 7.2},
                    }
                ],
            )
        )
    else:
        result["scanner_results"].append(_build_scanner_result("entropy", success=True, risk="safe"))

    try:
        from attack_map import map_capa_to_attack

        result["mitre"] = map_capa_to_attack(result["capa_matches"])
    except ImportError:
        for m in result["capa_matches"][:50]:
            if isinstance(m, dict) and m.get("rule"):
                result["mitre"].append({"source": "capa", "rule": m.get("rule")})

    anti_capa = _capa_anti_analysis_matches(result["capa_matches"])
    if anti_capa:
        result["scanner_results"].append(
            _build_scanner_result(
                "capa_anti_analysis",
                success=True,
                risk="medium",
                findings=[
                    {
                        "rule": str(m.get("rule", "capa_anti_analysis")),
                        "description": "capa anti-analysis / anti-VM capability",
                        "risk": "medium",
                        "details": m if isinstance(m, dict) else {"value": m},
                    }
                    for m in anti_capa[:15]
                ],
                metadata={"total_anti_analysis_matches": len(anti_capa)},
            )
        )

    try:
        from format_scanners import run_format_scanners

        for fmt in run_format_scanners(path, result.get("file_type")):
            result["scanner_results"].append(fmt)
    except ImportError:
        pass

    if _is_pe_sample(path, result.get("file_type")) and _packer_suspected(result):
        floss_timeout = int(os.environ.get("MAU_FLOSS_TIMEOUT", "120"))
        floss = _floss_scan(path, timeout=floss_timeout)
        if floss.get("success"):
            decoded = floss.get("strings") or []
            merged = list(dict.fromkeys((result.get("strings_sample") or []) + decoded))
            result["strings_sample"] = merged[:120]
            url_re = re.compile(r"https?://[^\s\x00-\x1f\"'<>]+|ftp://[^\s\x00-\x1f\"'<>]+", re.I)
            ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
            try:
                from ioc_extract import merge_surface_iocs

                merge_surface_iocs(result)
            except ImportError:
                pass
            result["scanner_results"].append(
                _build_scanner_result(
                    "floss",
                    success=True,
                    risk="low" if decoded else "safe",
                    findings=[
                        {
                            "rule": "floss_decoded_strings",
                            "description": f"FLOSS extracted {len(decoded)} decoded strings (sample)",
                            "risk": "low",
                            "details": {"count": len(decoded), "sample": decoded[:20]},
                        }
                    ],
                    metadata={"string_count": len(decoded)},
                )
            )
        else:
            result["scanner_results"].append(
                _build_scanner_result(
                    "floss",
                    success=False,
                    risk="safe",
                    error=str(floss.get("error") or "floss skipped"),
                )
            )

    try:
        from scanner_dedup import dedupe_scanner_results

        result["scanner_results"] = dedupe_scanner_results(result["scanner_results"])
    except ImportError:
        pass

    result["overall_risk"] = _risk_max(*(str(x.get("risk", "safe")) for x in result["scanner_results"]))
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
