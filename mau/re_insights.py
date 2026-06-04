"""Roll up anti-analysis and obfuscation signals from static Ghidra JSON."""

from __future__ import annotations

from typing import Any, Optional

_ANTI_ANALYSIS_IDS = frozenset({
    "anti_debug",
    "nt_query_process",
    "output_debug",
    "timing",
    "tls_callback",
})

_SEVERITY_ORD = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORD.get((sev or "info").lower(), 0)


def rollup_decompile_insights(analysis_json: dict[str, Any]) -> dict[str, Any]:
    """
    Aggregate per-function decompile_insights into program-level anti_analysis_signals
    and obfuscation_stats.
    """
    signals: list[dict[str, Any]] = []
    stats = {
        "functions_with_insights": 0,
        "goto_flatten_count": 0,
        "opaque_predicate_count": 0,
        "infinite_loop_count": 0,
        "heavy_goto_flattening_count": 0,
        "string_decrypt_loop_count": 0,
        "anti_analysis_signal_count": 0,
    }

    funcs = analysis_json.get("functions")
    if not isinstance(funcs, list):
        return {"anti_analysis_signals": [], "obfuscation_stats": stats}

    seen_global: set[tuple[str, str]] = set()

    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        insights = fn.get("decompile_insights")
        if not isinstance(insights, dict):
            continue
        stats["functions_with_insights"] += 1
        fn_name = str(fn.get("name") or "?")
        fn_addr = str(fn.get("address") or "")

        istats = insights.get("stats")
        if isinstance(istats, dict):
            if istats.get("heavy_goto_flattening"):
                stats["heavy_goto_flattening_count"] += 1
            if istats.get("opaque_loop_hint"):
                stats["infinite_loop_count"] += 1

        for sig in insights.get("signals") or []:
            if not isinstance(sig, dict):
                continue
            sid = str(sig.get("id") or "")
            sev = str(sig.get("severity") or "info")
            label = str(sig.get("label") or sid)
            if sid == "goto_flatten":
                stats["goto_flatten_count"] += 1
            elif sid == "opaque_predicate_like":
                stats["opaque_predicate_count"] += 1
            elif sid == "infinite_loop":
                stats["infinite_loop_count"] += 1
            elif sid == "string_decrypt_loop":
                stats["string_decrypt_loop_count"] += 1
            if sid in _ANTI_ANALYSIS_IDS:
                stats["anti_analysis_signal_count"] += 1

            key = (sid, fn_addr)
            if key in seen_global:
                continue
            seen_global.add(key)
            signals.append(
                {
                    "id": sid,
                    "severity": sev,
                    "label": label,
                    "function": fn_name,
                    "address": fn_addr,
                }
            )

    signals.sort(key=lambda s: (-_severity_rank(str(s.get("severity"))), str(s.get("id"))))
    return {"anti_analysis_signals": signals, "obfuscation_stats": stats}


def enrich_summary(summary: dict[str, Any], analysis_json: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Add anti_analysis_count and top_anti_analysis_signals to static summary."""
    if analysis_json is None:
        return summary
    rolled = rollup_decompile_insights(analysis_json)
    anti = rolled["anti_analysis_signals"]
    anti_only = [s for s in anti if str(s.get("id")) in _ANTI_ANALYSIS_IDS]
    out = dict(summary)
    out["anti_analysis_count"] = len(anti_only)
    out["top_anti_analysis_signals"] = anti_only[:15]
    out["obfuscation_stats"] = rolled["obfuscation_stats"]
    out["anti_analysis_signals_total"] = len(anti)
    return out
