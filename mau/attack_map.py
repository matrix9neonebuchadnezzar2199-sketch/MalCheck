"""Heuristic capa rule name → ATT&CK technique ID mapping (verify at attack.mitre.org)."""

from __future__ import annotations

import re
from typing import Any

# Substring in capa rule/namespace → technique ID (enterprise)
_RULE_HINTS: list[tuple[str, str, str]] = [
    (r"anti-debug|debugger", "T1622", "Debugger Evasion"),
    (r"anti-vm|virtualization|sandbox", "T1497", "Virtualization/Sandbox Evasion"),
    (r"process.?inject", "T1055", "Process Injection"),
    (r"create.?remote.?thread", "T1055", "Process Injection"),
    (r"credential", "T1003", "OS Credential Dumping"),
    (r"registry", "T1112", "Modify Registry"),
    (r"persist", "T1547", "Boot or Logon Autostart Execution"),
    (r"download", "T1105", "Ingress Tool Transfer"),
    (r"http|https|url", "T1071", "Application Layer Protocol"),
    (r"encrypt", "T1027", "Obfuscated Files or Information"),
    (r"shellcode", "T1059", "Command and Scripting Interpreter"),
    (r"mutex", "T1070", "Indicator Removal"),
]


def map_capa_to_attack(capa_matches: list[Any], *, limit: int = 30) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in capa_matches:
        if not isinstance(m, dict):
            continue
        rule = str(m.get("rule") or m.get("name") or "")
        ns = ""
        meta = m.get("meta")
        if isinstance(meta, dict):
            ns = str(meta.get("namespace") or "")
        blob = f"{rule} {ns}".lower()
        for pat, tid, title in _RULE_HINTS:
            if tid in seen:
                continue
            if re.search(pat, blob):
                seen.add(tid)
                out.append(
                    {
                        "technique_id": tid,
                        "technique_name": title,
                        "source_rule": rule or ns,
                        "confidence": "low",
                        "note": "Heuristic substring match; verify on MITRE ATT&CK",
                    }
                )
                break
        if len(out) >= limit:
            break
    return out
