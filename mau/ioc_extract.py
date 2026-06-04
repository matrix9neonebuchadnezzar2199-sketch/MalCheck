"""Extract IOCs from string lists (surface phase)."""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlparse

_URL_RE = re.compile(
    r"https?://[^\s\x00-\x1f\"'<>]+|ftp://[^\s\x00-\x1f\"'<>]+",
    re.I,
)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)
_DOMAIN_FROM_URL_RE = re.compile(
    r"(?:https?://|ftp://)?([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)",
    re.I,
)
_STANDALONE_DOMAIN_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+)\b"
)
_REGISTRY_RE = re.compile(
    r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|"
    r"HKLM|HKCU|HKCR|HKU|HKCC)"
    r"(?:\\[A-Za-z0-9_.\-\\]+)+",
    re.I,
)
_MUTEX_RE = re.compile(
    r"\b(?:Global|Local)\\[A-Za-z0-9_\-\\]{3,128}\b",
    re.I,
)

_DOMAIN_BLOCKLIST = frozenset(
    {
        "microsoft.com",
        "windows.com",
        "schemas.microsoft.com",
        "w3.org",
        "example.com",
        "localhost",
    }
)


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(x) for x in parts]
    except ValueError:
        return False
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 127:
        return True
    return False


def _normalize_domain(host: str) -> str | None:
    h = host.strip().lower().rstrip(".")
    if not h or "." not in h:
        return None
    if h in _DOMAIN_BLOCKLIST:
        return None
    if h.endswith((".dll", ".exe", ".sys", ".ocx")):
        return None
    if len(h) > 253:
        return None
    return h


def extract_iocs_from_strings(strings: Iterable[str]) -> dict[str, list[str]]:
    """Return urls, ips, domains, emails, registry_keys, mutexes (sorted, capped)."""
    urls: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()
    emails: set[str] = set()
    registry: set[str] = set()
    mutexes: set[str] = set()

    for raw in strings:
        if not raw or not isinstance(raw, str):
            continue
        s = raw.strip()
        if len(s) < 4:
            continue
        for u in _URL_RE.findall(s)[:8]:
            urls.add(u.rstrip(".,;)]}"))
            try:
                host = urlparse(u).hostname
                if host:
                    dom = _normalize_domain(host)
                    if dom:
                        domains.add(dom)
            except Exception:
                pass
        for ip in _IP_RE.findall(s)[:8]:
            if not _is_private_ip(ip):
                ips.add(ip)
        for em in _EMAIL_RE.findall(s)[:5]:
            if not em.lower().endswith((".dll", ".exe")):
                emails.add(em.lower())
        for reg in _REGISTRY_RE.findall(s)[:5]:
            registry.add(reg)
        for mx in _MUTEX_RE.findall(s)[:5]:
            mutexes.add(mx)
        for m in _STANDALONE_DOMAIN_RE.findall(s)[:5]:
            dom = _normalize_domain(m)
            if dom and dom not in domains:
                if not any(dom.endswith(x) for x in (".local", ".invalid")):
                    domains.add(dom)

    return {
        "urls": sorted(urls)[:50],
        "ips": sorted(ips)[:50],
        "domains": sorted(domains)[:50],
        "emails": sorted(emails)[:50],
        "registry_keys": sorted(registry)[:50],
        "mutexes": sorted(mutexes)[:50],
    }


def merge_surface_iocs(result: dict) -> None:
    """Merge IOC fields into surface analyze result dict in place."""
    strs = list(result.get("strings_sample") or [])
    iocs = extract_iocs_from_strings(strs)
    for key in ("urls", "ips", "domains", "emails", "registry_keys", "mutexes"):
        existing = result.get(key)
        if isinstance(existing, list):
            merged = sorted(set(existing) | set(iocs.get(key) or []))
            result[key] = merged[:50]
        else:
            result[key] = iocs.get(key) or []
