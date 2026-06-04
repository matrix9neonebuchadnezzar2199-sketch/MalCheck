"""Offline export of report 2.1 to CSV, MISP JSON, and STIX 2.1 bundle."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _iocs_from_report(report: dict[str, Any]) -> dict[str, list[str]]:
    iocs = report.get("iocs") or {}
    if not isinstance(iocs, dict):
        return {}
    return {
        "md5": [iocs.get("hashes", {}).get("md5")] if iocs.get("hashes", {}).get("md5") else [],
        "sha256": [iocs.get("hashes", {}).get("sha256")] if iocs.get("hashes", {}).get("sha256") else [],
        "url": list(iocs.get("urls") or []),
        "ip": list(iocs.get("ips") or []),
        "domain": list(iocs.get("domains") or []),
        "email": list(iocs.get("emails") or []),
        "registry": list(iocs.get("registry_keys") or []),
        "mutex": list(iocs.get("mutexes") or []),
    }


def export_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "sample", "verdict"])
    sample = str((report.get("meta") or {}).get("sample_name") or "")
    verdict = str((report.get("verdict") or {}).get("label") or "")
    for kind, values in _iocs_from_report(report).items():
        for v in values:
            if v:
                w.writerow([kind, v, sample, verdict])
    for m in report.get("malicious_findings") or []:
        if isinstance(m, dict):
            w.writerow(["finding", m.get("summary"), m.get("child"), m.get("severity")])
    return buf.getvalue()


def export_misp_event(report: dict[str, Any]) -> dict[str, Any]:
    meta = report.get("meta") or {}
    iocs = _iocs_from_report(report)
    attributes: list[dict[str, Any]] = []
    for kind, values in iocs.items():
        misp_type = {
            "md5": "md5",
            "sha256": "sha256",
            "url": "url",
            "ip": "ip-dst",
            "domain": "domain",
            "email": "email-src",
            "registry": "regkey",
            "mutex": "mutex",
        }.get(kind, "text")
        for v in values:
            if v:
                attributes.append({"type": misp_type, "value": v, "comment": "MalCheck export"})
    return {
        "Event": {
            "info": f"MalCheck: {meta.get('sample_name', 'sample')}",
            "date": (meta.get("timestamp") or datetime.now(timezone.utc).isoformat())[:10],
            "analysis": "2",
            "distribution": "0",
            "Attribute": attributes,
        }
    }


def export_stix_bundle(report: dict[str, Any]) -> dict[str, Any]:
    meta = report.get("meta") or {}
    sample = str(meta.get("sample_name") or "sample")
    ts = meta.get("timestamp") or datetime.now(timezone.utc).isoformat()
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "name": "MalCheck",
            "identity_class": "system",
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{uuid.uuid4()}",
            "name": sample,
            "is_family": False,
            "malware_types": ["unknown"],
        },
    ]
    malware_id = objects[1]["id"]
    iocs = _iocs_from_report(report)
    for sha in iocs.get("sha256") or []:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": ts,
                "pattern": f"[file:hashes.'SHA-256' = '{sha}']",
                "pattern_type": "stix",
                "valid_from": ts,
            }
        )
    for ip in iocs.get("ip") or []:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": ts,
                "pattern": f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": ts,
            }
        )
    for dom in iocs.get("domain") or []:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": ts,
                "pattern": f"[domain-name:value = '{dom}']",
                "pattern_type": "stix",
                "valid_from": ts,
            }
        )
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
        "extensions": {"malcheck_malware_ref": malware_id},
    }


def write_exports(report: dict[str, Any], out_dir: Any, base: str) -> dict[str, str]:
    from pathlib import Path

    out_dir = Path(out_dir)
    paths: dict[str, str] = {}
    csv_path = out_dir / f"{base}.csv"
    csv_path.write_text(export_csv(report), encoding="utf-8")
    paths["csv"] = str(csv_path)
    misp_path = out_dir / f"{base}.misp.json"
    misp_path.write_text(json.dumps(export_misp_event(report), indent=2), encoding="utf-8")
    paths["misp"] = str(misp_path)
    stix_path = out_dir / f"{base}.stix.json"
    stix_path.write_text(json.dumps(export_stix_bundle(report), indent=2), encoding="utf-8")
    paths["stix"] = str(stix_path)
    return paths
