"""PE / Office / PDF format-specific scanners for surface analyze.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

_RISK_ORD = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_PE_SUFFIX = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}
_OFFICE_SUFFIX = {
    ".doc",
    ".xls",
    ".ppt",
    ".docx",
    ".xlsx",
    ".pptx",
    ".docm",
    ".xlsm",
    ".pptm",
    ".xlsb",
    ".rtf",
    ".msi",
}
_PDF_SUFFIX = {".pdf"}

_ANTI_ANALYSIS_IMPORTS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "ZwQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "GetTickCount",
    "QueryPerformanceCounter",
    "Sleep",
    "NtSetInformationThread",
    "FindWindowA",
    "FindWindowW",
}

_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "InternetOpenA",
    "InternetOpenUrlA",
    "CryptEncrypt",
    "CryptDecrypt",
}

_PACKER_SECTION_HINTS = (".upx", "upx0", "upx1", ".themida", ".vmp", ".aspack", ".ndata")

_PDF_HIGH = {"/JS", "/JavaScript", "/Launch"}
_PDF_MEDIUM = {"/OpenAction", "/AA", "/RichMedia", "/XFA"}


def _build(
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


def _max_risk(current: str, new: str) -> str:
    if _RISK_ORD.get(new, 0) > _RISK_ORD.get(current, 0):
        return new
    return current


def _scan_pe(path: Path) -> dict[str, Any]:
    try:
        import pefile
    except ImportError:
        return _build("pefile", success=False, error="pefile not installed")

    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    try:
        pe = pefile.PE(str(path))
    except pefile.PEFormatError as e:
        return _build("pefile", success=False, error=f"PE parse error: {e}")

    metadata["machine"] = hex(pe.FILE_HEADER.Machine)
    metadata["num_sections"] = pe.FILE_HEADER.NumberOfSections
    try:
        ts = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=UTC)
        metadata["compile_time"] = ts.isoformat()
        if ts.year < 2000 or ts > datetime.now(UTC):
            findings.append(
                {
                    "rule": "pe_suspicious_timestamp",
                    "description": f"Suspicious compile timestamp: {ts.isoformat()}",
                    "risk": "medium",
                    "details": {"timestamp": ts.isoformat()},
                }
            )
    except Exception:
        pass

    for section in pe.sections:
        sec_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        sec_lower = sec_name.lower()
        ent = float(section.get_entropy())
        if ent > 7.0:
            findings.append(
                {
                    "rule": "pe_high_entropy_section",
                    "description": f"Section '{sec_name}' high entropy ({ent:.2f})",
                    "risk": "high",
                    "details": {"name": sec_name, "entropy": round(ent, 3)},
                }
            )
        if any(hint in sec_lower for hint in _PACKER_SECTION_HINTS):
            findings.append(
                {
                    "rule": "pe_packer_section_name",
                    "description": f"Section name suggests packer: {sec_name}",
                    "risk": "medium",
                    "details": {"name": sec_name},
                }
            )

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
            metadata["has_tls"] = True
            findings.append(
                {
                    "rule": "pe_tls_callbacks",
                    "description": "TLS directory present (callbacks may run before entry)",
                    "risk": "medium",
                    "details": {},
                }
            )
    except Exception:
        pass

    try:
        chars = pe.OPTIONAL_HEADER
        dll_chars = getattr(chars, "DllCharacteristics", 0) or 0
        metadata["dll_characteristics"] = hex(dll_chars)
        if not (dll_chars & 0x0040):
            findings.append(
                {
                    "rule": "pe_aslr_disabled",
                    "description": "ASLR not enabled (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)",
                    "risk": "low",
                    "details": {"dll_characteristics": hex(dll_chars)},
                }
            )
        if not (dll_chars & 0x0100):
            findings.append(
                {
                    "rule": "pe_dep_disabled",
                    "description": "DEP/NX not enabled (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)",
                    "risk": "low",
                    "details": {"dll_characteristics": hex(dll_chars)},
                }
            )
    except Exception:
        pass

    anti_analysis: list[str] = []
    suspicious: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp and imp.name:
                    fn = imp.name.decode("utf-8", errors="replace")
                    if fn in _ANTI_ANALYSIS_IMPORTS:
                        anti_analysis.append(fn)
                    elif fn in _SUSPICIOUS_IMPORTS:
                        suspicious.append(fn)
    if anti_analysis:
        metadata["anti_analysis_imports"] = anti_analysis
        findings.append(
            {
                "rule": "pe_anti_analysis_imports",
                "description": f"Anti-analysis API imports: {', '.join(anti_analysis[:10])}",
                "risk": "high" if len(anti_analysis) >= 2 else "medium",
                "details": {"imports": anti_analysis},
            }
        )
    if suspicious:
        metadata["suspicious_imports"] = suspicious
        risk = "high" if len(suspicious) >= 5 else "medium"
        findings.append(
            {
                "rule": "pe_suspicious_imports",
                "description": f"Suspicious API imports: {', '.join(suspicious[:10])}",
                "risk": risk,
                "details": {"imports": suspicious},
            }
        )
    pe.close()

    overall = "safe"
    for f in findings:
        overall = _max_risk(overall, str(f.get("risk", "safe")))
    return _build("pefile", success=True, risk=overall, findings=findings, metadata=metadata)


def _scan_office(path: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    try:
        from oletools import oleid
        from oletools.olevba import VBA_Parser
    except ImportError:
        return _build("oletools", success=False, error="oletools not installed")

    try:
        oid = oleid.OleID(str(path))
        for ind in oid.check():
            metadata[ind.name] = {"value": str(ind.value), "risk": str(ind.risk)}
            rsk = (str(ind.risk) if ind.risk is not None else "").lower()
            if rsk in ("high", "medium"):
                findings.append(
                    {
                        "rule": f"oleid_{ind.name}",
                        "description": f"{ind.name}: {ind.value}",
                        "risk": "high" if rsk == "high" else "medium",
                        "details": {"indicator": ind.name, "value": str(ind.value)},
                    }
                )
    except Exception as e:
        metadata["oleid_error"] = str(e)

    try:
        vba = VBA_Parser(str(path))
        if vba.detect_vba_macros():
            metadata["has_vba_macros"] = True
            for kw_type, keyword, description in vba.analyze_macros():
                risk = "low"
                if kw_type in ("AutoExec", "Suspicious"):
                    risk = "high"
                elif kw_type == "IOC":
                    risk = "medium"
                findings.append(
                    {
                        "rule": f"olevba_{kw_type}_{keyword}",
                        "description": str(description),
                        "risk": risk,
                        "details": {"type": kw_type, "keyword": keyword},
                    }
                )
        else:
            metadata["has_vba_macros"] = False
        vba.close()
    except Exception as e:
        metadata["olevba_error"] = str(e)

    overall = "safe"
    for f in findings:
        overall = _max_risk(overall, str(f.get("risk", "safe")))
    return _build("oletools", success=True, risk=overall, findings=findings, metadata=metadata)


def _iter_pdfid_keywords(path: Path) -> list[dict[str, Any]]:
    from pdfid import pdfid

    xmldoc = pdfid.PDFiD(str(path))
    raw = pdfid.PDFiD2JSON(xmldoc, force=True)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    data = json.loads(raw) if raw else []
    out: list[dict[str, Any]] = []
    if not isinstance(data, list):
        return out
    for top in data:
        if not isinstance(top, dict):
            continue
        pdfi = top.get("pdfid")
        if not isinstance(pdfi, dict):
            continue
        kwrap = pdfi.get("keywords")
        if not isinstance(kwrap, dict):
            continue
        klist = kwrap.get("keyword")
        if klist is None:
            continue
        if isinstance(klist, dict):
            klist = [klist]
        for kw in klist or []:
            if isinstance(kw, dict):
                out.append({"name": str(kw.get("name", "")), "count": int(kw.get("count", 0))})
    return out


def _scan_pdf(path: Path) -> dict[str, Any]:
    try:
        from pdfid import pdfid  # noqa: F401
    except ImportError:
        return _build("pdfid", success=False, error="pdfid not installed")

    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    try:
        for row in _iter_pdfid_keywords(path):
            kw = str(row.get("name", ""))
            count = int(row.get("count", 0))
            if count <= 0:
                continue
            metadata[kw] = count
            if kw in _PDF_HIGH:
                findings.append(
                    {
                        "rule": f"pdfid{kw.replace('/', '_')}",
                        "description": f"PDF contains {kw} (count: {count})",
                        "risk": "high",
                        "details": {"keyword": kw, "count": count},
                    }
                )
            elif kw in _PDF_MEDIUM:
                findings.append(
                    {
                        "rule": f"pdfid{kw.replace('/', '_')}",
                        "description": f"PDF contains {kw} (count: {count})",
                        "risk": "medium",
                        "details": {"keyword": kw, "count": count},
                    }
                )
    except Exception as e:
        return _build("pdfid", success=False, error=str(e))

    overall = "safe"
    for f in findings:
        overall = _max_risk(overall, str(f.get("risk", "safe")))
    return _build("pdfid", success=True, risk=overall, findings=findings, metadata=metadata)


def run_format_scanners(path: Path, file_type: Optional[str] = None) -> list[dict[str, Any]]:
    """Return zero or more scanner_results entries for format-specific analysis."""
    suffix = path.suffix.lower()
    ft = (file_type or "").lower()
    results: list[dict[str, Any]] = []

    is_pe = suffix in _PE_SUFFIX or "executable" in ft or "msdownload" in ft or "dosexec" in ft
    is_office = suffix in _OFFICE_SUFFIX or "msword" in ft or "ms-excel" in ft or "powerpoint" in ft
    is_pdf = suffix in _PDF_SUFFIX or "pdf" in ft

    if is_pe:
        results.append(_scan_pe(path))
    if is_office:
        results.append(_scan_office(path))
    if is_pdf:
        results.append(_scan_pdf(path))
    return results
