"""Archive intake: safe extraction with password trial (e.g. infected)."""

from __future__ import annotations

import logging
import shutil
import tempfile
import uuid
import zipfile
from collections import deque
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

_NESTED_SKIP_OOXML_SUFFIX: frozenset[str] = frozenset(
    s.lower()
    for s in (
        ".docx",
        ".xlsx",
        ".pptx",
        ".xlsm",
        ".docm",
        ".xlsb",
        ".xlam",
        ".dotx",
        ".dotm",
        ".potx",
        ".ppsx",
        ".ppsm",
        ".pptm",
        ".sldm",
        ".odt",
        ".ods",
        ".odp",
        ".odf",
        ".odg",
        ".odc",
        ".epub",
    )
)


def get_intake_config(cfg: dict[str, Any]) -> dict[str, Any]:
    raw = cfg.get("intake") or {}
    if not isinstance(raw, dict):
        raw = {}
    passwords = raw.get("passwords")
    if not isinstance(passwords, list) or not passwords:
        passwords = ["", "infected", "malware", "virus"]
    return {
        "enabled": bool(raw.get("enabled", True)),
        "passwords": [str(p) for p in passwords],
        "max_extract_mb": int(raw.get("max_extract_mb", 500)),
        "max_files": int(raw.get("max_files", 200)),
        "max_nested_depth": int(raw.get("max_nested_depth", 8)),
    }


def _is_archive(filepath: Path) -> Optional[str]:
    try:
        if zipfile.is_zipfile(str(filepath)):
            return "zip"
    except OSError:
        pass
    try:
        with filepath.open("rb") as fh:
            if fh.read(6) == b"7z\xbc\xaf\x27\x1c":
                return "7z"
    except OSError:
        pass
    return None


def _zip_looks_like_document_or_epub_container(filepath: Path) -> bool:
    try:
        with zipfile.ZipFile(str(filepath), "r") as zf:
            names = [n.replace("\\", "/") for n in zf.namelist() if n and not n.endswith("/")]
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return False
    if not names:
        return False
    joined = "\n".join(names).lower()
    if (
        "word/document.xml" in joined
        or "ppt/slides/" in joined
        or "xl/worksheets/sheet" in joined
        or "xl/worksheets/" in joined
    ):
        return True
    for n in names:
        seg = n.replace("\\", "/")
        if seg in ("mimetype",) or seg.rsplit("/", 1)[-1] == "mimetype":
            try:
                with zf.open(n) as mf:
                    h = mf.read(200).lower()
            except (OSError, KeyError, RuntimeError):
                continue
            if b"epub" in h or b"odf" in h or b"opendocument" in h or b"application/vnd.oasis" in h:
                return True
    for n in names:
        if n.replace("\\", "/").lower().startswith("oebps/"):
            return True
    return False


def _nested_expand_archive_type(filepath: Path) -> Optional[str]:
    t = _is_archive(filepath)
    if t is None:
        return None
    if t == "zip":
        if filepath.suffix.lower() in _NESTED_SKIP_OOXML_SUFFIX:
            return None
        if _zip_looks_like_document_or_epub_container(filepath):
            return None
    return t


def _safe_extract_name(name: str) -> str:
    return Path(name).name


def _extract_zip_pyzipper(
    filepath: Path,
    password: str,
    extract_dir: Path,
    acc_size: list[int],
    max_bytes: int,
) -> list[Path]:
    try:
        import pyzipper
    except ImportError as e:
        raise ValueError("AES ZIP requires pyzipper") from e

    extracted: list[Path] = []
    pwd = password.encode("utf-8") if password else None
    with pyzipper.AESZipFile(str(filepath), "r") as zf:
        if pwd:
            zf.pwd = pwd
        for info in zf.infolist():
            if info.is_dir():
                continue
            safe_name = _safe_extract_name(info.filename)
            if not safe_name or safe_name.startswith("."):
                continue
            if info.file_size == 0:
                continue
            if acc_size[0] + int(info.file_size) > max_bytes:
                raise ValueError(f"Archive exceeds max extract size ({max_bytes} bytes)")
            data = zf.read(info.filename)
            acc_size[0] += len(data)
            out_path = extract_dir / safe_name
            counter = 1
            while out_path.exists():
                out_path = extract_dir / f"{Path(safe_name).stem}_{counter}{Path(safe_name).suffix}"
                counter += 1
            out_path.write_bytes(data)
            extracted.append(out_path)
    return extracted


def _extract_zip(
    filepath: Path,
    password: str,
    extract_dir: Path,
    acc_size: list[int],
    max_bytes: int,
) -> list[Path]:
    extracted: list[Path] = []
    try:
        with zipfile.ZipFile(str(filepath), "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                safe_name = _safe_extract_name(info.filename)
                if not safe_name or safe_name.startswith("."):
                    continue
                if info.file_size == 0:
                    continue
                if acc_size[0] + int(info.file_size) > max_bytes:
                    raise ValueError(f"Archive exceeds max extract size ({max_bytes} bytes)")
                pwd_bytes = password.encode("utf-8") if password else None
                try:
                    data = zf.read(info.filename, pwd=pwd_bytes)
                except RuntimeError as e:
                    raise ValueError(str(e)) from e
                acc_size[0] += len(data)
                out_path = extract_dir / safe_name
                counter = 1
                while out_path.exists():
                    stem = Path(safe_name).stem
                    suffix = Path(safe_name).suffix
                    out_path = extract_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
                out_path.write_bytes(data)
                extracted.append(out_path)
        if extracted:
            return extracted
    except (RuntimeError, zipfile.BadZipFile):
        if password:
            return _extract_zip_pyzipper(filepath, password, extract_dir, acc_size, max_bytes)
        return []
    if not extracted and password:
        try:
            return _extract_zip_pyzipper(filepath, password, extract_dir, acc_size, max_bytes)
        except ValueError:
            return []
    return extracted


def _extract_7z(
    filepath: Path,
    password: str,
    extract_dir: Path,
    acc_size: list[int],
    max_bytes: int,
) -> list[Path]:
    try:
        import py7zr
    except ImportError as e:
        raise ValueError("7z support requires py7zr") from e

    extracted: list[Path] = []
    tmp_extract = extract_dir / f"_7z_tmp_{uuid.uuid4().hex[:8]}"
    with py7zr.SevenZipFile(str(filepath), mode="r", password=password or None) as sz:
        to_add = 0
        for entry in sz.list():
            if entry.is_directory:
                continue
            to_add += int(entry.uncompressed or 0)
        if acc_size[0] + to_add > max_bytes:
            raise ValueError(f"Archive exceeds max extract size ({max_bytes} bytes)")
        acc_size[0] += to_add
        tmp_extract.mkdir(exist_ok=True, parents=True)
        sz.extractall(path=str(tmp_extract))
    try:
        for f in tmp_extract.rglob("*"):
            if f.is_dir():
                continue
            safe_name = _safe_extract_name(f.name)
            if not safe_name or safe_name.startswith("."):
                continue
            if f.stat().st_size == 0:
                continue
            out_path = extract_dir / safe_name
            counter = 1
            while out_path.exists():
                stem = Path(safe_name).stem
                suffix = Path(safe_name).suffix
                out_path = extract_dir / f"{stem}_{counter}{suffix}"
                counter += 1
            shutil.move(str(f), str(out_path))
            extracted.append(out_path)
    finally:
        shutil.rmtree(str(tmp_extract), ignore_errors=True)
    return extracted


def _extract_archive(
    filepath: Path,
    password: str,
    extract_dir: Path,
    archive_type: str,
    acc_size: list[int],
    max_bytes: int,
) -> list[Path]:
    if archive_type == "zip":
        return _extract_zip(filepath, password, extract_dir, acc_size, max_bytes)
    if archive_type == "7z":
        return _extract_7z(filepath, password, extract_dir, acc_size, max_bytes)
    return []


def _expand_nested_archives_to_leaves(
    first_paths: list[Path],
    password: str,
    work_root: Path,
    acc_size: list[int],
    max_bytes: int,
    max_depth: int,
    max_files: int,
) -> list[Path]:
    leaves: list[Path] = []
    queue: deque[tuple[Path, int]] = deque((p, 0) for p in first_paths)
    seen_archives = 0

    while queue:
        if len(leaves) >= max_files:
            log.warning("intake: max_files %d reached", max_files)
            break
        path, depth = queue.popleft()
        if not path.is_file():
            continue
        arch = _nested_expand_archive_type(path) if depth < max_depth else None
        if arch:
            seen_archives += 1
            nest = work_root / f"nest_{uuid.uuid4().hex[:8]}"
            nest.mkdir(parents=True, exist_ok=True)
            try:
                inner = _extract_archive(path, password, nest, arch, acc_size, max_bytes)
                for p in inner:
                    queue.append((p, depth + 1))
            except ValueError:
                leaves.append(path)
            continue
        leaves.append(path)
    return leaves


def _try_extract_with_passwords(
    filepath: Path,
    archive_type: str,
    extract_dir: Path,
    passwords: list[str],
    max_bytes: int,
) -> tuple[Optional[str], list[Path], Optional[str]]:
    last_err: Optional[str] = None
    for pw in passwords:
        acc: list[int] = [0]
        try:
            if archive_type == "zip" and pw:
                first = _extract_zip_pyzipper(filepath, pw, extract_dir, acc, max_bytes)
                if first:
                    return pw, first, None
            first = _extract_archive(filepath, pw, extract_dir, archive_type, acc, max_bytes)
            if first:
                return pw, first, None
            last_err = "empty archive"
        except ValueError as e:
            last_err = str(e)
            if "password" in str(e).lower() or "bad password" in str(e).lower():
                continue
        except zipfile.BadZipFile as e:
            last_err = str(e)
            break
        except RuntimeError as e:
            last_err = str(e)
            if "password" in str(e).lower():
                continue
    return None, [], last_err


def process_intake(
    sample_path: Path,
    cfg: dict[str, Any],
    *,
    archive_password: Optional[str] = None,
    staging_root: Optional[Path] = None,
) -> dict[str, Any]:
    """
    If sample is an archive, extract to staging and return leaf paths.
    Otherwise return a single-path intake result.
    """
    icfg = get_intake_config(cfg)
    path = sample_path.resolve()
    result: dict[str, Any] = {
        "status": "skipped",
        "reason": "intake disabled",
        "archive": False,
        "leaf_paths": [str(path)],
        "password_used": None,
        "archive_type": None,
        "extracted_count": 1,
        "error": None,
    }
    if not icfg["enabled"]:
        return result

    archive_type = _is_archive(path)
    if archive_type is None:
        result["status"] = "completed"
        result["reason"] = "not an archive"
        result["archive"] = False
        result["leaf_paths"] = [str(path)]
        return result

    max_bytes = icfg["max_extract_mb"] * 1024 * 1024
    passwords = list(icfg["passwords"])
    if archive_password is not None and archive_password not in passwords:
        passwords.insert(0, archive_password)
    elif archive_password is not None:
        passwords = [archive_password] + [p for p in passwords if p != archive_password]

    staging_root = staging_root or Path(
        tempfile.mkdtemp(prefix="mau_intake_", dir=str(path.parent))
    )
    extract_dir = staging_root / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)

    pw_used, first_layer, err = _try_extract_with_passwords(
        path, archive_type, extract_dir, passwords, max_bytes
    )
    if not first_layer:
        return {
            "status": "failed",
            "reason": "extraction failed",
            "archive": True,
            "archive_type": archive_type,
            "leaf_paths": [],
            "password_used": pw_used,
            "extracted_count": 0,
            "error": err or "could not extract archive",
            "staging_dir": str(staging_root),
        }

    acc = [sum(f.stat().st_size for f in first_layer if f.is_file())]
    try:
        leaves = _expand_nested_archives_to_leaves(
            first_layer,
            pw_used or "",
            extract_dir,
            acc,
            max_bytes,
            icfg["max_nested_depth"],
            icfg["max_files"],
        )
    except ValueError as e:
        return {
            "status": "failed",
            "reason": "nested extraction failed",
            "archive": True,
            "archive_type": archive_type,
            "leaf_paths": [],
            "password_used": pw_used,
            "extracted_count": 0,
            "error": str(e),
            "staging_dir": str(staging_root),
        }

    if not leaves:
        return {
            "status": "failed",
            "reason": "no files after extraction",
            "archive": True,
            "archive_type": archive_type,
            "leaf_paths": [],
            "password_used": pw_used,
            "extracted_count": 0,
            "error": "empty after nested expansion",
            "staging_dir": str(staging_root),
        }

    return {
        "status": "completed",
        "reason": None,
        "archive": True,
        "archive_type": archive_type,
        "leaf_paths": [str(p.resolve()) for p in leaves],
        "password_used": pw_used,
        "extracted_count": len(leaves),
        "error": None,
        "staging_dir": str(staging_root),
    }
