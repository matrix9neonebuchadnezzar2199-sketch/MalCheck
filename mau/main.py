"""CLI entry: python -m mau.main <sample_filename>"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from mau.phase_router import run_pipeline_with_intake

log = logging.getLogger(__name__)


def _setup_logging() -> None:
    level = os.environ.get("MAU_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main(argv: Optional[List[str]] = None) -> int:
    _setup_logging()
    parser = argparse.ArgumentParser(description="Malware Unified Analyzer orchestrator")
    parser.add_argument(
        "sample",
        help="Filename under SAMPLES_DIR (or absolute path to sample file)",
    )
    parser.add_argument(
        "timeout",
        nargs="?",
        type=int,
        default=None,
        help="Optional timeout override (reserved for future use)",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=os.environ.get("MAU_CONFIG", ""),
        help="Path to analyzer.yaml",
    )
    parser.add_argument(
        "--archive-password",
        default=os.environ.get("MAU_ARCHIVE_PASSWORD", "infected"),
        help="Password for encrypted archives (default: infected)",
    )
    args = parser.parse_args(argv)

    samples_dir = Path(os.environ.get("SAMPLES_DIR", "/samples"))
    sample_arg = Path(args.sample)
    if sample_arg.is_file():
        sample_path = sample_arg.resolve()
    else:
        sample_path = (samples_dir / args.sample).resolve()

    if not sample_path.is_file():
        log.error("Sample not found: %s", sample_path)
        return 2

    cfg_path = args.config.strip() or None
    try:
        out = run_pipeline_with_intake(
            str(sample_path),
            config_path=cfg_path,
            sample_name=sample_path.name,
            archive_password=args.archive_password.strip() or None,
        )
    except Exception as e:
        log.exception("Pipeline failed: %s", e)
        return 1

    print(json.dumps(out["report"], indent=2, default=str, ensure_ascii=False))
    paths = out["report"].get("_paths") or {}
    log.info("Report JSON: %s", paths.get("json"))
    log.info("Report HTML: %s", paths.get("html"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
