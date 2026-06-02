import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYZE = ROOT / "scripts" / "remnux" / "analyze.py"


def test_analyze_emits_json(tmp_path):
    if not ANALYZE.is_file():
        return
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    proc = subprocess.run(
        [sys.executable, str(ANALYZE), str(p)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "hashes" in data
    assert "md5" in data["hashes"]
    assert "scanner_results" in data
    assert isinstance(data["scanner_results"], list)
    assert any(x.get("scanner_name") == "yara" for x in data["scanner_results"])
    assert "overall_risk" in data
