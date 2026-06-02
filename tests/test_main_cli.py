import subprocess
import sys


def test_main_missing_sample_exit_code():
    r = subprocess.run(
        [sys.executable, "-m", "mau.main", "___does_not_exist__.exe"],
        capture_output=True,
        text=True,
        cwd=__import__("pathlib").Path(__file__).resolve().parents[1],
    )
    assert r.returncode == 2
