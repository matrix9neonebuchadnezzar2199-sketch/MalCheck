from pathlib import Path

from mau.config import load_config


def test_default_merge(tmp_path):
    f = tmp_path / "analyzer.yaml"
    f.write_text("phases:\n  surface:\n    enabled: false\n", encoding="utf-8")
    c = load_config(path=str(f))
    assert c["phases"]["surface"]["enabled"] is False
    assert c["phases"]["static"]["enabled"] is True


def test_load_repo_config():
    p = Path(__file__).resolve().parents[1] / "compose" / "config" / "analyzer.yaml"
    assert p.is_file()
    c = load_config(path=str(p))
    assert "phases" in c
