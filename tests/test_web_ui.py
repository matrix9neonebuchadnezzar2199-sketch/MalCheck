import json
from pathlib import Path

from fastapi.testclient import TestClient

from web_ui import app as web_app


def test_health():
    client = TestClient(web_app.app)
    assert client.get("/health").json() == {"status": "ok"}


def test_api_reports_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    (tmp_path / "reports").mkdir(parents=True)
    client = TestClient(web_app.app)
    assert client.get("/api/reports").json() == {"reports": []}


def test_serve_report_files(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    base = "sample_exe"
    (reports / f"{base}.html").write_text("<html>ok</html>", encoding="utf-8")
    (reports / f"{base}.json").write_text("{}", encoding="utf-8")
    (reports / f"{base}.csv").write_text("type,value\n", encoding="utf-8")
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    client = TestClient(web_app.app)
    r = client.get(f"/reports/{base}.html")
    assert r.status_code == 200
    assert "ok" in r.text
    assert client.get(f"/export/{base}/csv").status_code == 200
    assert client.get("/reports/not%20valid!.html").status_code == 400


def test_list_reports_from_json(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    payload = {
        "meta": {"sample_name": "a.exe", "timestamp": "2026-01-01T00:00:00Z"},
        "verdict": {"label": "low", "score": 5},
    }
    (reports / "a.exe.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    client = TestClient(web_app.app)
    rows = client.get("/api/reports").json()["reports"]
    assert len(rows) == 1
    assert rows[0]["sample_name"] == "a.exe"
    assert rows[0]["view_url"] == "/reports/a.exe.html"
