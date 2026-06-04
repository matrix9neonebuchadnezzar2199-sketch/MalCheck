from mau.report_export import export_csv, export_misp_event, export_stix_bundle, write_exports


def test_export_formats():
    report = {
        "meta": {"sample_name": "t.exe", "timestamp": "2026-06-04T00:00:00+00:00"},
        "verdict": {"label": "suspicious", "score": 25},
        "iocs": {
            "hashes": {"sha256": "abc"},
            "urls": ["http://x"],
            "ips": ["1.2.3.4"],
            "domains": ["x.test"],
            "emails": [],
            "registry_keys": [],
            "mutexes": [],
        },
        "malicious_findings": [{"summary": "yara", "child": "t.exe", "severity": "high"}],
    }
    csv_text = export_csv(report)
    assert "sha256" in csv_text
    assert "abc" in csv_text
    misp = export_misp_event(report)
    assert misp["Event"]["Attribute"]
    stix = export_stix_bundle(report)
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) >= 2


def test_write_exports(tmp_path):
    report = {
        "meta": {"sample_name": "s.bin"},
        "verdict": {"label": "low"},
        "iocs": {"hashes": {}, "urls": [], "ips": [], "domains": [], "emails": [], "registry_keys": [], "mutexes": []},
    }
    paths = write_exports(report, tmp_path, "s.bin")
    assert (tmp_path / "s.bin.csv").is_file()
    assert (tmp_path / "s.bin.misp.json").is_file()
    assert (tmp_path / "s.bin.stix.json").is_file()
    assert paths["csv"].endswith(".csv")
