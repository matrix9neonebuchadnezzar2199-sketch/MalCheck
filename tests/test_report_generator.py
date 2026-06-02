from mau.report_generator import aggregate_iocs, calculate_verdict, generate_report


def test_aggregate_iocs():
    s = {"hashes": {"sha256": "abc"}, "urls": ["http://x"], "ips": ["1.2.3.4"]}
    i = aggregate_iocs(s, {}, {})
    assert i["hashes"]["sha256"] == "abc"
    assert "http://x" in i["urls"]


def test_verdict():
    v = calculate_verdict({"yara_matches": [{"r": 1}]}, {}, {})
    assert v["score"] > 0


def test_verdict_with_scanner_results():
    v = calculate_verdict(
        {
            "scanner_results": [
                {"scanner_name": "yara", "findings": [{"rule": "x"}]},
                {"scanner_name": "capa", "findings": [{"rule": "y"}]},
            ]
        },
        {},
        {},
    )
    assert v["score"] > 0
    assert any("yara matches" in reason for reason in v["reasons"])


def test_generate_report_json(tmp_path):
    surface = {"hashes": {"md5": "x"}}
    dynamic = {"status": "skipped"}
    static = {"status": "skipped"}
    r = generate_report(
        surface,
        dynamic,
        static,
        sample_name="t.exe",
        out_dir=tmp_path,
        html=True,
        executive_summary_llm=False,
    )
    assert "_paths" in r
    assert (tmp_path / "t.exe.json").is_file()
    assert (tmp_path / "t.exe.html").is_file()
