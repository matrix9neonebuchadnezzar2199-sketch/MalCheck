from mau.surface_schema import count_findings, normalize_scanner_results, overall_risk


def test_normalize_scanner_results_filters_invalid_rows():
    rows = normalize_scanner_results(
        [
            {"scanner_name": "yara", "risk": "high", "findings": [{"rule": "r1"}]},
            {"scanner_name": "", "risk": "low"},
            "invalid",
            {"scanner_name": "capa", "risk": "weird", "findings": "bad"},
        ]
    )
    assert len(rows) == 2
    assert rows[0]["scanner_name"] == "yara"
    assert rows[1]["risk"] == "safe"
    assert rows[1]["findings"] == []


def test_count_findings_and_overall_risk():
    rows = normalize_scanner_results(
        [
            {"scanner_name": "yara", "risk": "high", "findings": [{"rule": "a"}, {"rule": "b"}]},
            {"scanner_name": "capa", "risk": "medium", "findings": [{"rule": "c"}]},
        ]
    )
    assert count_findings(rows, "yara") == 2
    assert count_findings(rows, "capa") == 1
    assert overall_risk(rows) == "high"
