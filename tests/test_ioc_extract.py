from mau.ioc_extract import extract_iocs_from_strings, merge_surface_iocs


def test_extract_domains_and_registry():
    strings = [
        "HKEY_LOCAL_MACHINE\\Software\\Malware",
        "Global\\MyMutex123",
        "contact@evil.example",
        "https://evil.example/payload",
    ]
    iocs = extract_iocs_from_strings(strings)
    assert "evil.example" in iocs["domains"]
    assert any("HKEY" in k for k in iocs["registry_keys"])
    assert "Global\\MyMutex123" in iocs["mutexes"]
    assert "contact@evil.example" in iocs["emails"]


def test_merge_surface_iocs():
    surface = {"strings_sample": ["https://a.test/x"], "urls": [], "ips": []}
    merge_surface_iocs(surface)
    assert "a.test" in surface.get("domains", [])
