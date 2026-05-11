from app.worker import (
    _classify_string,
    _compute_entropy,
    _extract_strings,
    _pe_summary_for_report,
    _summarize_import_risks,
)


def test_classify_string_detects_core_ioc_types():
    assert _classify_string("https://bad.example/payload.bin") == "URL"
    assert _classify_string("192.168.1.10") == "IP_ADDRESS"
    assert _classify_string("operator@example.org") == "EMAIL"
    assert _classify_string(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run") == "REGISTRY_KEY"
    assert _classify_string(r"C:\Users\Public\dropper.exe") == "FILE_PATH"
    assert _classify_string("c2.bad-example.net") == "DOMAIN"
    assert _classify_string("999.1.1.1") == "UNKNOWN"


def test_extract_strings_reads_ascii_and_utf16le():
    utf16_ioc = "http://unicode-c2.example/checkin".encode("utf-16le")
    data = b"\x00\x01http://ascii-c2.example/drop\x00" + b"\x00" * 8 + utf16_ioc

    strings = _extract_strings(data)
    values = {item["value"]: item for item in strings}

    assert values["http://ascii-c2.example/drop"]["encoding"] == "ascii"
    assert values["http://unicode-c2.example/checkin"]["encoding"] == "utf-16le"
    assert values["http://unicode-c2.example/checkin"]["classification"] == "URL"


def test_entropy_identifies_low_and_high_entropy_inputs():
    assert _compute_entropy(b"\x00" * 1024) == 0.0
    assert _compute_entropy(bytes(range(256)) * 4) == 8.0


def test_summarize_import_risks_flags_suspicious_apis_once():
    pe_info = {
        "imports": [
            {"dll": "KERNEL32.dll", "functions": ["VirtualAllocEx", "WriteProcessMemory"]},
            {"dll": "WININET.dll", "functions": ["InternetOpen", "InternetConnect"]},
        ]
    }

    findings = _summarize_import_risks(pe_info)

    assert "Remote process memory allocation" in findings
    assert "Process memory modification" in findings
    assert "WinINet network capability" in findings
    assert findings.count("WinINet network capability") == 1


def test_pe_summary_excludes_nested_report_tables():
    pe_info = {
        "is_pe": True,
        "machine": "x64",
        "sections": [{"name": ".text"}],
        "imports": [{"dll": "KERNEL32.dll", "functions": ["ExitProcess"]}],
        "exports": [{"name": "Exported"}],
    }

    summary = _pe_summary_for_report(pe_info)

    assert summary == {"is_pe": True, "machine": "x64"}
