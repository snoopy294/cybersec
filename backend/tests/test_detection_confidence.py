"""Detection rule confidence is computed from the evidence behind each rule."""

import math
from types import SimpleNamespace

import pytest

from app.schemas.schemas import DetectionPackResponse
from app.services.detection_service import compute_rule_confidence, generate_detection_pack

URL = "http://c2.example/gate.php"


def _report(iocs=None, capabilities=None, severity=50):
    return SimpleNamespace(
        id="report-1",
        file_hash_sha256="a" * 64,
        severity_score=severity,
        iocs=iocs or {},
        static_data={
            "behavior_profile": {
                "capabilities": capabilities or [],
                "capability_names": [c["name"] for c in capabilities or []],
            }
        },
    )


def _rule(pack, fmt):
    return next(rule for rule in pack["rules"] if rule["format"] == fmt)


def test_rule_without_evidence_gets_the_floor():
    confidence, basis = compute_rule_confidence([], [])

    assert confidence == 0.2
    assert basis == {
        "evidence_items": 0,
        "evidence_kinds": {},
        "evidence_strength": 0,
        "supporting_capabilities": [],
    }


def test_formula_matches_the_documented_example():
    # One full URL: weight 1.0, specificity 1.0 (26 chars >= 20), no corroboration.
    confidence, basis = compute_rule_confidence([(URL, "url")], [])

    assert basis["evidence_strength"] == 1.0
    assert confidence == round(0.2 + 0.55 * (1 - math.exp(-1.0 / 2.5)), 2) == 0.38


def test_more_evidence_raises_confidence_with_diminishing_returns():
    urls = [(f"http://c2-{i}.example/gate.php", "url") for i in range(12)]
    one, _ = compute_rule_confidence(urls[:1], [])
    three, _ = compute_rule_confidence(urls[:3], [])
    twelve, _ = compute_rule_confidence(urls, [])

    assert one < three < twelve
    assert (three - one) > (twelve - three) / 9 * 2  # early items are worth more


def test_stronger_evidence_kinds_score_higher_than_weak_ones():
    url, _ = compute_rule_confidence([(URL, "url")], [])
    command, _ = compute_rule_confidence([("cmd.exe /c vssadmin delete shadows", "command")], [])
    privilege, _ = compute_rule_confidence([("SeDebugPrivilege_x", "windows_privilege")], [])

    assert url > privilege
    assert command > privilege


def test_short_generic_strings_count_for_less_than_specific_ones():
    short, _ = compute_rule_confidence([("send", "capability_string")], [])
    specific, _ = compute_rule_confidence([("urldownloadtofilew_payload", "capability_string")], [])

    assert short < specific


def test_capabilities_that_share_the_evidence_corroborate_it():
    evidence = [(URL, "url")]
    network = {"name": "network_communications", "confidence": 0.83, "evidence": ["c2.example"]}
    unrelated = {"name": "persistence", "confidence": 0.9, "evidence": ["schtasks"]}

    alone, _ = compute_rule_confidence(evidence, [unrelated])
    corroborated, basis = compute_rule_confidence(evidence, [network, unrelated])

    assert corroborated > alone
    assert basis["supporting_capabilities"] == ["network_communications"]


def test_confidence_is_capped_below_certainty():
    evidence = [(f"http://c2-{i}.example/gate.php", "url") for i in range(50)]
    capabilities = [
        {"name": f"cap{i}", "confidence": 0.95, "evidence": [f"c2-{i}.example"]} for i in range(5)
    ]

    confidence, _ = compute_rule_confidence(evidence, capabilities)

    assert confidence == 0.95


def test_pack_rules_are_scored_from_their_own_evidence():
    report = _report(
        iocs={
            "urls": [URL, "http://update.bad.example/payload.bin"],
            "commands": ["powershell -enc SQBFAFgA", "cmd.exe /c whoami /all"],
            "registry_keys": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\updater"],
        },
        capabilities=[
            {"name": "network_communications", "confidence": 0.83, "evidence": ["c2.example", "internetopen"]},
            {"name": "persistence", "confidence": 0.59, "evidence": ["\\currentversion\\run"]},
        ],
    )

    pack = generate_detection_pack(report, ["yara", "sigma", "suricata", "splunk"], "balanced")

    yara, sigma = _rule(pack, "yara"), _rule(pack, "sigma")
    suricata = [rule for rule in pack["rules"] if rule["format"] == "suricata"]
    # YARA matches on every IOC plus the capability strings, so it outscores a
    # Suricata rule that rests on a single host name.
    assert yara["confidence_basis"]["evidence_items"] == 8
    assert yara["confidence_basis"]["evidence_kinds"] == {
        "url": 2, "command": 2, "registry_key": 1, "capability_string": 3,
    }
    assert all(rule["confidence"] < yara["confidence"] for rule in suricata)
    assert sigma["confidence_basis"]["evidence_kinds"] == {"command": 2}
    c2_rule = next(rule for rule in suricata if rule["evidence"] == ["c2.example"])
    assert c2_rule["confidence_basis"]["supporting_capabilities"] == ["network_communications"]
    other_host = next(rule for rule in suricata if rule["evidence"] == ["update.bad.example"])
    assert other_host["confidence_basis"]["supporting_capabilities"] == []
    # The API response schema keeps the basis.
    response = DetectionPackResponse(**pack)
    assert response.rules[0].confidence_basis == pack["rules"][0]["confidence_basis"]


def test_empty_report_rules_fall_to_the_floor():
    pack = generate_detection_pack(_report(), ["yara", "splunk"], "strict")

    assert _rule(pack, "yara")["confidence"] == 0.2
    assert _rule(pack, "splunk")["confidence"] == 0.2


@pytest.mark.parametrize("strictness", ["strict", "broad"])
def test_broad_packs_with_more_evidence_score_at_least_as_high(strictness):
    iocs = {"urls": [f"http://c2-{i}.example/gate.php" for i in range(20)]}

    strict = _rule(generate_detection_pack(_report(iocs=iocs), ["yara"], "strict"), "yara")
    chosen = _rule(generate_detection_pack(_report(iocs=iocs), ["yara"], strictness), "yara")

    assert chosen["confidence"] >= strict["confidence"]
