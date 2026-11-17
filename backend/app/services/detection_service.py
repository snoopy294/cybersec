"""Detection pack generation from SENTINEL report evidence."""

from __future__ import annotations

import hashlib
import math

from app.models.models import ThreatReport

DETECTION_TARGETS = {"yara", "sigma", "suricata", "splunk"}
DETECTION_STRICTNESS_LEVELS = {"strict", "balanced", "broad"}

# How much one piece of evidence of each kind says about this specific sample.
# A full URL or command line is close to unique; a privilege name or an API
# string pulled out by a capability rule is shared by plenty of clean software.
EVIDENCE_KIND_WEIGHTS = {
    "url": 1.0,
    "command": 0.9,
    "registry_key": 0.8,
    "domain": 0.8,
    "file_path": 0.6,
    "capability_string": 0.5,
    "windows_privilege": 0.4,
}
IOC_KINDS = {
    "urls": "url",
    "registry_keys": "registry_key",
    "file_paths": "file_path",
    "commands": "command",
    "windows_privileges": "windows_privilege",
}

CONFIDENCE_FLOOR = 0.2
EVIDENCE_SPAN = 0.55
CORROBORATION_SPAN = 0.2
EVIDENCE_SATURATION = 2.5
CORROBORATION_SATURATION = 1.5
SPECIFIC_TOKEN_LENGTH = 20
MIN_SPECIFICITY = 0.3


def _evidence_strength(value: str, kind: str) -> float:
    """Strength of one evidence item: kind weight times token specificity.

    Specificity grows with length up to SPECIFIC_TOKEN_LENGTH characters, so
    "send" counts for far less than "http://c2.example/gate.php".
    """
    specificity = max(MIN_SPECIFICITY, min(1.0, len(value) / SPECIFIC_TOKEN_LENGTH))
    return EVIDENCE_KIND_WEIGHTS.get(kind, 0.5) * specificity


def _supporting_capabilities(evidence: list[tuple[str, str]], capabilities: list[dict]) -> list[dict]:
    """Capabilities whose own evidence overlaps the rule's evidence."""
    rule_tokens = [value.lower() for value, _ in evidence]
    supporting = []
    for capability in capabilities:
        cap_tokens = [str(item).lower() for item in capability.get("evidence") or [] if item]
        if any(
            rule == cap or (len(cap) >= 4 and cap in rule) or (len(rule) >= 4 and rule in cap)
            for rule in rule_tokens
            for cap in cap_tokens
        ):
            supporting.append(capability)
    return supporting


def compute_rule_confidence(evidence: list[tuple[str, str]], capabilities: list[dict]) -> tuple[float, dict]:
    """Confidence for one detection rule, computed from the evidence behind it.

    ``evidence`` is the list of ``(value, kind)`` pairs the rule matches on,
    where kind is one of EVIDENCE_KIND_WEIGHTS (url, command, registry_key,
    domain, file_path, capability_string, windows_privilege). ``capabilities``
    is the report's behavior profile, each with a ``confidence`` and the
    ``evidence`` strings that produced it.

    The score has three parts:

    1. A floor of CONFIDENCE_FLOOR (0.2). A rule with no evidence behind it
       gets only this.
    2. Evidence: each item's strength is its kind weight times specificity
       (length / 20 characters, clamped to 0.3..1.0). Strengths are summed,
       so more items and stronger items both count, then saturated with
       ``1 - exp(-total / 2.5)``. This part adds up to EVIDENCE_SPAN (0.55)
       with diminishing returns: the tenth weak string adds little.
    3. Corroboration: capabilities whose evidence overlaps the rule's
       evidence confirm that the matched strings mean something. Their
       confidences are summed, capped at 1.5, scaled to 0..1, and add up to
       CORROBORATION_SPAN (0.2).

    The result is ``0.2 + 0.55 * evidence + 0.2 * corroboration``, which
    ranges from 0.2 to 0.95, rounded to two places. It is returned with the
    inputs that produced it, so the number can be explained.
    """
    total_strength = sum(_evidence_strength(value, kind) for value, kind in evidence)
    evidence_factor = 1 - math.exp(-total_strength / EVIDENCE_SATURATION)

    supporting = _supporting_capabilities(evidence, capabilities)
    support = min(
        1.0,
        sum(float(cap.get("confidence") or 0) for cap in supporting) / CORROBORATION_SATURATION,
    )

    confidence = CONFIDENCE_FLOOR + EVIDENCE_SPAN * evidence_factor + CORROBORATION_SPAN * support
    kinds: dict[str, int] = {}
    for _, kind in evidence:
        kinds[kind] = kinds.get(kind, 0) + 1
    basis = {
        "evidence_items": len(evidence),
        "evidence_kinds": kinds,
        "evidence_strength": round(total_strength, 2),
        "supporting_capabilities": [cap.get("name") for cap in supporting if cap.get("name")],
    }
    return round(min(confidence, 0.95), 2), basis


def _sanitize_rule_token(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\r", " ")
        .replace("\n", " ")
    )[:180]


def _suricata_sid(short_hash: str, domain: str, index: int) -> int:
    seed = f"{short_hash}:{index}:{domain}".encode("utf-8")
    return 1_000_000 + (int(hashlib.sha1(seed).hexdigest()[:6], 16) % 900_000)


def generate_detection_pack(report: ThreatReport, targets: list[str], strictness: str) -> dict:
    static_data = report.static_data or {}
    behavior_profile = static_data.get("behavior_profile") or {}
    behavior_names = behavior_profile.get("capability_names") or []
    capabilities = behavior_profile.get("capabilities") or []
    iocs = report.iocs or {}

    # (value, kind) pairs. IOCs come first so a value keeps its IOC kind even
    # when a capability rule also matched it.
    evidence_values = []
    for key, kind in IOC_KINDS.items():
        evidence_values.extend((value, kind) for value in iocs.get(key) or [])
    for capability in capabilities:
        evidence_values.extend((value, "capability_string") for value in capability.get("evidence") or [])

    deduped_evidence = []
    seen = set()
    for value, kind in evidence_values:
        if not value or len(str(value).strip()) < 4:
            continue
        token = str(value).strip()
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped_evidence.append((token, kind))

    selected_items = deduped_evidence[:18 if strictness == "broad" else 12]
    selected = [value for value, _ in selected_items]

    def scored(rule: dict, evidence: list[tuple[str, str]]) -> dict:
        rule["confidence"], rule["confidence_basis"] = compute_rule_confidence(evidence, capabilities)
        return rule
    short_hash = report.file_hash_sha256[:12]
    pack = {
        "file_hash_sha256": report.file_hash_sha256,
        "strictness": strictness,
        "source_report_id": str(report.id),
        "evidence_count": len(selected),
        "rules": [],
    }

    if "yara" in targets:
        strings = "\n".join(
            f"        $s{i} = \"{_sanitize_rule_token(value)}\" nocase"
            for i, value in enumerate(selected, start=1)
        )
        condition = "any of them" if selected else "uint16(0) == 0x5A4D"
        pack["rules"].append(scored({
            "format": "yara",
            "name": f"Sentinel_{short_hash}_Behavior_Profile",
            "validation_status": "draft_unvalidated",
            "evidence": selected,
            "content": (
                f"rule Sentinel_{short_hash}_Behavior_Profile {{\n"
                f"    meta:\n"
                f"        source = \"SENTINEL\"\n"
                f"        sha256 = \"{report.file_hash_sha256}\"\n"
                f"        behaviors = \"{', '.join(behavior_names)}\"\n"
                f"    strings:\n"
                f"{strings if strings else '        $mz = { 4D 5A }'}\n"
                f"    condition:\n"
                f"        {condition}\n"
                f"}}"
            ),
        }, selected_items))

    if iocs.get("commands"):
        command_items = [(value, "command") for value in iocs["commands"][:8]]
    else:
        command_items = selected_items[:8]
    command_values = [value for value, _ in command_items]
    if "sigma" in targets and command_values:
        pack["rules"].append(scored({
            "format": "sigma",
            "name": f"sentinel_{short_hash}_behavior_profile",
            "validation_status": "draft_unvalidated",
            "evidence": command_values,
            "content": {
                "title": f"SENTINEL behavior profile for {short_hash}",
                "id": f"sentinel-{short_hash}",
                "status": "experimental",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {"CommandLine|contains": command_values},
                    "condition": "selection",
                },
                "fields": ["Image", "CommandLine", "ParentImage", "User"],
                "falsepositives": ["Administrative tooling with overlapping strings"],
                "level": "high" if report.severity_score >= 70 else "medium",
            },
        }, command_items))

    if "suricata" in targets:
        domains = []
        for url in iocs.get("urls") or []:
            if "://" in url:
                host = url.split("://", 1)[1].split("/", 1)[0]
                if host and host not in domains:
                    domains.append(host)
        for index, domain in enumerate(domains[:8], start=1):
            pack["rules"].append(scored({
                "format": "suricata",
                "name": f"sentinel_{short_hash}_{domain}",
                "validation_status": "draft_unvalidated",
                "evidence": [domain],
                "content": (
                    f"alert http any any -> any any "
                    f"(msg:\"SENTINEL related host {domain}\"; "
                    f"http.host; content:\"{_sanitize_rule_token(domain)}\"; nocase; "
                    f"sid:{_suricata_sid(short_hash, domain, index)}; rev:1;)"
                ),
            }, [(domain, "domain")]))

    if "splunk" in targets:
        splunk_items = selected_items[:10]
        splunk_terms = [value for value, _ in splunk_items]
        query = " OR ".join(f"\"{_sanitize_rule_token(value)}\"" for value in splunk_terms)
        pack["rules"].append(scored({
            "format": "splunk",
            "name": f"sentinel_{short_hash}_ioc_search",
            "validation_status": "draft_unvalidated",
            "evidence": splunk_terms,
            "content": f"index=* ({query}) | stats count by host, source, sourcetype" if query else "index=* | head 0",
        }, splunk_items))

    return pack
