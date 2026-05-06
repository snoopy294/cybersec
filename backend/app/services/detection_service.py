"""Detection pack generation from SENTINEL report evidence."""

from __future__ import annotations

import hashlib

from app.models.models import ThreatReport


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
    iocs = report.iocs or {}

    evidence_values = []
    for key in ("urls", "registry_keys", "file_paths", "commands", "windows_privileges"):
        evidence_values.extend(iocs.get(key) or [])
    for capability in behavior_profile.get("capabilities") or []:
        evidence_values.extend(capability.get("evidence") or [])

    deduped_evidence = []
    seen = set()
    for value in evidence_values:
        if not value or len(str(value).strip()) < 4:
            continue
        token = str(value).strip()
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped_evidence.append(token)

    selected = deduped_evidence[:18 if strictness == "broad" else 12]
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
        pack["rules"].append({
            "format": "yara",
            "name": f"Sentinel_{short_hash}_Behavior_Profile",
            "confidence": 0.72 if selected else 0.35,
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
        })

    if "sigma" in targets:
        command_values = (iocs.get("commands") or selected)[:8]
        pack["rules"].append({
            "format": "sigma",
            "name": f"sentinel_{short_hash}_behavior_profile",
            "confidence": 0.68 if command_values else 0.3,
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
        })

    if "suricata" in targets:
        domains = []
        for url in iocs.get("urls") or []:
            if "://" in url:
                host = url.split("://", 1)[1].split("/", 1)[0]
                if host and host not in domains:
                    domains.append(host)
        for index, domain in enumerate(domains[:8], start=1):
            pack["rules"].append({
                "format": "suricata",
                "name": f"sentinel_{short_hash}_{domain}",
                "confidence": 0.62,
                "validation_status": "draft_unvalidated",
                "evidence": [domain],
                "content": (
                    f"alert http any any -> any any "
                    f"(msg:\"SENTINEL related host {domain}\"; "
                    f"http.host; content:\"{_sanitize_rule_token(domain)}\"; nocase; "
                    f"sid:{_suricata_sid(short_hash, domain, index)}; rev:1;)"
                ),
            })

    if "splunk" in targets:
        splunk_terms = selected[:10]
        query = " OR ".join(f"\"{_sanitize_rule_token(value)}\"" for value in splunk_terms)
        pack["rules"].append({
            "format": "splunk",
            "name": f"sentinel_{short_hash}_ioc_search",
            "confidence": 0.65 if splunk_terms else 0.3,
            "validation_status": "draft_unvalidated",
            "evidence": splunk_terms,
            "content": f"index=* ({query}) | stats count by host, source, sourcetype" if query else "index=* | head 0",
        })

    return pack
