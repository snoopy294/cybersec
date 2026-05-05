"""SENTINEL — Analysis engine.

Runs static analysis on uploaded files:
  - PE header extraction
  - String extraction with IOC classification
  - Shannon entropy computation
  - Automated threat scoring

Supports two modes:
  - Synchronous (default): Runs in a background thread, no Redis/Celery needed
  - Celery (optional): Distributed via Redis broker
"""

import hashlib
import json
import re
import struct
import threading
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.services.file_service import download_file

settings = get_settings()

# Synchronous DB session for the analysis worker
sync_engine = create_engine(settings.DATABASE_URL_SYNC, connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL_SYNC else {})
SyncSession = sessionmaker(bind=sync_engine)


# ── Static Analysis Helpers ──────────────────────────────────────

def _extract_strings(data: bytes, min_length: int = 4) -> list[dict]:
    """Extract ASCII strings from binary data."""
    results = []
    ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    for match in ascii_pattern.finditer(data[:500000]):  # First 500KB
        value = match.group().decode('ascii', errors='ignore')
        classification = _classify_string(value)
        results.append({
            "value": value,
            "encoding": "ascii",
            "offset": match.start(),
            "classification": classification,
        })
    return results[:500]  # Cap at 500 strings


def _classify_string(s: str) -> str:
    """Classify a string as an IOC type."""
    if re.match(r'https?://', s, re.IGNORECASE):
        return "URL"
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        return "IP_ADDRESS"
    if re.match(r'[^@]+@[^@]+\.[^@]+', s):
        return "EMAIL"
    if 'HKEY_' in s or 'SOFTWARE\\' in s:
        return "REGISTRY_KEY"
    if re.match(r'[A-Za-z]:\\', s) or '/..' in s:
        return "FILE_PATH"
    return "UNKNOWN"


def _analyze_pe_headers(data: bytes) -> dict | None:
    """Basic PE header extraction."""
    if len(data) < 64 or data[:2] != b'MZ':
        return None

    try:
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None

        machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
        num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
        timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]

        machine_names = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64"}

        return {
            "is_pe": True,
            "machine": machine_names.get(machine, f"0x{machine:04x}"),
            "num_sections": num_sections,
            "compile_timestamp": timestamp,
            "compile_date": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if 0 < timestamp < 2000000000 else None,
            "file_size": len(data),
        }
    except (struct.error, ValueError):
        return {"is_pe": True, "parse_error": "Failed to parse PE headers"}


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of binary data."""
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


BEHAVIOR_RULES = {
    "network_communications": {
        "patterns": [
            "http://", "https://", "ws2_32", "wininet", "winhttp", "internetopen",
            "internetconnect", "httpopenrequest", "urldownloadtofile", "getaddrinfo",
            "socket", "connect", "send", "recv",
        ],
        "mitre": ["T1071"],
        "label": "Network or command-and-control communications",
    },
    "persistence": {
        "patterns": [
            "\\currentversion\\run", "\\currentversion\\runonce", "startup",
            "schtasks", "createservice", "openservice", "startservice",
            "setwindowshookex", "runservices",
        ],
        "mitre": ["T1060", "T1053", "T1543"],
        "label": "Persistence through startup, scheduled task, or service hooks",
    },
    "process_injection": {
        "patterns": [
            "virtualallocex", "writeprocessmemory", "createremotethread",
            "ntmapviewofsection", "queueuserapc", "setthreadcontext",
            "openprocess", "rtlcreateuserthread",
        ],
        "mitre": ["T1055"],
        "label": "Process injection or remote memory manipulation",
    },
    "defense_evasion": {
        "patterns": [
            "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
            "virtualprotect", "loadlibrary", "getprocaddress", "sleep", "upx",
            "themida", "vmprotect",
        ],
        "mitre": ["T1027", "T1497"],
        "label": "Defense evasion, packing, or anti-analysis behavior",
    },
    "credential_access": {
        "patterns": [
            "cryptunprotectdata", "credenumerate", "lsass", "sam\\", "sekurlsa",
            "logonpasswords", "advapi32", "vaultcli",
        ],
        "mitre": ["T1003", "T1555"],
        "label": "Credential or secret access",
    },
    "system_discovery": {
        "patterns": [
            "enumprocesses", "createtoolhelp32snapshot", "process32first",
            "process32next", "getusername", "getcomputername", "systeminfo",
            "ipconfig", "whoami", "net view",
        ],
        "mitre": ["T1057", "T1082", "T1033"],
        "label": "Host, user, process, or network discovery",
    },
    "registry_modification": {
        "patterns": [
            "regopenkey", "regsetvalue", "regcreatekey", "regdeletevalue",
            "hkey_", "software\\microsoft\\windows",
        ],
        "mitre": ["T1112"],
        "label": "Registry inspection or modification",
    },
    "file_system_activity": {
        "patterns": [
            "createfile", "writefile", "deletefile", "copyfile", "movefile",
            "gettemppath", "\\temp\\", "appdata", "programdata",
        ],
        "mitre": ["T1105", "T1036"],
        "label": "File staging, writing, or cleanup activity",
    },
    "destructive_or_ransomware": {
        "patterns": [
            "vssadmin delete shadows", "wbadmin delete", "bcdedit /set",
            "delete shadows", ".locked", ".encrypted", "ransom", "recover your files",
        ],
        "mitre": ["T1486", "T1490"],
        "label": "Destructive, recovery-inhibiting, or ransomware-like behavior",
    },
}


def _ioc_hosts(iocs_dict: dict) -> list[str]:
    """Normalize IOC URLs/IPs into host-like comparison tokens."""
    hosts = set(iocs_dict.get("ips", []))
    for url in iocs_dict.get("urls", []):
        parsed = urlparse(url)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    return sorted(hosts)


def _build_behavior_profile(strings: list[dict], iocs_dict: dict, entropy: float, pe_info: dict | None) -> dict:
    """Infer behavior capabilities from static strings and PE metadata."""
    searchable = []
    for item in strings:
        value = item.get("value", "")
        if value:
            searchable.append(value)

    capabilities = []
    all_text = "\n".join(searchable).lower()

    for name, rule in BEHAVIOR_RULES.items():
        evidence = []
        for pattern in rule["patterns"]:
            pattern_l = pattern.lower()
            if pattern_l in all_text:
                evidence.append(pattern)

        if name == "network_communications":
            evidence.extend(_ioc_hosts(iocs_dict))
        if name == "defense_evasion" and entropy > 7.0:
            evidence.append(f"entropy:{entropy}")
        if name == "registry_modification" and iocs_dict.get("registry_keys"):
            evidence.extend(iocs_dict["registry_keys"][:5])

        deduped = sorted(set(evidence))
        if deduped:
            confidence = min(0.95, 0.35 + (0.12 * len(deduped)))
            capabilities.append({
                "name": name,
                "label": rule["label"],
                "confidence": round(confidence, 2),
                "evidence": deduped[:10],
                "mitre": rule["mitre"],
            })

    capability_names = sorted(c["name"] for c in capabilities)
    mitre = sorted({tech for c in capabilities for tech in c["mitre"]})
    api_tokens = _extract_api_tokens(strings)

    fingerprint_payload = {
        "capabilities": capability_names,
        "ioc_hosts": _ioc_hosts(iocs_dict),
        "api_tokens": api_tokens[:100],
        "pe_machine": pe_info.get("machine") if pe_info else None,
        "pe_sections": pe_info.get("num_sections") if pe_info else None,
        "entropy_bucket": _entropy_bucket(entropy),
    }

    return {
        "capabilities": capabilities,
        "capability_names": capability_names,
        "api_tokens": api_tokens[:100],
        "ioc_hosts": fingerprint_payload["ioc_hosts"],
        "mitre": mitre,
        "semantic_fingerprint": hashlib.sha256(
            json.dumps(fingerprint_payload, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "fingerprint_payload": fingerprint_payload,
    }


def _extract_api_tokens(strings: list[dict]) -> list[str]:
    """Pull Windows-looking API names from extracted strings."""
    counter = Counter()
    api_pattern = re.compile(r"\b[A-Z][A-Za-z0-9]{4,}(?:A|W)?\b")
    for item in strings:
        value = item.get("value", "")
        for token in api_pattern.findall(value):
            if any(keyword in token.lower() for keyword in (
                "process", "thread", "file", "registry", "internet", "crypt",
                "token", "service", "window", "memory", "module",
            )):
                counter[token.lower()] += 1
    return [token for token, _ in counter.most_common(100)]


def _entropy_bucket(entropy: float) -> str:
    if entropy >= 7.3:
        return "very_high"
    if entropy >= 7.0:
        return "high"
    if entropy >= 6.0:
        return "medium"
    return "low"


def _jaccard(left: set, right: set) -> float:
    if not left and not right:
        return 0.0
    return len(left & right) / len(left | right)


def _find_behavior_matches(session, current_job, static_data: dict, iocs_dict: dict) -> dict:
    """Compare the current sample against previously completed reports."""
    from app.models.models import AnalysisJob, ThreatReport, JobStatus

    current_profile = static_data.get("behavior_profile") or {}
    current_caps = set(current_profile.get("capability_names") or [])
    current_apis = set(current_profile.get("api_tokens") or [])
    current_hosts = set(current_profile.get("ioc_hosts") or [])
    current_entropy_bucket = _entropy_bucket(static_data.get("entropy", 0.0))

    candidates = (
        session.query(ThreatReport, AnalysisJob)
        .join(AnalysisJob, ThreatReport.job_id == AnalysisJob.id)
        .filter(ThreatReport.file_hash_sha256 != current_job.file_hash_sha256)
        .filter(AnalysisJob.status == JobStatus.COMPLETED)
        .order_by(ThreatReport.created_at.desc())
        .limit(250)
        .all()
    )

    matches = []
    for report, job in candidates:
        previous_static = report.static_data or {}
        previous_profile = previous_static.get("behavior_profile") or {}

        previous_caps = set(previous_profile.get("capability_names") or [])
        previous_apis = set(previous_profile.get("api_tokens") or [])
        previous_hosts = set(previous_profile.get("ioc_hosts") or [])

        behavior_similarity = _jaccard(current_caps, previous_caps)
        api_similarity = _jaccard(current_apis, previous_apis)
        ioc_similarity = _jaccard(current_hosts, previous_hosts)
        entropy_match = 1.0 if current_entropy_bucket == _entropy_bucket(previous_static.get("entropy", 0.0)) else 0.0

        similarity = (
            behavior_similarity * 0.55
            + api_similarity * 0.20
            + ioc_similarity * 0.20
            + entropy_match * 0.05
        )

        if similarity < 0.18:
            continue

        matches.append({
            "file_name": job.file_name,
            "file_hash_sha256": report.file_hash_sha256,
            "verdict": report.verdict,
            "severity_score": report.severity_score,
            "created_at": report.created_at.isoformat() if report.created_at else None,
            "similarity_score": round(similarity * 100),
            "matched_behaviors": sorted(current_caps & previous_caps),
            "shared_api_tokens": sorted(current_apis & previous_apis)[:20],
            "shared_iocs": sorted(current_hosts & previous_hosts)[:20],
        })

    matches.sort(key=lambda item: item["similarity_score"], reverse=True)
    return {
        "match_count": len(matches),
        "top_matches": matches[:5],
        "method": "behavior+jaccard:v1",
    }


# ── Core Analysis Function ───────────────────────────────────────

def run_analysis(job_id: str):
    """Process a file through the static analysis pipeline.

    This function runs synchronously and is designed to be called
    either directly in a background thread or via Celery.
    """
    from app.models.models import AnalysisJob, ThreatReport, JobStatus, Verdict

    session = SyncSession()
    try:
        job = session.query(AnalysisJob).filter_by(id=job_id).first()
        if not job:
            print(f"[SENTINEL] Job {job_id} not found")
            return {"error": f"Job {job_id} not found"}

        # ── Stage 1: Update status ───────────────────────────────
        job.status = JobStatus.ANALYZING
        job.progress_percent = 10
        session.commit()
        print(f"[SENTINEL] Analyzing: {job.file_name}")

        # ── Stage 2: Download file ───────────────────────────────
        try:
            file_data = download_file(job.minio_object_path)
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = f"Failed to read file: {str(e)}"
            session.commit()
            return {"error": str(e)}

        job.progress_percent = 25
        session.commit()

        # ── Stage 3: Static analysis ────────────────────────────
        pe_info = _analyze_pe_headers(file_data)
        strings = _extract_strings(file_data)
        entropy = _compute_entropy(file_data)

        ioc_strings = [s for s in strings if s["classification"] != "UNKNOWN"]
        iocs_dict = {
            "urls": [s["value"] for s in ioc_strings if s["classification"] == "URL"],
            "ips": [s["value"] for s in ioc_strings if s["classification"] == "IP_ADDRESS"],
            "emails": [s["value"] for s in ioc_strings if s["classification"] == "EMAIL"],
            "registry_keys": [s["value"] for s in ioc_strings if s["classification"] == "REGISTRY_KEY"],
            "file_paths": [s["value"] for s in ioc_strings if s["classification"] == "FILE_PATH"],
        }
        behavior_profile = _build_behavior_profile(strings, iocs_dict, entropy, pe_info)

        static_data = {
            "pe_headers": pe_info,
            "strings_count": len(strings),
            "strings_sample": strings[:100],
            "iocs_extracted": ioc_strings,
            "entropy": entropy,
            "high_entropy": entropy > 7.0,
            "behavior_profile": behavior_profile,
        }
        cross_reference = _find_behavior_matches(session, job, static_data, iocs_dict)
        static_data["cross_reference"] = cross_reference

        job.progress_percent = 60
        job.status = JobStatus.CORTEX_REASONING
        session.commit()

        # ── Stage 4: Threat scoring ──────────────────────────────
        score = 0
        reasons = []

        if entropy > 7.0:
            score += 30
            reasons.append("High entropy suggests packed or encrypted content")

        url_count = len([s for s in ioc_strings if s["classification"] == "URL"])
        ip_count = len([s for s in ioc_strings if s["classification"] == "IP_ADDRESS"])
        reg_count = len([s for s in ioc_strings if s["classification"] == "REGISTRY_KEY"])

        if url_count > 0:
            score += min(url_count * 5, 20)
            reasons.append(f"Contains {url_count} embedded URL(s)")
        if ip_count > 0:
            score += min(ip_count * 5, 15)
            reasons.append(f"Contains {ip_count} embedded IP address(es)")
        if reg_count > 0:
            score += min(reg_count * 10, 20)
            reasons.append(f"References {reg_count} registry key(s)")

        behavior_names = set(behavior_profile.get("capability_names", []))
        high_risk_behaviors = behavior_names & {
            "process_injection",
            "credential_access",
            "persistence",
            "destructive_or_ransomware",
        }
        if high_risk_behaviors:
            score += min(len(high_risk_behaviors) * 12, 30)
            reasons.append(
                "Behavior profile matches high-risk capability group(s): "
                + ", ".join(sorted(high_risk_behaviors))
            )

        best_match = (cross_reference.get("top_matches") or [None])[0]
        if best_match:
            match_score = best_match["similarity_score"]
            if match_score >= 70:
                score += 20
            elif match_score >= 45:
                score += 10
            reasons.append(
                f"Behaviorally similar to prior sample {best_match['file_name']} "
                f"({match_score}% match, verdict {best_match['verdict']})"
            )

        if pe_info and pe_info.get("is_pe"):
            score += 5
            if pe_info.get("num_sections", 0) > 8:
                score += 10
                reasons.append("Unusual number of PE sections")

        score = min(score, 100)

        if score >= 70:
            verdict = Verdict.MALICIOUS
        elif score >= 30:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

        # ── Generate narrative ───────────────────────────────────
        narrative = f"## Automated Static Analysis Report\n\n"
        narrative += f"**File:** {job.file_name}\n"
        narrative += f"**SHA-256:** `{job.file_hash_sha256}`\n"
        narrative += f"**Size:** {job.file_size_bytes:,} bytes\n"
        narrative += f"**Entropy:** {entropy} / 8.0\n\n"

        if pe_info and pe_info.get("is_pe"):
            narrative += f"### PE Binary Analysis\n"
            narrative += f"- Architecture: {pe_info.get('machine', 'Unknown')}\n"
            narrative += f"- Sections: {pe_info.get('num_sections', 'N/A')}\n"
            if pe_info.get('compile_date'):
                narrative += f"- Compile Date: {pe_info['compile_date']}\n"
            narrative += "\n"

        if behavior_profile["capabilities"]:
            narrative += "### Behavior Profile\n"
            for capability in behavior_profile["capabilities"][:8]:
                evidence = ", ".join(capability["evidence"][:3])
                narrative += (
                    f"- {capability['label']} "
                    f"({int(capability['confidence'] * 100)}% confidence"
                )
                if evidence:
                    narrative += f"; evidence: `{evidence}`"
                narrative += ")\n"
            narrative += "\n"

        if cross_reference["top_matches"]:
            narrative += "### Historical Behavior Matches\n"
            for match in cross_reference["top_matches"][:3]:
                behaviors = ", ".join(match["matched_behaviors"][:4]) or "shared static traits"
                narrative += (
                    f"- {match['similarity_score']}% similar to `{match['file_name']}` "
                    f"({match['verdict']}, score {match['severity_score']}): {behaviors}\n"
                )
            narrative += "\n"

        if reasons:
            narrative += "### Risk Indicators\n"
            for r in reasons:
                narrative += f"- ⚠️ {r}\n"
            narrative += "\n"

        if ioc_strings:
            narrative += f"### Indicators of Compromise ({len(ioc_strings)} found)\n"
            for ioc in ioc_strings[:10]:
                narrative += f"- [{ioc['classification']}] `{ioc['value']}`\n"

        # ── Stage 5: Save report ─────────────────────────────────
        report = ThreatReport(
            job_id=job_id,
            file_hash_sha256=job.file_hash_sha256,
            severity_score=score,
            verdict=verdict,
            ai_narrative=narrative,
            ai_available=False,
            static_data=static_data,
            iocs=iocs_dict,
        )
        session.add(report)

        job.status = JobStatus.COMPLETED
        job.progress_percent = 100
        job.completed_at = datetime.now(timezone.utc)
        session.commit()

        print(f"[SENTINEL] ✅ Complete: {job.file_name} → {verdict.value} (score: {score})")
        return {"job_id": job_id, "verdict": verdict.value, "severity_score": score}

    except Exception as e:
        session.rollback()
        try:
            job = session.query(AnalysisJob).filter_by(id=job_id).first()
            if job:
                job.status = JobStatus.FAILED
                job.error_message = str(e)
                session.commit()
        except Exception:
            pass
        print(f"[SENTINEL] ❌ Failed: {e}")
        raise
    finally:
        session.close()


# ── Dispatch: Background Thread (default) or Celery ──────────────

def dispatch_analysis(job_id: str):
    """Dispatch analysis — uses background thread by default, Celery if configured."""
    if settings.USE_CELERY:
        # Lazy import Celery task to avoid import errors when Redis isn't available
        from app.celery_worker import analyze_file_task
        analyze_file_task.delay(job_id)
    else:
        # Run in background thread (no Redis/Celery required)
        thread = threading.Thread(target=run_analysis, args=(job_id,), daemon=True)
        thread.start()
