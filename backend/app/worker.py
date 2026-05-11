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

import re
import struct
import threading
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.services.file_service import download_file

try:
    import pefile
except ImportError:  # pragma: no cover - fallback keeps local dev usable before deps install
    pefile = None

settings = get_settings()

# Synchronous DB session for the analysis worker
sync_engine = create_engine(settings.DATABASE_URL_SYNC, connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL_SYNC else {})
SyncSession = sessionmaker(bind=sync_engine)


# ── Static Analysis Helpers ──────────────────────────────────────

MAX_SCAN_BYTES = 2_000_000
MAX_STRINGS = 750
MAX_IMPORT_FUNCTIONS = 400

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$"
)
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,253}\.[^@\s]{2,}$")
URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\")
BTC_RE = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

SUSPICIOUS_IMPORTS = {
    "createremotethread": "Process injection primitive",
    "writeprocessmemory": "Process memory modification",
    "virtualallocex": "Remote process memory allocation",
    "virtualprotect": "Executable memory permission changes",
    "setwindowshookex": "Userland hook installation",
    "regsetvalueex": "Registry modification",
    "internetopen": "WinINet network capability",
    "internetconnect": "WinINet network capability",
    "httpopenrequest": "HTTP request capability",
    "urldownloadtofile": "Download-to-file capability",
    "wsastartup": "Raw socket/network capability",
    "connect": "Outbound socket connection",
    "cryptdecrypt": "Cryptographic decrypt operation",
    "isdebuggerpresent": "Anti-debugging check",
    "checkremotedebuggerpresent": "Anti-debugging check",
}


def _extract_strings(data: bytes, min_length: int = 4) -> list[dict]:
    """Extract printable ASCII and UTF-16LE strings from binary data."""
    scan_data = data[:MAX_SCAN_BYTES]
    results = []

    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    for match in ascii_pattern.finditer(scan_data):
        value = match.group().decode("ascii", errors="ignore")
        results.append({
            "value": value,
            "encoding": "ascii",
            "offset": match.start(),
            "classification": _classify_string(value),
        })

    utf16_pattern = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}") % min_length)
    for match in utf16_pattern.finditer(scan_data):
        value = match.group().decode("utf-16le", errors="ignore").rstrip("\x00")
        if value:
            results.append({
                "value": value,
                "encoding": "utf-16le",
                "offset": match.start(),
                "classification": _classify_string(value),
            })

    results.sort(key=lambda item: item["offset"])
    return results[:MAX_STRINGS]


def _classify_string(s: str) -> str:
    """Classify a string as an IOC type."""
    normalized = s.strip().strip("\"'<>[](){}")

    if URL_RE.match(normalized):
        return "URL"
    if _is_valid_ipv4(normalized):
        return "IP_ADDRESS"
    if EMAIL_RE.match(normalized):
        return "EMAIL"
    if normalized.upper().startswith("HKEY_") or "SOFTWARE\\" in normalized.upper():
        return "REGISTRY_KEY"
    if WINDOWS_PATH_RE.match(normalized) or "/.." in normalized:
        return "FILE_PATH"
    if BTC_RE.match(normalized) or ETH_RE.match(normalized):
        return "CRYPTO_WALLET"
    if DOMAIN_RE.match(normalized):
        return "DOMAIN"
    return "UNKNOWN"


def _is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _analyze_pe_headers(data: bytes) -> dict | None:
    """Extract PE metadata, sections, imports, and exports."""
    if len(data) < 64 or data[:2] != b'MZ':
        return None

    if pefile is not None:
        try:
            return _analyze_pe_with_pefile(data)
        except Exception as exc:
            fallback = _analyze_pe_headers_basic(data)
            if fallback:
                fallback["parse_warning"] = f"pefile parse failed: {exc}"
            return fallback

    return _analyze_pe_headers_basic(data)


def _analyze_pe_headers_basic(data: bytes) -> dict | None:
    """Basic PE header extraction used when pefile is unavailable."""
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
            "parser": "manual",
            "machine": machine_names.get(machine, f"0x{machine:04x}"),
            "num_sections": num_sections,
            "compile_timestamp": timestamp,
            "compile_date": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if 0 < timestamp < 2000000000 else None,
            "file_size": len(data),
            "sections": [],
            "imports": [],
            "exports": [],
        }
    except (struct.error, ValueError):
        return {"is_pe": True, "parse_error": "Failed to parse PE headers"}


def _analyze_pe_with_pefile(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=False)
    machine_names = {
        0x14c: "x86",
        0x8664: "x64",
        0xaa64: "ARM64",
    }

    timestamp = pe.FILE_HEADER.TimeDateStamp
    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        entropy = round(section.get_entropy(), 4)
        sections.append({
            "name": name or "<unnamed>",
            "virtual_address": section.VirtualAddress,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
            "high_entropy": entropy > 7.0,
            "characteristics": f"0x{section.Characteristics:08x}",
        })

    imports = []
    import_function_total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "unknown"
        functions = []
        for imported in entry.imports:
            if import_function_total >= MAX_IMPORT_FUNCTIONS:
                break
            if imported.name:
                functions.append(imported.name.decode("utf-8", errors="replace"))
            else:
                functions.append(f"ordinal_{imported.ordinal}")
            import_function_total += 1
        imports.append({"dll": dll_name, "functions": functions})
        if import_function_total >= MAX_IMPORT_FUNCTIONS:
            break

    exports = []
    for exported in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        name = exported.name.decode("utf-8", errors="replace") if exported.name else None
        exports.append({
            "name": name or f"ordinal_{exported.ordinal}",
            "address": exported.address,
            "ordinal": exported.ordinal,
        })
        if len(exports) >= 200:
            break

    optional = pe.OPTIONAL_HEADER
    return {
        "is_pe": True,
        "parser": "pefile",
        "machine": machine_names.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04x}"),
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "compile_timestamp": timestamp,
        "compile_date": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if 0 < timestamp < 2000000000 else None,
        "entry_point": optional.AddressOfEntryPoint,
        "image_base": optional.ImageBase,
        "subsystem": getattr(optional, "Subsystem", None),
        "file_size": len(data),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "imports_truncated": import_function_total >= MAX_IMPORT_FUNCTIONS,
    }


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


def _flatten_import_names(pe_info: dict | None) -> set[str]:
    if not pe_info:
        return set()

    names = set()
    for import_group in pe_info.get("imports", []) or []:
        dll = import_group.get("dll")
        if dll:
            names.add(dll.lower())
        for function_name in import_group.get("functions", []) or []:
            names.add(function_name.lower())
    return names


def _summarize_import_risks(pe_info: dict | None) -> list[str]:
    import_names = _flatten_import_names(pe_info)
    if not import_names:
        return []

    findings = []
    for suspicious_name, description in SUSPICIOUS_IMPORTS.items():
        if suspicious_name in import_names:
            findings.append(description)

    return sorted(set(findings))


def _pe_summary_for_report(pe_info: dict | None) -> dict | None:
    if not pe_info:
        return None

    excluded = {"sections", "imports", "exports"}
    return {key: value for key, value in pe_info.items() if key not in excluded}


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
        high_entropy_sections = [
            section for section in (pe_info or {}).get("sections", [])
            if section.get("high_entropy")
        ]
        import_risks = _summarize_import_risks(pe_info)

        static_data = {
            "pe_headers": _pe_summary_for_report(pe_info),
            "pe_sections": (pe_info or {}).get("sections", []),
            "pe_imports": (pe_info or {}).get("imports", []),
            "pe_exports": (pe_info or {}).get("exports", []),
            "strings_count": len(strings),
            "strings_sample": strings[:100],
            "iocs_extracted": ioc_strings,
            "entropy": entropy,
            "high_entropy": entropy > 7.0,
            "high_entropy_sections": high_entropy_sections,
            "import_risks": import_risks,
        }

        job.progress_percent = 60
        job.status = JobStatus.CORTEX_REASONING
        session.commit()

        # ── Stage 4: Threat scoring ──────────────────────────────
        score = 0
        reasons = []

        if entropy > 7.0:
            score += 20
            reasons.append("High entropy suggests packed or encrypted content")

        if high_entropy_sections:
            score += min(len(high_entropy_sections) * 15, 30)
            section_names = ", ".join(section["name"] for section in high_entropy_sections[:5])
            reasons.append(f"High-entropy PE section(s): {section_names}")

        url_count = len([s for s in ioc_strings if s["classification"] == "URL"])
        ip_count = len([s for s in ioc_strings if s["classification"] == "IP_ADDRESS"])
        domain_count = len([s for s in ioc_strings if s["classification"] == "DOMAIN"])
        reg_count = len([s for s in ioc_strings if s["classification"] == "REGISTRY_KEY"])

        if url_count > 0:
            score += min(url_count * 5, 20)
            reasons.append(f"Contains {url_count} embedded URL(s)")
        if ip_count > 0:
            score += min(ip_count * 5, 15)
            reasons.append(f"Contains {ip_count} embedded IP address(es)")
        if domain_count > 0:
            score += min(domain_count * 3, 12)
            reasons.append(f"Contains {domain_count} embedded domain(s)")
        if reg_count > 0:
            score += min(reg_count * 10, 20)
            reasons.append(f"References {reg_count} registry key(s)")

        if import_risks:
            score += min(len(import_risks) * 8, 32)
            reasons.extend(import_risks)

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
            narrative += f"- Imported DLLs: {len(pe_info.get('imports', []))}\n"
            narrative += f"- Exported Symbols: {len(pe_info.get('exports', []))}\n"
            if pe_info.get('compile_date'):
                narrative += f"- Compile Date: {pe_info['compile_date']}\n"
            narrative += "\n"

        if high_entropy_sections:
            narrative += "### High-Entropy Sections\n"
            for section in high_entropy_sections[:10]:
                narrative += f"- `{section['name']}` entropy {section['entropy']} / 8.0\n"
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
        iocs_dict = {
            "urls": [s["value"] for s in ioc_strings if s["classification"] == "URL"],
            "ips": [s["value"] for s in ioc_strings if s["classification"] == "IP_ADDRESS"],
            "domains": [s["value"] for s in ioc_strings if s["classification"] == "DOMAIN"],
            "emails": [s["value"] for s in ioc_strings if s["classification"] == "EMAIL"],
            "registry_keys": [s["value"] for s in ioc_strings if s["classification"] == "REGISTRY_KEY"],
            "file_paths": [s["value"] for s in ioc_strings if s["classification"] == "FILE_PATH"],
            "crypto_wallets": [s["value"] for s in ioc_strings if s["classification"] == "CRYPTO_WALLET"],
        }

        report = session.query(ThreatReport).filter_by(job_id=job_id).first()
        if report is None:
            report = ThreatReport(job_id=job_id, file_hash_sha256=job.file_hash_sha256)
            session.add(report)

        report.severity_score = score
        report.verdict = verdict
        report.ai_narrative = narrative
        report.ai_available = False
        report.static_data = static_data
        report.iocs = iocs_dict

        job.status = JobStatus.COMPLETED
        job.progress_percent = 100
        job.completed_at = datetime.now(timezone.utc)
        session.commit()

        print(f"[SENTINEL] COMPLETE: {job.file_name} -> {verdict.value} (score: {score})")
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
        print(f"[SENTINEL] FAILED: {e}")
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
