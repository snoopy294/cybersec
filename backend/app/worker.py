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

        static_data = {
            "pe_headers": pe_info,
            "strings_count": len(strings),
            "strings_sample": strings[:100],
            "iocs_extracted": ioc_strings,
            "entropy": entropy,
            "high_entropy": entropy > 7.0,
        }

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
            "emails": [s["value"] for s in ioc_strings if s["classification"] == "EMAIL"],
            "registry_keys": [s["value"] for s in ioc_strings if s["classification"] == "REGISTRY_KEY"],
            "file_paths": [s["value"] for s in ioc_strings if s["classification"] == "FILE_PATH"],
        }

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
