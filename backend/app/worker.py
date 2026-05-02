"""SENTINEL — Celery worker for asynchronous analysis pipeline.

This worker processes files through the analysis pipeline:
  QUEUED → ANALYZING (static) → CORTEX_REASONING → COMPLETED
"""

import time
import re
import struct
from datetime import datetime, timezone
from celery import Celery
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.services.file_service import download_from_minio

settings = get_settings()

# ── Celery App ───────────────────────────────────────────────────

celery_app = Celery(
    "sentinel",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

# Synchronous DB session for Celery (can't use async in Celery tasks)
sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
SyncSession = sessionmaker(bind=sync_engine)


# ── Static Analysis Helpers ──────────────────────────────────────

def _extract_strings(data: bytes, min_length: int = 4) -> list[dict]:
    """Extract ASCII and Unicode strings from binary data."""
    results = []

    # ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    for match in ascii_pattern.finditer(data[:500000]):  # Limit to first 500KB for speed
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
            "compile_date": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if timestamp > 0 else None,
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


# ── Main Analysis Task ───────────────────────────────────────────

@celery_app.task(bind=True, name="sentinel.analyze_file", max_retries=3)
def analyze_file(self, job_id: str):
    """Process a file through the static analysis pipeline.

    Pipeline stages:
      1. Download file from MinIO
      2. Static analysis (PE headers, strings, entropy)
      3. Generate preliminary threat assessment
      4. Save report to database
    """
    from app.models.models import AnalysisJob, ThreatReport, JobStatus, Verdict

    session = SyncSession()
    try:
        # Fetch the job
        job = session.query(AnalysisJob).filter_by(id=job_id).first()
        if not job:
            return {"error": f"Job {job_id} not found"}

        # ── Stage 1: Update status ───────────────────────────────
        job.status = JobStatus.ANALYZING
        job.progress_percent = 10
        session.commit()

        # ── Stage 2: Download file from MinIO ────────────────────
        try:
            file_data = download_from_minio(job.minio_object_path)
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = f"Failed to download file from storage: {str(e)}"
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

        # ── Stage 4: Preliminary threat scoring ──────────────────
        score = 0
        reasons = []

        # High entropy = likely packed/encrypted
        if entropy > 7.0:
            score += 30
            reasons.append("High entropy suggests packed or encrypted content")

        # Suspicious IOCs
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

        # PE-specific scoring
        if pe_info and pe_info.get("is_pe"):
            score += 5  # PE files are inherently higher risk
            if pe_info.get("num_sections", 0) > 8:
                score += 10
                reasons.append("Unusual number of PE sections")

        score = min(score, 100)

        # Determine verdict
        if score >= 70:
            verdict = Verdict.MALICIOUS
        elif score >= 30:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

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
            ai_available=False,  # Will be True when Cortex LLM is integrated
            static_data=static_data,
            iocs=iocs_dict,
        )
        session.add(report)

        job.status = JobStatus.COMPLETED
        job.progress_percent = 100
        job.completed_at = datetime.now(timezone.utc)
        session.commit()

        return {
            "job_id": job_id,
            "verdict": verdict.value,
            "severity_score": score,
            "status": "COMPLETED",
        }

    except Exception as e:
        session.rollback()
        # Try to mark job as failed
        try:
            job = session.query(AnalysisJob).filter_by(id=job_id).first()
            if job:
                job.status = JobStatus.FAILED
                job.error_message = str(e)
                session.commit()
        except Exception:
            pass
        raise
    finally:
        session.close()
