"""The upload limit is set in several places that must change together."""

import math
import re
from pathlib import Path

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_LIMIT_MB = 12


def _match(path: str, pattern: str) -> str:
    match = re.search(pattern, (ROOT / path).read_text(encoding="utf-8"))
    assert match, f"{pattern!r} not found in {path}"
    return match.group(1)


def test_backend_default_matches_expected_limit():
    assert Settings.model_fields["MAX_FILE_SIZE_MB"].default == EXPECTED_LIMIT_MB


def test_frontend_limit_matches_backend():
    value = _match("frontend/src/app/_lib/constants.js", r"MAX_UPLOAD_SIZE_MB = (\d+)")
    assert int(value) == EXPECTED_LIMIT_MB


def test_render_blueprint_matches_backend():
    value = _match("render.yaml", r"key: MAX_FILE_SIZE_MB\s+value: (\d+)")
    assert int(value) == EXPECTED_LIMIT_MB


def test_env_example_matches_backend():
    value = _match("backend/.env.example", r"MAX_FILE_SIZE_MB=(\d+)")
    assert int(value) == EXPECTED_LIMIT_MB


def test_proxy_passes_anything_the_backend_can_answer():
    """The proxy truncates bodies over its cap, so it must exceed the backend's own cap."""
    value = _match("frontend/next.config.js", r"middlewareClientMaxBodySize: '(\d+)mb'")
    backend_cap_mb = Settings().max_request_body_bytes / (1024 * 1024)
    assert int(value) > math.ceil(backend_cap_mb)
