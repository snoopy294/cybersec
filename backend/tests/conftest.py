"""Test configuration.

Settings are read once at import, so the environment is pinned here before
any app module loads. Set TEST_DATABASE_URL to run the API tests against
Postgres (CI does); otherwise they use a throwaway SQLite file.
"""

import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))

os.environ["DEBUG"] = "true"
os.environ["STORAGE_BACKEND"] = "local"
os.environ["STORAGE_DIR"] = str(_tmp / "storage")
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", f"sqlite+aiosqlite:///{(_tmp / 'test.db').as_posix()}"
)
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-1234")
os.environ["ALLOW_REGISTRATION"] = "true"
