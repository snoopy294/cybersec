"""Compose runs Celery against the real module; Render stays on threads."""

from pathlib import Path

import yaml
from celery import Celery

from app import celery_worker

ROOT = Path(__file__).resolve().parents[2]


def _load(path):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_compose_worker_command_names_the_real_celery_app():
    services = _load("docker-compose.yml")["services"]
    command = services["celery-worker"]["command"]

    module, _, attribute = command.split("-A ", 1)[1].split()[0].partition(":")
    assert module == "app.celery_worker"
    assert isinstance(getattr(celery_worker, attribute), Celery)
    assert "sentinel.analyze_file" in celery_worker.celery_app.tasks


def test_compose_enables_celery_for_api_and_worker():
    services = _load("docker-compose.yml")["services"]

    for name in ("backend", "celery-worker"):
        environment = services[name]["environment"]
        assert environment["USE_CELERY"] == "true"
        assert environment["REDIS_URL"].startswith("redis://")
    assert "flower" in services["celery-flower"]["command"]


def test_render_stays_on_thread_mode():
    env_vars = _load("render.yaml")["services"][0]["envVars"]
    use_celery = next(item for item in env_vars if item["key"] == "USE_CELERY")
    assert use_celery["value"] is False
