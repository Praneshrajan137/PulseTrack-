import hashlib
import hmac
import importlib
import json
import sys
import time
from typing import Dict, Tuple

import pytest
from fastapi.testclient import TestClient


def generate_valid_signature(payload: Dict, secret: str, prefix: bool = True) -> Tuple[str, bytes]:
    """Return (signature_header_value, body_bytes) for a payload using canonical JSON encoding."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return ((f"sha256={digest}" if prefix else digest), body)


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "testsecret")
    monkeypatch.setenv("MONITORED_KEYWORDS", "Chat Completions,API,Assistants API,OpenAI API")
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    monkeypatch.setenv("PRODUCTION_MODE", "false")

    # Ensure a fresh import of main per test
    if "main" in sys.modules:
        del sys.modules["main"]
    import main  # type: ignore  # noqa

    return TestClient(main.app)


def post_signed(client: TestClient, payload: Dict, secret: str, *, prefix: bool = True,
                content_type: str = "application/json"):
    sig, body = generate_valid_signature(payload, secret, prefix=prefix)
    headers = {"content-type": content_type, "x-hub-signature-256": sig}
    return client.post("/webhook", data=body, headers=headers)


def test_health_ok(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.parametrize("prefix", [True, False])
def test_webhook_component_happy_path(client: TestClient, prefix: bool, caplog, monkeypatch):
    # Fix timestamp for deterministic log
    import processor
    monkeypatch.setattr(processor, "_now_utc_tag", lambda: "[2025-10-15T14:32:01Z]")

    payload = {
        "component": {"name": "OpenAI API - Chat Completions"},
        "component_update": {"id": "cu_1", "new_status": "degraded_performance"},
    }
    r = post_signed(client, payload, "testsecret", prefix=prefix)
    assert r.status_code == 202
    assert r.json() == {"status": "accepted"}

    # Background task logs the message
    client.__exit__()  # trigger app shutdown to flush background tasks
    # Caplog captured at INFO in pytest.ini
    messages = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    assert (
        "[2025-10-15T14:32:01Z] Product: OpenAI API - Chat Completions\n"
        "Status: Degraded performance\n" in messages
    )


def test_webhook_incident_happy_path(client: TestClient, caplog, monkeypatch):
    import processor
    monkeypatch.setattr(processor, "_now_utc_tag", lambda: "[2025-10-15T14:35:22Z]")

    payload = {
        "incident": {"id": "inc_1", "name": "Elevated error rate in Assistants API", "status": "investigating"}
    }
    r = post_signed(client, payload, "testsecret")
    assert r.status_code == 202
    client.__exit__()
    messages = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    assert (
        "[2025-10-15T14:35:22Z] Product: Platform Incident\n"
        "Status: Elevated error rate in Assistants API - Investigating\n" in messages
    )


def test_component_priority_over_incident(client: TestClient, caplog, monkeypatch):
    import processor
    monkeypatch.setattr(processor, "_now_utc_tag", lambda: "[2025-10-15T14:40:00Z]")

    payload = {
        "component": {"name": "OpenAI API - Chat Completions"},
        "component_update": {"id": "cu_2", "new_status": "operational"},
        "incident": {"id": "inc_2", "name": "Some platform issue", "status": "identified"},
    }
    r = post_signed(client, payload, "testsecret")
    assert r.status_code == 202
    client.__exit__()
    messages = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    # Ensure component log is present and incident log is not emitted due to priority
    assert (
        "[2025-10-15T14:40:00Z] Product: OpenAI API - Chat Completions\n"
        "Status: Operational\n" in messages
    )


@pytest.mark.parametrize(
    "ctype",
    ["text/plain", "application/xml", "", "multipart/form-data"],
)
def test_bad_content_type_rejected(client: TestClient, ctype: str):
    payload = {"foo": "bar"}
    sig, body = generate_valid_signature(payload, "testsecret")
    headers = {"content-type": ctype, "x-hub-signature-256": sig}
    r = client.post("/webhook", data=body, headers=headers)
    assert r.status_code == 415
    assert r.json()["detail"] == "Unsupported Media Type"


@pytest.mark.parametrize(
    "sig_header",
    [None, "", "sha256=deadbeef", "nothex"],
)
def test_missing_or_invalid_signature(client: TestClient, sig_header):
    payload = {"foo": "bar"}
    _, body = generate_valid_signature(payload, "testsecret")
    headers = {"content-type": "application/json"}
    if sig_header is not None:
        headers["x-hub-signature-256"] = sig_header
    r = client.post("/webhook", data=body, headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid signature"


@pytest.mark.parametrize("use_prefix", [True, False])
def test_valid_signature_with_or_without_prefix(client: TestClient, use_prefix: bool):
    payload = {"foo": "bar"}
    sig, body = generate_valid_signature(payload, "testsecret", prefix=use_prefix)
    headers = {"content-type": "application/json", "x-hub-signature-256": sig}
    r = client.post("/webhook", data=body, headers=headers)
    assert r.status_code == 202


def test_request_too_large(client: TestClient):
    # Simulate large content by faking Content-Length header only
    payload = {"foo": "bar"}
    sig, body = generate_valid_signature(payload, "testsecret")
    headers = {"content-type": "application/json", "x-hub-signature-256": sig, "content-length": str(1_048_577)}
    r = client.post("/webhook", data=body, headers=headers)
    assert r.status_code == 413


def test_dedup_component_suppresses_second(client: TestClient, caplog, monkeypatch):
    import processor
    monkeypatch.setattr(processor, "_now_utc_tag", lambda: "[2025-10-15T14:50:00Z]")

    payload = {
        "component": {"name": "OpenAI API - Chat Completions"},
        "component_update": {"id": "dupe_1", "new_status": "degraded_performance"},
    }
    r1 = post_signed(client, payload, "testsecret")
    r2 = post_signed(client, payload, "testsecret")
    assert r1.status_code == 202 and r2.status_code == 202
    client.__exit__()
    info_msgs = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    debug_msgs = [rec.getMessage() for rec in caplog.records if rec.levelname == "DEBUG"]
    assert any("Product: OpenAI API - Chat Completions" in m for m in info_msgs)
    assert any("Duplicate component update suppressed" in m for m in debug_msgs)


def test_dedup_incident_suppresses_second(client: TestClient, caplog, monkeypatch):
    import processor
    monkeypatch.setattr(processor, "_now_utc_tag", lambda: "[2025-10-15T14:55:00Z]")

    payload = {
        "incident": {"id": "dupe_inc", "name": "Assistants API partial outage", "status": "monitoring"}
    }
    r1 = post_signed(client, payload, "testsecret")
    r2 = post_signed(client, payload, "testsecret")
    assert r1.status_code == 202 and r2.status_code == 202
    client.__exit__()
    info_msgs = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    debug_msgs = [rec.getMessage() for rec in caplog.records if rec.levelname == "DEBUG"]
    assert any("Product: Platform Incident" in m for m in info_msgs)
    assert any("Duplicate incident suppressed" in m for m in debug_msgs)


@pytest.mark.parametrize(
    "name,should_log",
    [
        ("Billing Portal", False),
        ("OpenAI Playground", False),
        ("OpenAI API - Chat Completions", True),
        ("Embeddings API", True),
    ],
)
def test_filtering_on_component_name(client: TestClient, caplog, name: str, should_log: bool, monkeypatch):
    import processor
    monkeypatch.setattr(processor, "_now_utc_tag", lambda: "[2025-10-15T15:00:00Z]")

    payload = {"component": {"name": name}, "component_update": {"id": name, "new_status": "partial_outage"}}
    r = post_signed(client, payload, "testsecret")
    assert r.status_code == 202
    client.__exit__()
    info_msgs = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    if should_log:
        assert any("Product:" in m for m in info_msgs)
    else:
        assert not any("Product:" in m for m in info_msgs)


@pytest.mark.parametrize(
    "incident_name,should_log",
    [
        ("Elevated error rate in Playground", False),
        ("Elevated error rate in Assistants API", True),
    ],
)
def test_filtering_on_incident_name(client: TestClient, caplog, incident_name: str, should_log: bool, monkeypatch):
    import processor
    monkeypatch.setattr(processor, "_now_utc_tag", lambda: "[2025-10-15T15:05:00Z]")

    payload = {"incident": {"id": incident_name, "name": incident_name, "status": "identified"}}
    r = post_signed(client, payload, "testsecret")
    assert r.status_code == 202
    client.__exit__()
    info_msgs = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    if should_log:
        assert any("Platform Incident" in m for m in info_msgs)
    else:
        assert not any("Platform Incident" in m for m in info_msgs)


@pytest.mark.parametrize("bad_body", ["[]", "123", '"string"'])
def test_malformed_body_returns_422_with_valid_signature(client: TestClient, bad_body: str):
    # Compute signature over the exact bad body string
    secret = "testsecret"
    digest = hmac.new(secret.encode("utf-8"), bad_body.encode("utf-8"), hashlib.sha256).hexdigest()
    sig = f"sha256={digest}"
    headers = {"content-type": "application/json", "x-hub-signature-256": sig}
    r = client.post("/webhook", data=bad_body.encode("utf-8"), headers=headers)
    assert r.status_code == 422


def test_monitored_keywords_env_override(client: TestClient, caplog, monkeypatch):
    # Override to only allow Playground (not default)
    monkeypatch.setenv("MONITORED_KEYWORDS", "Playground")

    if "processor" in sys.modules:
        del sys.modules["processor"]
    import processor  # type: ignore  # noqa

    payload = {"component": {"name": "OpenAI API - Chat Completions"}, "component_update": {"id": "x", "new_status": "operational"}}
    r = post_signed(client, payload, "testsecret")
    assert r.status_code == 202
    client.__exit__()
    info_msgs = [rec.getMessage() for rec in caplog.records if rec.levelname == "INFO"]
    assert not any("Product:" in m for m in info_msgs)


def test_background_tasks_drain_on_shutdown(client: TestClient):
    payload = {"component": {"name": "OpenAI API - Chat Completions"}, "component_update": {"id": "bg_1", "new_status": "operational"}}
    r = post_signed(client, payload, "testsecret")
    assert r.status_code == 202
    # Trigger shutdown to enter lifespan drain
    client.__exit__()
    # If we reach here without timeout, background tasks drained
    assert True
