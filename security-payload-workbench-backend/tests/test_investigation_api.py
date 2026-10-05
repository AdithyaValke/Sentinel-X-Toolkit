import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, select

from app import app, limiter
from database import Base, create_database
from models import (
    AuthSession,
    Investigation,
    InvestigationEvent,
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationIOC,
    User,
)


ORIGIN = "http://localhost:3000"


@pytest.fixture
def investigator_clients():
    original_database = app.extensions.get("database")
    database = create_database("sqlite:///:memory:")

    @event.listens_for(database.engine, "connect")
    def enable_sqlite_foreign_keys(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(database.engine)
    app.extensions["database"] = database
    app.testing = True
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_LIFETIME_SECONDS"] = 3600
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 60
    limiter.reset()

    def client_for(email):
        token = secrets.token_urlsafe(32)
        with database.sessions.begin() as db_session:
            user = User(email=email, password_hash="test-only-hash", display_name=email.split("@", 1)[0])
            db_session.add(user)
            db_session.flush()
            db_session.add(AuthSession(
                user_id=user.id,
                session_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ))
            user_id = user.id
        client = app.test_client()
        client.set_cookie("sentinelx_session", token, path="/api")
        return client, user_id

    client_a, user_a = client_for("analyst-a@example.org")
    client_b, user_b = client_for("analyst-b@example.org")
    yield database, client_a, user_a, client_b, user_b
    limiter.reset()
    app.extensions["database"] = original_database
    database.dispose()


def post(client, path, payload):
    return client.post(path, json=payload, headers={"Origin": ORIGIN})


def patch(client, path, payload, *, origin=ORIGIN):
    headers = {"Origin": origin} if origin else {}
    return client.patch(path, json=payload, headers=headers)


def create_case(client, title="Suspicious activity"):
    response = post(client, "/api/investigations", {"title": title, "description": "Initial review"})
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def test_investigation_api_requires_authentication(investigator_clients):
    _, _, _, _, _ = investigator_clients
    anonymous = app.test_client()
    paths = [
        ("get", "/api/investigations"),
        ("post", "/api/investigations"),
        ("get", "/api/investigations/1"),
        ("patch", "/api/investigations/1"),
        ("delete", "/api/investigations/1"),
        ("get", "/api/investigations/1/iocs"),
        ("post", "/api/investigations/1/iocs"),
        ("get", "/api/investigations/1/findings"),
        ("post", "/api/investigations/1/findings"),
        ("get", "/api/investigations/1/evidence"),
        ("post", "/api/investigations/1/evidence"),
        ("get", "/api/investigations/1/timeline"),
    ]
    for method, path in paths:
        response = getattr(anonymous, method)(path, json={} if method in {"post", "patch"} else None)
        assert response.status_code == 401, (method, path, response.get_data(as_text=True))


def test_owner_crud_and_close_timestamp_behavior(investigator_clients):
    database, client, owner_id, _, _ = investigator_clients
    created = create_case(client)
    assert created["status"] == "open"
    assert created["closed_at"] is None
    assert created["created_at"].endswith("Z")

    listed = client.get("/api/investigations").get_json()
    assert [item["id"] for item in listed["items"]] == [created["id"]]
    detail = client.get(f"/api/investigations/{created['id']}")
    assert detail.status_code == 200
    assert "owner_id" not in detail.get_json()["item"]
    assert "role" not in detail.get_json()["item"]

    closed = patch(client, f"/api/investigations/{created['id']}", {"status": "resolved", "title": "Reviewed incident"})
    assert closed.status_code == 200
    assert closed.get_json()["item"]["closed_at"].endswith("Z")
    reopened = patch(client, f"/api/investigations/{created['id']}", {"status": "investigating"})
    assert reopened.get_json()["item"]["closed_at"] is None
    with database.sessions() as session:
        item = session.get(Investigation, created["id"])
        assert item.owner_id == owner_id

    deleted = client.delete(f"/api/investigations/{created['id']}", headers={"Origin": ORIGIN})
    assert deleted.status_code == 204
    assert client.get(f"/api/investigations/{created['id']}").status_code == 404
    with database.sessions() as session:
        assert session.scalar(select(InvestigationEvent).where(InvestigationEvent.investigation_id == created["id"])) is None


def test_all_investigation_and_child_access_is_owner_scoped(investigator_clients):
    _, client_a, _, client_b, _ = investigator_clients
    case_a = create_case(client_a, "A case")
    case_b = create_case(client_b, "B case")
    ioc = post(client_b, f"/api/investigations/{case_b['id']}/iocs", {"ioc_type": "ip", "value": "192.0.2.8"}).get_json()["item"]
    finding = post(client_b, f"/api/investigations/{case_b['id']}/findings", {"title": "B finding"}).get_json()["item"]
    evidence = post(client_b, f"/api/investigations/{case_b['id']}/evidence", {
        "evidence_type": "note", "title": "B evidence", "content": "Observed by analyst",
    }).get_json()["item"]

    listed = client_a.get("/api/investigations").get_json()["items"]
    assert [item["id"] for item in listed] == [case_a["id"]]
    assert client_a.get(f"/api/investigations/{case_b['id']}").status_code == 404
    assert patch(client_a, f"/api/investigations/{case_b['id']}", {"title": "takeover"}).status_code == 404
    assert client_a.delete(f"/api/investigations/{case_b['id']}", headers={"Origin": ORIGIN}).status_code == 404
    for child in ("iocs", "findings", "evidence", "timeline"):
        assert client_a.get(f"/api/investigations/{case_b['id']}/{child}").status_code == 404
    assert post(client_a, f"/api/investigations/{case_b['id']}/iocs", {"ioc_type": "ip", "value": "192.0.2.9"}).status_code == 404
    assert post(client_a, f"/api/investigations/{case_b['id']}/findings", {"title": "No access"}).status_code == 404
    assert post(client_a, f"/api/investigations/{case_b['id']}/evidence", {
        "evidence_type": "note", "title": "No access", "content": "No access",
    }).status_code == 404
    assert ioc["investigation_id"] == finding["investigation_id"] == evidence["investigation_id"] == case_b["id"]


def test_ioc_validation_normalization_pagination_and_timeline(investigator_clients):
    database, client, _, _, _ = investigator_clients
    case = create_case(client)
    path = f"/api/investigations/{case['id']}/iocs"
    response = post(client, path, {
        "ioc_type": "domain", "value": "Malware[.]Example.", "confidence": 90,
    })
    assert response.status_code == 201
    assert response.get_json()["item"]["normalized_value"] == "malware.example"
    assert client.get(path).get_json()["items"][0]["ioc_type"] == "domain"
    assert client.get(path + "?limit=1&offset=0").get_json()["limit"] == 1
    assert client.get(path + "?limit=101").status_code == 400
    assert client.get(path + "?offset=-1").status_code == 400
    assert client.get(path + "?limit=NaN").status_code == 400

    timeline = client.get(f"/api/investigations/{case['id']}/timeline").get_json()["items"]
    assert {event["event_type"] for event in timeline} == {"created", "ioc_added"}
    assert all("Malware" not in event["message"] for event in timeline)
    with database.sessions() as session:
        assert session.scalar(select(InvestigationIOC)).source == "manual"


@pytest.mark.parametrize("payload", [
    {"ioc_type": [], "value": "192.0.2.1"},
    {"ioc_type": "ip", "value": "not-an-ip"},
    {"ioc_type": "hash", "value": "not-a-hash"},
    {"ioc_type": "ip", "value": "192.0.2.1", "confidence": 101},
    {"ioc_type": "ip", "value": "192.0.2.1", "confidence": True},
    {"ioc_type": "ip", "value": "192.0.2.1", "source": "unknown"},
    {"ioc_type": "ip", "value": "api_key=do-not-store"},
    {"ioc_type": "ip", "value": "192.0.2.1", "normalized_value": "192.0.2.2"},
    {"ioc_type": "ip", "value": "192.0.2.1", "investigation_id": 3},
])
def test_ioc_invalid_inputs_are_rejected(investigator_clients, payload):
    _, client, _, _, _ = investigator_clients
    case = create_case(client)
    assert post(client, f"/api/investigations/{case['id']}/iocs", payload).status_code == 400


def test_finding_validation_and_status_timeline(investigator_clients):
    _, client, _, _, _ = investigator_clients
    case = create_case(client)
    path = f"/api/investigations/{case['id']}/findings"
    created = post(client, path, {"title": "Suspicious execution", "severity": "high", "status": "confirmed"})
    assert created.status_code == 201
    assert created.get_json()["item"]["severity"] == "high"
    assert client.get(path).get_json()["items"][0]["title"] == "Suspicious execution"
    for payload in (
        {}, {"title": "x" * 201}, {"title": "x", "severity": "urgent"},
        {"title": "x", "status": "new"}, {"title": "x", "description": "y" * 8001},
        {"title": "x", "owner_id": 44}, {"title": "x", "description": "password=do-not-store"},
    ):
        assert post(client, path, payload).status_code == 400
    timeline = client.get(f"/api/investigations/{case['id']}/timeline").get_json()["items"]
    assert "finding_created" in {event["event_type"] for event in timeline}


def test_evidence_requires_same_investigation_finding_and_rejects_secrets(investigator_clients):
    _, client, _, _, _ = investigator_clients
    case_a = create_case(client, "Case A")
    case_b = create_case(client, "Case B")
    finding = post(client, f"/api/investigations/{case_b['id']}/findings", {"title": "Other case finding"}).get_json()["item"]
    evidence_path = f"/api/investigations/{case_a['id']}/evidence"
    payload = {"evidence_type": "log_snippet", "title": "DNS record", "content": "A lookup was observed"}
    linked_wrong = post(client, evidence_path, {**payload, "finding_id": finding["id"]})
    assert linked_wrong.status_code == 400
    created = post(client, f"/api/investigations/{case_b['id']}/evidence", {**payload, "finding_id": finding["id"]})
    assert created.status_code == 201
    assert client.get(f"/api/investigations/{case_b['id']}/evidence").get_json()["items"][0]["finding_id"] == finding["id"]
    evidence_events = client.get(f"/api/investigations/{case_b['id']}/timeline").get_json()["items"]
    assert "evidence_added" in {event["event_type"] for event in evidence_events}
    for secret in (
        "password=hidden", "Authorization: Bearer abc123", "eyJabcdefgh.abcdefgh.abcdefgh",
        "-----BEGIN PRIVATE KEY-----", "private_key=hidden", "sentinelx_session_cookie=hidden",
        "https://user:password@example.org/", "AKIA1234567890ABCDEF",
    ):
        result = post(client, evidence_path, {**payload, "content": secret})
        assert result.status_code == 400
        assert "credentials" in result.get_json()["error"] or "authentication" in result.get_json()["error"]
    assert client.get(f"/api/investigations/{case_a['id']}/evidence?limit=200").status_code == 400


def test_investigation_validation_origin_and_timeline_mutations(investigator_clients):
    _, client, _, _, _ = investigator_clients
    for payload in (
        {}, {"title": 7}, {"title": " "}, {"title": "x" * 201},
        {"title": "valid", "description": "x" * 8001}, {"title": "valid", "status": "closed"},
        {"title": "valid", "owner_id": 1}, {"title": "valid", "description": "session_token=secret"},
    ):
        assert post(client, "/api/investigations", payload).status_code == 400
    assert client.post("/api/investigations", data="{", content_type="application/json", headers={"Origin": ORIGIN}).status_code == 400
    created = create_case(client)
    path = f"/api/investigations/{created['id']}"
    assert client.post("/api/investigations", json={"title": "No Origin"}).status_code == 403
    assert patch(client, path, {"status": "resolved"}, origin=None).status_code == 403
    assert client.delete(path).status_code == 403
    for child, payload in (
        ("iocs", {"ioc_type": "ip", "value": "192.0.2.1"}),
        ("findings", {"title": "No Origin"}),
        ("evidence", {"evidence_type": "note", "title": "No Origin", "content": "Text"}),
    ):
        blocked = client.post(f"/api/investigations/{created['id']}/{child}", json=payload)
        assert blocked.status_code == 403
    assert patch(client, path, {"status": "bogus"}).status_code == 400
    assert patch(client, path, {"owner_id": 2}).status_code == 400
    assert patch(client, path, {"closed_at": "2026-01-01T00:00:00Z"}).status_code == 400
    changed = patch(client, path, {"status": "closed"})
    assert changed.status_code == 200 and changed.get_json()["item"]["closed_at"]
    events = client.get(f"/api/investigations/{created['id']}/timeline").get_json()["items"]
    assert {event["event_type"] for event in events} == {"created", "status_changed"}


def test_investigation_creation_uses_existing_rate_limiter(investigator_clients):
    _, client, _, _, _ = investigator_clients
    responses = [
        post(client, "/api/investigations", {"title": f"Rate test {number}"})
        for number in range(21)
    ]
    assert [response.status_code for response in responses] == [201] * 20 + [429]


def test_malformed_child_json_and_invalid_evidence_ids(investigator_clients):
    _, client, _, _, _ = investigator_clients
    case = create_case(client)
    bad_json = client.post(
        f"/api/investigations/{case['id']}/iocs", data="[]", content_type="application/json", headers={"Origin": ORIGIN},
    )
    assert bad_json.status_code == 400
    path = f"/api/investigations/{case['id']}/evidence"
    payload = {"evidence_type": "note", "title": "Note", "content": "Text"}
    for value in ("1", -1, True, {}):
        assert post(client, path, {**payload, "finding_id": value}).status_code == 400
    assert post(client, f"/api/investigations/99999/iocs", {"ioc_type": "ip", "value": "192.0.2.4"}).status_code == 404
