from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import app, g, jsonify, limiter, require_authentication
from database import create_database
from models import AuthSession, User


ORIGIN = "http://localhost:3000"


@pytest.fixture
def auth_client():
    original_database = app.extensions.get("database")
    database = create_database("sqlite:///:memory:")
    from database import Base
    import models  # noqa: F401
    Base.metadata.create_all(database.engine)
    app.extensions["database"] = database
    app.testing = True
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_LIFETIME_SECONDS"] = 3600
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 60
    limiter.reset()
    with app.test_client() as client:
        yield client, database
    limiter.reset()
    app.extensions["database"] = original_database
    database.dispose()


def post_auth(client, path, payload=None):
    return client.post(path, json=payload or {}, headers={"Origin": ORIGIN})


def register(client, email="Person@Example.org", password="a long password 123", display_name="Person"):
    return post_auth(client, "/api/auth/register", {"email": email, "password": password, "display_name": display_name})


def _test_protected_resource():
    return jsonify({"user_id": g.auth_user.id})


app.add_url_rule(
    "/api/test-only-protected-resource",
    endpoint="test_only_protected_investigation_placeholder",
    view_func=require_authentication(_test_protected_resource),
    methods=["GET"],
)


def test_registration_normalizes_email_hashes_password_and_returns_only_safe_user(auth_client):
    client, database = auth_client
    response = register(client)
    assert response.status_code == 201
    assert response.get_json()["user"]["email"] == "person@example.org"
    assert set(response.get_json()["user"]) == {"id", "email", "display_name", "role"}
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/api" in cookie
    assert "Secure" not in cookie
    with database.sessions() as session:
        user = session.scalar(select(User))
        auth_session = session.scalar(select(AuthSession))
        assert user.password_hash != "a long password 123"
        assert user.password_hash.startswith("$argon2id$")
        assert "a long password 123" not in response.get_data(as_text=True)
        assert auth_session.session_token_hash not in response.get_data(as_text=True)
        assert auth_session.session_token_hash != cookie.split("=", 1)[1].split(";", 1)[0]


def test_api_scoped_session_cookie_is_sent_to_future_api_routes(auth_client):
    client, _ = auth_client
    assert register(client).status_code == 201
    future_route_request = client.get("/api/future-protected-resource").request
    assert future_route_request.cookies.get("sentinelx_session")


def test_public_tool_is_usable_without_login_and_auth_decorator_is_opt_in(auth_client):
    client, _ = auth_client
    public_result = client.post("/api/process", json={
        "input_text": "hello", "operation": "base64_encode",
    })
    assert public_result.status_code == 200
    assert public_result.get_json()["result"] == "aGVsbG8="

    path = "/api/test-only-protected-resource"
    assert client.get(path, headers={"X-User-ID": "1", "X-User": "1"}).status_code == 401
    created = register(client)
    assert created.status_code == 201
    protected = client.get(path)
    assert protected.status_code == 200
    assert protected.get_json()["user_id"] == created.get_json()["user"]["id"]


def test_registration_validation_and_duplicate_email(auth_client):
    client, _ = auth_client
    assert register(client, "bad", "a long password 123").status_code == 400
    assert register(client, "person@example.org", "short").status_code == 400
    assert register(client, "person@example.org", "a long password 123", " ").status_code == 400
    limiter.reset()
    assert register(client, display_name="").status_code == 400
    limiter.reset()
    assert register(client).status_code == 201
    assert register(client, "PERSON@example.org").status_code == 409
    assert client.post("/api/auth/register", data="[]", content_type="application/json", headers={"Origin": ORIGIN}).status_code == 400


def test_login_generic_failure_and_successful_cookie_session(auth_client):
    client, _ = auth_client
    register(client)
    client.post("/api/auth/logout", headers={"Origin": ORIGIN})
    absent = post_auth(client, "/api/auth/login", {"email": "nobody@example.org", "password": "wrong"})
    wrong = post_auth(client, "/api/auth/login", {"email": "person@example.org", "password": "wrong"})
    assert (absent.status_code, absent.get_json()) == (401, wrong.get_json())
    success = post_auth(client, "/api/auth/login", {"email": " PERSON@example.org ", "password": "a long password 123"})
    assert success.status_code == 200
    cookie = success.headers["Set-Cookie"]
    assert "Path=/api" in cookie and "HttpOnly" in cookie
    assert "Secure" not in cookie and "SameSite=Lax" in cookie
    assert success.get_json()["user"]["email"] == "person@example.org"
    assert client.get("/api/auth/me").get_json()["user"]["id"] == success.get_json()["user"]["id"]


def test_inactive_user_cannot_login_and_invalid_or_forged_session_is_unauthorized(auth_client):
    client, database = auth_client
    register(client)
    with database.sessions.begin() as session:
        user = session.scalar(select(User))
        user.is_active = False
    client.post("/api/auth/logout", headers={"Origin": ORIGIN})
    assert post_auth(client, "/api/auth/login", {"email": "person@example.org", "password": "a long password 123"}).status_code == 401
    client.set_cookie("sentinelx_session", "forged-token", path="/api/auth")
    assert client.get("/api/auth/me").status_code == 401
    client.set_cookie("X-User-ID", "1")
    assert client.get("/api/auth/me", headers={"X-User-ID": "1", "X-User": "1", "X-Authenticated-User": "1"}).status_code == 401


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_expired_and_revoked_sessions_are_rejected(auth_client, state):
    client, database = auth_client
    register(client)
    with database.sessions.begin() as session:
        record = session.scalar(select(AuthSession))
        if state == "expired":
            record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        else:
            record.revoked_at = datetime.now(timezone.utc)
    assert client.get("/api/auth/me").status_code == 401


def test_logout_revokes_session_and_clears_cookie(auth_client):
    client, database = auth_client
    register(client)
    response = client.post("/api/auth/logout", headers={"Origin": ORIGIN})
    assert response.status_code == 200
    cookie = response.headers["Set-Cookie"]
    assert "Max-Age=0" in cookie and "Path=/api" in cookie
    assert "HttpOnly" in cookie and "Secure" not in cookie and "SameSite=Lax" in cookie
    with database.sessions() as session:
        assert session.scalar(select(AuthSession)).revoked_at is not None
    assert client.get("/api/auth/me").status_code == 401


def test_auth_unsafe_requests_require_trusted_origin_and_cors_is_allowlisted(auth_client):
    client, _ = auth_client
    assert client.post("/api/auth/register", json={}).status_code == 403
    assert client.post("/api/auth/register", json={}, headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.post("/api/auth/login", json={}).status_code == 403
    assert client.post("/api/auth/login", json={}, headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.post("/api/auth/logout").status_code == 403
    assert client.post("/api/auth/logout", headers={"Origin": "https://attacker.example"}).status_code == 403
    allowed = client.options("/api/auth/login", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST"})
    assert allowed.headers.get("Access-Control-Allow-Origin") == ORIGIN
    assert allowed.headers.get("Access-Control-Allow-Credentials") == "true"
    denied = client.options("/api/auth/login", headers={"Origin": "https://attacker.example", "Access-Control-Request-Method": "POST"})
    assert denied.headers.get("Access-Control-Allow-Origin") is None


def test_auth_route_rate_limits(auth_client):
    client, _ = auth_client
    responses = [register(client, email=f"person{i}@example.org") for i in range(4)]
    assert [response.status_code for response in responses] == [201, 201, 201, 429]
    limiter.reset()
    attempts = [post_auth(client, "/api/auth/login", {"email": "missing@example.org", "password": "a long password 123"}) for _ in range(6)]
    assert [response.status_code for response in attempts] == [401, 401, 401, 401, 401, 429]


def test_auth_me_is_limited_to_60_requests_per_minute(auth_client):
    client, _ = auth_client
    assert register(client).status_code == 201

    responses = [client.get("/api/auth/me") for _ in range(61)]

    assert [response.status_code for response in responses[:60]] == [200] * 60
    assert responses[60].status_code == 429
    assert responses[60].get_json() == {
        "success": False,
        "result": "",
        "error": "Rate limit exceeded. Try again later.",
    }


def test_production_cookie_is_secure_and_cross_site(auth_client):
    client, _ = auth_client
    app.config["SESSION_COOKIE_SECURE"] = True
    response = register(client)
    assert response.status_code == 201
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=None" in cookie and "Path=/api" in cookie
    deleted = client.post("/api/auth/logout", headers={"Origin": ORIGIN})
    deletion_cookie = deleted.headers["Set-Cookie"]
    assert "Max-Age=0" in deletion_cookie and "Path=/api" in deletion_cookie
    assert "Secure" in deletion_cookie and "HttpOnly" in deletion_cookie and "SameSite=None" in deletion_cookie


def test_logout_has_its_own_rate_limit(auth_client):
    client, _ = auth_client
    responses = [client.post("/api/auth/logout", headers={"Origin": ORIGIN}) for _ in range(11)]
    assert [response.status_code for response in responses] == [200] * 10 + [429]


def test_deleting_user_cascades_to_server_sessions(auth_client):
    client, database = auth_client
    register(client)
    with database.sessions.begin() as session:
        user = session.scalar(select(User))
        session.delete(user)
    with database.sessions() as session:
        assert session.scalar(select(AuthSession)) is None
