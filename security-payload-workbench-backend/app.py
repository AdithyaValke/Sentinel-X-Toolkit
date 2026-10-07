from flask import Flask, request, jsonify, make_response, g
from flask_cors import CORS
import base64
import urllib.parse
import hashlib
import os
import re
import ipaddress
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.exc import (
    DBAPIError, DisconnectionError, IntegrityError,
    TimeoutError as SQLAlchemyTimeoutError,
)

from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded

from database import create_database, database_url_from_environment
from hash_identifier import analyze_hashes
from models import (
    AuthSession, Investigation, InvestigationEvent, InvestigationEvidence,
    InvestigationFinding, InvestigationIOC, User,
)

CHAIN_MAX_STEPS = 10
CHAIN_MAX_OUTPUT_BYTES = 64 * 1024
IOC_CATEGORIES = {"ip", "domain", "hash", "email"}


def extract_iocs(input_text: str, categories: list[str]) -> list[dict]:
    """Extract potential indicators, retaining defanged spelling and source-line context."""
    found = {}
    lines = input_text.splitlines() or [input_text]

    def add(category, value, line):
        value = value.rstrip(".,;:!?) ]}\"'")
        if not value:
            return
        key = (category, value.casefold())
        if key in found:
            found[key]["occurrences"] += 1
        else:
            found[key] = {"category": category, "value": value, "occurrences": 1, "context": line.strip()[:240]}

    for line in lines:
        occupied = []
        ip_spans = []
        if "ip" in categories:
            # Normalize only the established defanged dot spelling for validation.
            candidate_re = re.compile(r"(?<![\w:])(?:\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:(?:\[\.\]|\.)\d{1,3}){2}(?::\d{1,5})?|[0-9A-Fa-f:]{2,}(?:%[\w.-]+)?)(?![\w:])")
            for match in candidate_re.finditer(line):
                candidate = match.group().replace("[.]", ".")
                if "." in candidate and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", candidate):
                    candidate = candidate.rsplit(":", 1)[0]
                try:
                    address = ipaddress.ip_address(candidate.split("%")[0])
                except ValueError:
                    continue
                display = match.group() if "[.]" in match.group() else str(address)
                add("ip", display, line)
                ip_spans.append(match.span())
        if "email" in categories:
            email_re = re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+(?:@|\[@\])[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:(?:\.|\[\.\])[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+", re.I)
            for match in email_re.finditer(line):
                add("email", match.group(), line)
                occupied.append(match.span())
        if "domain" in categories:
            # URLs include their path; defanged scheme and dot notation are preserved verbatim.
            url_re = re.compile(r"(?i)(?:https?://|hxxps?://)[^\s<>\"']+")
            domain_re = re.compile(r"(?i)(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\[\.\]|\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:(?:\[\.\]|\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*(?![\w-])")
            url_spans = []
            for match in url_re.finditer(line):
                value = match.group().rstrip(".,;:!?) ]}")
                authority = re.split(r"[/?#]", re.sub(r"(?i)^(?:https?|hxxps?)://", "", value), maxsplit=1)[0].rsplit("@", 1)[-1]
                host = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
                try:
                    ipaddress.ip_address(host.replace("[.]", ".").strip("[]"))
                    url_host_is_ip = True
                except ValueError:
                    url_host_is_ip = False
                if not url_host_is_ip:
                    add("domain", value, line)
                url_spans.append(match.span())
            for match in domain_re.finditer(line):
                if any(start <= match.start() < end for start, end in url_spans) or any(start <= match.start() < end for start, end in occupied) or any(start <= match.start() < end for start, end in ip_spans):
                    continue
                # Numeric dotted quads belong to the IP validator, not domains.
                if re.fullmatch(r"\d+(?:\.\d+){3}", match.group().replace("[.]", ".")):
                    continue
                add("domain", match.group(), line)
        if "hash" in categories:
            for match in re.finditer(r"(?<![\w])[A-Fa-f0-9]{128}(?![\w])|(?<![\w])[A-Fa-f0-9]{64}(?![\w])|(?<![\w])[A-Fa-f0-9]{40}(?![\w])|(?<![\w])[A-Fa-f0-9]{32}(?![\w])", line):
                add("hash", match.group(), line)
    return sorted(found.values(), key=lambda item: (item["category"], item["value"].casefold()))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024


def _safe_api_error(message):
    if request.path == "/api/extract-iocs":
        return jsonify({"success": False, "results": [], "summary": {}, "error": message})
    return jsonify({"success": False, "result": "", "error": message})


def _rate_limit_configuration(environment):
    is_render = bool(environment.get("RENDER"))
    storage_uri = environment.get("RATE_LIMIT_STORAGE_URI")
    if is_render and not storage_uri:
        raise RuntimeError("RATE_LIMIT_STORAGE_URI must be configured in production")
    if is_render and urllib.parse.urlsplit(storage_uri).scheme not in {"redis", "rediss", "redis+cluster"}:
        raise RuntimeError("RATE_LIMIT_STORAGE_URI must use a shared Redis-compatible scheme in production")
    limit = _positive_int_setting_from(environment, "API_RATE_LIMIT_PER_MINUTE", "60")
    return is_render, storage_uri, limit


def _positive_int_setting_from(environment, name: str, default: str) -> int:
    value = environment.get(name, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"{name} must be a positive integer") from error
    if parsed < 1:
        raise RuntimeError(f"{name} must be a positive integer")
    return parsed


_is_render, _rate_limit_storage, _rate_limit = _rate_limit_configuration(os.environ)
app.config["API_RATE_LIMIT_PER_MINUTE"] = _rate_limit
app.config["TRUST_CLOUDFLARE_CLIENT_IP"] = os.environ.get("TRUST_CLOUDFLARE_CLIENT_IP", "").lower() == "true"
# Engine construction is lazy: with no configured URL, stateless tools still start
# and database-backed routes report service unavailable when requested.
_database_url = database_url_from_environment(required=False)
app.extensions["database"] = create_database(_database_url) if _database_url else None


class DatabaseUnavailable(Exception):
    """A database-dependent operation cannot run because storage is unavailable."""


def _is_database_unavailable(error):
    if isinstance(error, (DatabaseUnavailable, DisconnectionError, SQLAlchemyTimeoutError)):
        return True
    if not isinstance(error, DBAPIError):
        return False
    if isinstance(error, DBAPIError) and error.connection_invalidated:
        return True

    cause = getattr(error, "orig", error)
    state = getattr(cause, "sqlstate", None) or getattr(cause, "pgcode", None)
    if isinstance(state, str) and (state.startswith("08") or state in {"28P01", "3D000", "57P01", "57P02", "57P03"}):
        return True
    error_number = getattr(cause, "errno", None)
    if error_number is None and getattr(cause, "args", None) and isinstance(cause.args[0], int):
        error_number = cause.args[0]
    if error_number in {32, 54, 57, 60, 61, 101, 104, 110, 111, 113, 10051, 10053, 10054, 10060, 10061, 10065}:
        return True
    message = str(cause).lower()
    return any(phrase in message for phrase in (
        "connection refused", "connection reset", "connection timed out",
        "could not connect", "could not translate host name", "server closed the connection",
        "terminating connection", "connection is closed", "timeout expired",
    ))


class ClientIpUnavailable(Exception):
    """Raised when the trusted deployment proxy does not provide a usable client IP."""


def verified_client_ip() -> str:
    # Trust CF-Connecting-IP only when an operator has verified Cloudflare-only origin ingress.
    # This opt-in cannot itself prevent direct-origin spoofing. Never trust X-Forwarded-For.
    if app.config.get("TRUST_CLOUDFLARE_CLIENT_IP", False):
        candidate = request.headers.get("CF-Connecting-IP", "")
        if not candidate or "," in candidate:
            raise ClientIpUnavailable
        try:
            return str(ipaddress.ip_address(candidate.strip()))
        except ValueError as error:
            raise ClientIpUnavailable from error
    # The socket peer is framework-derived; forwarded headers are never trusted by default.
    peer = request.remote_addr
    if peer:
        try:
            return str(ipaddress.ip_address(peer))
        except ValueError:
            return peer
    return "unknown"


def _rate_limit_response(_request_limit):
    response = _safe_api_error("Rate limit exceeded. Try again later.")
    response.status_code = 429
    return response


limiter = Limiter(
    key_func=verified_client_ip,
    app=app,
    storage_uri=_rate_limit_storage or "memory://",
    strategy="moving-window",
    headers_enabled=True,
    swallow_errors=False,
    on_breach=_rate_limit_response,
)


def public_api_rate_limit():
    return limiter.shared_limit(
        lambda: f"{app.config['API_RATE_LIMIT_PER_MINUTE']} per minute",
        scope="public-api",
        methods=["POST"],
    )


def _is_trusted_origin(origin: str, *, require_https: bool = False) -> bool:
    if origin == '*':
        return False
    try:
        parsed = urllib.parse.urlsplit(origin)
        parsed.port  # Accessing port validates its syntax and range.
        return (
            parsed.scheme in {'http', 'https'}
            and (not require_https or parsed.scheme == 'https')
            and bool(parsed.hostname)
            and '*' not in parsed.netloc
            and parsed.path in {'', '/'}
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


# Configure CORS based on environment variable FRONTEND_ORIGIN.
# In development, allow localhost:3000; in production, require explicit origins.
frontend_origin = os.getenv('FRONTEND_ORIGIN')
is_production = bool(os.getenv('RENDER'))
if is_production and not frontend_origin:
    raise RuntimeError("FRONTEND_ORIGIN must be configured in production")
if frontend_origin:
    origins = [o.strip() for o in frontend_origin.split(',') if o.strip()]
else:
    # Default development origin
    origins = ['http://localhost:3000']
if not origins or any(not _is_trusted_origin(origin, require_https=is_production) for origin in origins):
    raise RuntimeError("FRONTEND_ORIGIN must contain explicit HTTP(S) origins without paths or wildcards")
# Credentialed cookies are only emitted for the explicit origin list above.
app.config["AUTH_ORIGINS"] = tuple(origins)
CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)

app.config["SESSION_COOKIE_NAME"] = os.environ.get("SESSION_COOKIE_NAME", "sentinelx_session")
app.config["SESSION_COOKIE_PATH"] = "/api"
app.config["SESSION_LIFETIME_SECONDS"] = _positive_int_setting_from(os.environ, "SESSION_LIFETIME_SECONDS", str(7 * 24 * 60 * 60))
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("RENDER"))
_password_hasher = PasswordHasher(type=Type.ID, time_cost=3, memory_cost=65536, parallelism=2)
# Verify missing users against an Argon2 hash too, reducing login timing differences.
_dummy_password_hash = _password_hasher.hash(secrets.token_urlsafe(32))


def _auth_database():
    database = app.extensions.get("database")
    if database is None:
        raise RuntimeError("Authentication database is unavailable")
    return database


def _safe_user(user):
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "role": user.role}


def _auth_error(message, status):
    return jsonify({"success": False, "error": message}), status


def _trusted_auth_origin():
    return request.headers.get("Origin") in app.config["AUTH_ORIGINS"]


def _session_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _create_auth_session(db_session, user):
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    record = AuthSession(
        user_id=user.id,
        session_token_hash=_session_token_hash(token),
        expires_at=now + timedelta(seconds=app.config["SESSION_LIFETIME_SECONDS"]),
        last_seen_at=now,
    )
    db_session.add(record)
    return token


def get_current_user():
    token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
    if not token or len(token) > 128:
        return None
    database = app.extensions.get("database")
    if database is None:
        raise DatabaseUnavailable
    now = datetime.now(timezone.utc)
    with database.sessions.begin() as db_session:
        record = db_session.scalar(select(AuthSession).where(
            AuthSession.session_token_hash == _session_token_hash(token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        ))
        if record is None or not record.user.is_active:
            return None
        record.last_seen_at = now
        g.auth_session_id = record.id
        g.auth_user = record.user
        return record.user


def require_authentication(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            return _auth_error("Authentication required", 401)
        return view(*args, **kwargs)
    return wrapped


def _set_session_cookie(response, token):
    response.set_cookie(
        app.config["SESSION_COOKIE_NAME"], token,
        max_age=app.config["SESSION_LIFETIME_SECONDS"], httponly=True,
        secure=app.config["SESSION_COOKIE_SECURE"], samesite="None" if app.config["SESSION_COOKIE_SECURE"] else "Lax",
        path=app.config["SESSION_COOKIE_PATH"],
    )
    return response


def _auth_rate_limit(limit):
    return limiter.limit(limit, key_func=verified_client_ip, methods=["POST"])


@app.route("/api/auth/register", methods=["POST"])
@public_api_rate_limit()
@_auth_rate_limit("3 per minute")
def auth_register():
    if not _trusted_auth_origin():
        return _auth_error("Untrusted request origin", 403)
    if not request.is_json:
        return _auth_error("Content-Type must be application/json", 415)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _auth_error("Malformed JSON payload", 400)
    email, password, display_name = data.get("email"), data.get("password"), data.get("display_name")
    if not isinstance(email, str) or not isinstance(password, str) or not isinstance(display_name, str):
        return _auth_error("email, password, and display_name are required", 400)
    email = email.strip().casefold()
    display_name = display_name.strip()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return _auth_error("Enter a valid email address", 400)
    if not 12 <= len(password) <= 256:
        return _auth_error("Password must be between 12 and 256 characters", 400)
    if not display_name or len(display_name) > 80 or any(ord(char) < 32 for char in display_name):
        return _auth_error("Display name must be 1 to 80 characters", 400)
    database = app.extensions.get("database")
    if database is None:
        return _auth_error("Authentication service unavailable", 503)
    try:
        with database.sessions.begin() as db_session:
            if db_session.scalar(select(User.id).where(User.email == email)) is not None:
                return _auth_error("Email is already registered", 409)
            user = User(email=email, password_hash=_password_hasher.hash(password), display_name=display_name)
            db_session.add(user)
            db_session.flush()
            token = _create_auth_session(db_session, user)
    except IntegrityError:
        return _auth_error("Email is already registered", 409)
    response = make_response(jsonify({"success": True, "user": _safe_user(user)}), 201)
    return _set_session_cookie(response, token)


@app.route("/api/auth/login", methods=["POST"])
@public_api_rate_limit()
@_auth_rate_limit("5 per minute")
def auth_login():
    if not _trusted_auth_origin():
        return _auth_error("Untrusted request origin", 403)
    if not request.is_json:
        return _auth_error("Content-Type must be application/json", 415)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("email"), str) or not isinstance(data.get("password"), str):
        return _auth_error("email and password are required", 400)
    database = app.extensions.get("database")
    if database is None:
        return _auth_error("Authentication service unavailable", 503)
    email, password = data["email"].strip().casefold(), data["password"]
    with database.sessions.begin() as db_session:
        user = db_session.scalar(select(User).where(User.email == email))
        valid = False
        try:
            valid = _password_hasher.verify(user.password_hash if user is not None else _dummy_password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid = False
        if not valid or not user.is_active:
            return _auth_error("Invalid email or password", 401)
        token = _create_auth_session(db_session, user)
        safe_user = _safe_user(user)
    response = make_response(jsonify({"success": True, "user": safe_user}))
    return _set_session_cookie(response, token)


@app.route("/api/auth/me", methods=["GET"])
@limiter.limit("60 per minute", key_func=verified_client_ip, methods=["GET"])
def auth_me():
    user = get_current_user()
    if user is None:
        return _auth_error("Authentication required", 401)
    return jsonify({"success": True, "user": _safe_user(user)})


@app.route("/api/auth/logout", methods=["POST"])
@public_api_rate_limit()
@_auth_rate_limit("10 per minute")
def auth_logout():
    if not _trusted_auth_origin():
        return _auth_error("Untrusted request origin", 403)
    token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
    database = app.extensions.get("database")
    if token and database is None:
        return _auth_error("Authentication service unavailable", 503)
    if token and database is not None:
        with database.sessions.begin() as db_session:
            record = db_session.scalar(select(AuthSession).where(AuthSession.session_token_hash == _session_token_hash(token)))
            if record is not None and record.revoked_at is None:
                record.revoked_at = datetime.now(timezone.utc)
    response = make_response(jsonify({"success": True}))
    response.delete_cookie(app.config["SESSION_COOKIE_NAME"], path=app.config["SESSION_COOKIE_PATH"], httponly=True,
                           secure=app.config["SESSION_COOKIE_SECURE"],
                           samesite="None" if app.config["SESSION_COOKIE_SECURE"] else "Lax")
    return response


# Investigation access is opt-in through require_authentication. Existing stateless
# tool routes remain public. All write routes below also enforce trusted Origin.
INVESTIGATION_STATUSES = {"open", "investigating", "resolved", "closed"}
FINDING_SEVERITIES = {"info", "low", "medium", "high", "critical"}
FINDING_STATUSES = {"open", "confirmed", "dismissed", "resolved"}
IOC_TYPES = {"ip", "domain", "hash", "email"}
IOC_SOURCES = {"manual", "extractor", "log_analyzer", "integration"}
SECRET_MARKER_RE = re.compile(
    r"(?i)\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?(?:key|token)|refresh[_-]?token|session[_-]?(?:id|token|cookie)|csrf[_-]?token|private[_-]?key|secret|token|authorization|set-cookie|cookie)\b\s*(?:[:=]\s*)\S+"
)
SESSION_VALUE_RE = re.compile(r"(?i)\b[a-z0-9_-]*(?:session|auth)(?:[_-]cookie)?\s*[:=]\s*\S+")
BEARER_VALUE_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}={0,2}")
JWT_VALUE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I)
CREDENTIAL_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.I)
CLOUD_CREDENTIAL_RE = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b"
)


def _investigation_error(message, status):
    return jsonify({"success": False, "error": message}), status


def _require_trusted_origin(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _trusted_auth_origin():
            return _investigation_error("Untrusted request origin", 403)
        return view(*args, **kwargs)
    return wrapped


def _investigation_read_rate_limit():
    return limiter.limit("60 per minute", key_func=verified_client_ip, methods=["GET"])


def _investigation_write_rate_limit():
    return limiter.limit("20 per minute", key_func=verified_client_ip, methods=["POST", "PATCH", "DELETE"])


def _contains_sensitive_text(value: str) -> bool:
    return bool(
        SECRET_MARKER_RE.search(value)
        or SESSION_VALUE_RE.search(value)
        or BEARER_VALUE_RE.search(value)
        or JWT_VALUE_RE.search(value)
        or PRIVATE_KEY_RE.search(value)
        or CREDENTIAL_URL_RE.search(value)
        or CLOUD_CREDENTIAL_RE.search(value)
    )


def _parse_api_json(allowed_fields):
    if not request.is_json:
        return None, _investigation_error("Content-Type must be application/json", 415)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, _investigation_error("Malformed JSON payload", 400)
    unexpected = set(data) - set(allowed_fields)
    if unexpected:
        return None, _investigation_error(f"Unsupported field: {sorted(unexpected)[0]}", 400)
    return data, None


def _bounded_text(value, field, maximum, *, required=False, allow_null=False):
    if value is None:
        if allow_null and not required:
            return None, None
        return None, f"{field} is required" if required else f"{field} must be a string"
    if not isinstance(value, str):
        return None, f"{field} must be a string"
    value = unicodedata.normalize("NFC", value).strip()
    if required and not value:
        return None, f"{field} is required"
    if len(value) > maximum:
        return None, f"{field} must be at most {maximum} characters"
    if _contains_sensitive_text(value):
        return None, f"{field} appears to contain credentials or authentication material"
    return value, None


def _pagination():
    try:
        limit = int(request.args.get("limit", "20"))
        offset = int(request.args.get("offset", "0"))
    except (TypeError, ValueError):
        return None, _investigation_error("limit and offset must be integers", 400)
    if not 1 <= limit <= 100:
        return None, _investigation_error("limit must be between 1 and 100", 400)
    if not 0 <= offset <= 100000:
        return None, _investigation_error("offset must be between 0 and 100000", 400)
    return (limit, offset), None


def _owned_investigation(db_session, investigation_id, owner_id):
    return db_session.scalar(select(Investigation).where(
        Investigation.id == investigation_id,
        Investigation.owner_id == owner_id,
    ))


def _owned_parent_or_404(db_session, investigation_id, owner_id):
    if _owned_investigation(db_session, investigation_id, owner_id) is None:
        return _investigation_error("Investigation not found", 404)
    return None


def _timestamp(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _serialize_investigation(item):
    return {
        "id": item.id, "title": item.title, "description": item.description, "status": item.status,
        "created_at": _timestamp(item.created_at), "updated_at": _timestamp(item.updated_at),
        "closed_at": _timestamp(item.closed_at),
    }


def _serialize_ioc(item):
    return {
        "id": item.id, "investigation_id": item.investigation_id, "ioc_type": item.ioc_type,
        "value": item.value, "normalized_value": item.normalized_value, "source": item.source,
        "confidence": item.confidence, "first_seen": _timestamp(item.first_seen),
        "last_seen": _timestamp(item.last_seen), "created_at": _timestamp(item.created_at),
    }


def _serialize_finding(item):
    return {
        "id": item.id, "investigation_id": item.investigation_id, "title": item.title,
        "description": item.description, "severity": item.severity, "status": item.status,
        "source": item.source, "created_at": _timestamp(item.created_at), "updated_at": _timestamp(item.updated_at),
    }


def _serialize_evidence(item):
    return {
        "id": item.id, "investigation_id": item.investigation_id, "finding_id": item.finding_id,
        "evidence_type": item.evidence_type, "title": item.title, "content": item.content,
        "source": item.source, "created_at": _timestamp(item.created_at),
    }


def _serialize_event(item):
    return {
        "id": item.id, "investigation_id": item.investigation_id, "event_type": item.event_type,
        "message": item.message, "created_at": _timestamp(item.created_at),
    }


def _validated_page_or_error():
    page, error = _pagination()
    return (None, error) if error else (page, None)


@app.route("/api/investigations", methods=["GET"])
@_investigation_read_rate_limit()
@require_authentication
def list_investigations():
    page, error = _validated_page_or_error()
    if error:
        return error
    limit, offset = page
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions() as db_session:
        query = select(Investigation).where(Investigation.owner_id == g.auth_user.id).order_by(
            Investigation.updated_at.desc(), Investigation.id.desc()
        ).limit(limit).offset(offset)
        items = [_serialize_investigation(item) for item in db_session.scalars(query)]
    return jsonify({"items": items, "limit": limit, "offset": offset})


@app.route("/api/investigations", methods=["POST"])
@public_api_rate_limit()
@_investigation_write_rate_limit()
@require_authentication
@_require_trusted_origin
def create_investigation():
    data, error = _parse_api_json({"title", "description"})
    if error:
        return error
    if "title" not in data:
        return _investigation_error("title is required", 400)
    title, error_message = _bounded_text(data["title"], "title", 200, required=True)
    if error_message:
        return _investigation_error(error_message, 400)
    description = None
    if "description" in data:
        description, error_message = _bounded_text(data["description"], "description", 8000, allow_null=True)
        if error_message:
            return _investigation_error(error_message, 400)
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions.begin() as db_session:
        investigation = Investigation(owner_id=g.auth_user.id, title=title, description=description)
        db_session.add(investigation)
        db_session.flush()
        db_session.add(InvestigationEvent(
            investigation_id=investigation.id, event_type="created", message="Investigation created",
        ))
        result = _serialize_investigation(investigation)
    return jsonify({"item": result}), 201


@app.route("/api/investigations/<int:investigation_id>", methods=["GET"])
@_investigation_read_rate_limit()
@require_authentication
def get_investigation(investigation_id):
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions() as db_session:
        item = _owned_investigation(db_session, investigation_id, g.auth_user.id)
        if item is None:
            return _investigation_error("Investigation not found", 404)
        result = _serialize_investigation(item)
    return jsonify({"item": result})


@app.route("/api/investigations/<int:investigation_id>", methods=["PATCH"])
@_investigation_read_rate_limit()
@_investigation_write_rate_limit()
@require_authentication
@_require_trusted_origin
def update_investigation(investigation_id):
    data, error = _parse_api_json({"title", "description", "status"})
    if error:
        return error
    if not data:
        return _investigation_error("At least one field must be provided", 400)
    title = None
    if "title" in data:
        title, error_message = _bounded_text(data["title"], "title", 200, required=True)
        if error_message:
            return _investigation_error(error_message, 400)
    description = None
    if "description" in data and data["description"] is not None:
        description, error_message = _bounded_text(data["description"], "description", 8000)
        if error_message:
            return _investigation_error(error_message, 400)
    status = data.get("status")
    if "status" in data and (not isinstance(status, str) or status not in INVESTIGATION_STATUSES):
        return _investigation_error("Invalid investigation status", 400)
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions.begin() as db_session:
        item = _owned_investigation(db_session, investigation_id, g.auth_user.id)
        if item is None:
            return _investigation_error("Investigation not found", 404)
        old_status = item.status
        if "title" in data:
            item.title = title
        if "description" in data:
            item.description = description
        if "status" in data:
            item.status = status
            if status in {"resolved", "closed"}:
                if old_status not in {"resolved", "closed"} or item.closed_at is None:
                    item.closed_at = datetime.now(timezone.utc)
            else:
                item.closed_at = None
            if old_status != status:
                db_session.add(InvestigationEvent(
                    investigation_id=item.id, event_type="status_changed",
                    message=f"Status changed from {old_status} to {status}",
                ))
        db_session.flush()
        result = _serialize_investigation(item)
    return jsonify({"item": result})


@app.route("/api/investigations/<int:investigation_id>", methods=["DELETE"])
@_investigation_read_rate_limit()
@_investigation_write_rate_limit()
@require_authentication
@_require_trusted_origin
def delete_investigation(investigation_id):
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions.begin() as db_session:
        item = _owned_investigation(db_session, investigation_id, g.auth_user.id)
        if item is None:
            return _investigation_error("Investigation not found", 404)
        db_session.delete(item)
    return "", 204


def _normalize_ioc(ioc_type, value):
    if ioc_type == "ip":
        return str(ipaddress.ip_address(value))
    if ioc_type == "hash":
        return value.lower()
    if ioc_type == "email":
        return value.casefold()
    normalized = value.casefold().replace("[.]", ".").rstrip(".")
    try:
        labels = normalized.encode("idna").decode("ascii").split(".")
    except UnicodeError as error:
        raise ValueError("invalid domain") from error
    ascii_domain = ".".join(labels)
    if len(labels) < 2 or len(ascii_domain) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
    ):
        raise ValueError("invalid domain")
    return ascii_domain


def _validate_ioc_value(ioc_type, value):
    if not isinstance(ioc_type, str) or ioc_type not in IOC_TYPES:
        return None, "ioc_type must be one of: domain, email, hash, ip"
    if not isinstance(value, str):
        return None, "value must be a string"
    value = value.strip()
    if not value or len(value) > 2048:
        return None, "value must be between 1 and 2048 characters"
    if _contains_sensitive_text(value):
        return None, "value appears to contain credentials or authentication material"
    try:
        if ioc_type == "hash":
            if not re.fullmatch(r"(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})", value):
                return None, "hash value must be a supported hexadecimal digest"
        elif ioc_type == "email" and (len(value) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value)):
            return None, "value is not a valid email address"
        normalized = _normalize_ioc(ioc_type, value)
    except ValueError:
        return None, "value does not match ioc_type"
    return normalized, None


def _list_child_records(investigation_id, model, serializer, order_by):
    page, error = _pagination()
    if error:
        return error
    limit, offset = page
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions() as db_session:
        parent = _owned_investigation(db_session, investigation_id, g.auth_user.id)
        if parent is None:
            return _investigation_error("Investigation not found", 404)
        query = select(model).where(model.investigation_id == investigation_id).order_by(*order_by).limit(limit).offset(offset)
        items = [serializer(row) for row in db_session.scalars(query)]
    return jsonify({"items": items, "limit": limit, "offset": offset})


def _create_child(investigation_id, model, serializer, event_type, event_message, values):
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions.begin() as db_session:
        parent = _owned_investigation(db_session, investigation_id, g.auth_user.id)
        if parent is None:
            return _investigation_error("Investigation not found", 404)
        record = model(investigation_id=investigation_id, **values)
        db_session.add(record)
        db_session.flush()
        db_session.add(InvestigationEvent(
            investigation_id=investigation_id, event_type=event_type, message=event_message,
        ))
        result = serializer(record)
    return jsonify({"item": result}), 201


@app.route("/api/investigations/<int:investigation_id>/iocs", methods=["GET"])
@_investigation_read_rate_limit()
@require_authentication
def list_investigation_iocs(investigation_id):
    return _list_child_records(
        investigation_id, InvestigationIOC, _serialize_ioc,
        [InvestigationIOC.created_at.desc(), InvestigationIOC.id.desc()],
    )


@app.route("/api/investigations/<int:investigation_id>/iocs", methods=["POST"])
@public_api_rate_limit()
@_investigation_write_rate_limit()
@require_authentication
@_require_trusted_origin
def create_investigation_ioc(investigation_id):
    data, error = _parse_api_json({"ioc_type", "value", "normalized_value", "source", "confidence", "first_seen", "last_seen"})
    if error:
        return error
    ioc_type, value = data.get("ioc_type"), data.get("value")
    normalized_default, error_message = _validate_ioc_value(ioc_type, value)
    if error_message:
        return _investigation_error(error_message, 400)
    normalized = normalized_default
    if "normalized_value" in data and data["normalized_value"] is not None:
        supplied_normalized, error_message = _bounded_text(data["normalized_value"], "normalized_value", 2048, required=True)
        if error_message:
            return _investigation_error(error_message, 400)
        try:
            supplied_normalized = _normalize_ioc(ioc_type, supplied_normalized)
        except ValueError:
            return _investigation_error("normalized_value does not match ioc_type", 400)
        if supplied_normalized != normalized_default:
            return _investigation_error("normalized_value must match the normalized value of value", 400)
    source = data.get("source", "manual")
    if not isinstance(source, str) or source not in IOC_SOURCES:
        return _investigation_error("Invalid IOC source", 400)
    confidence = data.get("confidence")
    if confidence is not None and (isinstance(confidence, bool) or not isinstance(confidence, int) or not 0 <= confidence <= 100):
        return _investigation_error("confidence must be an integer between 0 and 100", 400)
    datetime_values = {}
    for field in ("first_seen", "last_seen"):
        raw = data.get(field)
        if raw is None:
            datetime_values[field] = None
        elif not isinstance(raw, str):
            return _investigation_error(f"{field} must be an ISO-8601 timestamp", 400)
        else:
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return _investigation_error(f"{field} must be an ISO-8601 timestamp", 400)
            if parsed.tzinfo is None:
                return _investigation_error(f"{field} must include a timezone", 400)
            datetime_values[field] = parsed.astimezone(timezone.utc)
    first_seen, last_seen = datetime_values["first_seen"], datetime_values["last_seen"]
    if first_seen and last_seen and last_seen < first_seen:
        return _investigation_error("last_seen cannot precede first_seen", 400)
    return _create_child(
        investigation_id, InvestigationIOC, _serialize_ioc, "ioc_added", f"IOC added ({ioc_type})",
        {"ioc_type": ioc_type, "value": value.strip(), "normalized_value": normalized,
         "source": source, "confidence": confidence, **datetime_values},
    )


@app.route("/api/investigations/<int:investigation_id>/findings", methods=["GET"])
@_investigation_read_rate_limit()
@require_authentication
def list_investigation_findings(investigation_id):
    return _list_child_records(
        investigation_id, InvestigationFinding, _serialize_finding,
        [InvestigationFinding.updated_at.desc(), InvestigationFinding.id.desc()],
    )


@app.route("/api/investigations/<int:investigation_id>/findings", methods=["POST"])
@public_api_rate_limit()
@_investigation_write_rate_limit()
@require_authentication
@_require_trusted_origin
def create_investigation_finding(investigation_id):
    data, error = _parse_api_json({"title", "description", "severity", "status", "source"})
    if error:
        return error
    if "title" not in data:
        return _investigation_error("title is required", 400)
    title, message = _bounded_text(data["title"], "title", 200, required=True)
    if message:
        return _investigation_error(message, 400)
    description = None
    if data.get("description") is not None:
        description, message = _bounded_text(data["description"], "description", 8000)
        if message:
            return _investigation_error(message, 400)
    severity, status = data.get("severity", "info"), data.get("status", "open")
    if not isinstance(severity, str) or severity not in FINDING_SEVERITIES:
        return _investigation_error("Invalid finding severity", 400)
    if not isinstance(status, str) or status not in FINDING_STATUSES:
        return _investigation_error("Invalid finding status", 400)
    source = data.get("source")
    if source is not None:
        source, message = _bounded_text(source, "source", 32, required=True)
        if message:
            return _investigation_error(message, 400)
    return _create_child(
        investigation_id, InvestigationFinding, _serialize_finding, "finding_created", "Finding created",
        {"title": title, "description": description, "severity": severity, "status": status, "source": source},
    )


@app.route("/api/investigations/<int:investigation_id>/evidence", methods=["GET"])
@_investigation_read_rate_limit()
@require_authentication
def list_investigation_evidence(investigation_id):
    return _list_child_records(
        investigation_id, InvestigationEvidence, _serialize_evidence,
        [InvestigationEvidence.created_at.desc(), InvestigationEvidence.id.desc()],
    )


@app.route("/api/investigations/<int:investigation_id>/evidence", methods=["POST"])
@public_api_rate_limit()
@_investigation_write_rate_limit()
@require_authentication
@_require_trusted_origin
def create_investigation_evidence(investigation_id):
    data, error = _parse_api_json({"finding_id", "evidence_type", "title", "content", "source"})
    if error:
        return error
    for field in ("evidence_type", "title", "content"):
        if field not in data:
            return _investigation_error(f"{field} is required", 400)
    evidence_type, message = _bounded_text(data["evidence_type"], "evidence_type", 32, required=True)
    if message or not re.fullmatch(r"[a-z][a-z0-9_]*", evidence_type or ""):
        return _investigation_error(message or "evidence_type has an invalid format", 400)
    title, message = _bounded_text(data["title"], "title", 200, required=True)
    if message:
        return _investigation_error(message, 400)
    content, message = _bounded_text(data["content"], "content", 8000, required=True)
    if message:
        return _investigation_error(message, 400)
    source = data.get("source")
    if source is not None:
        source, message = _bounded_text(source, "source", 32, required=True)
        if message:
            return _investigation_error(message, 400)
    finding_id = data.get("finding_id")
    if finding_id is not None and (isinstance(finding_id, bool) or not isinstance(finding_id, int) or finding_id < 1):
        return _investigation_error("finding_id must be a positive integer or null", 400)
    database = app.extensions.get("database")
    if database is None:
        return _investigation_error("Investigation service unavailable", 503)
    with database.sessions.begin() as db_session:
        parent = _owned_investigation(db_session, investigation_id, g.auth_user.id)
        if parent is None:
            return _investigation_error("Investigation not found", 404)
        if finding_id is not None:
            finding = db_session.scalar(select(InvestigationFinding.id).where(
                InvestigationFinding.id == finding_id,
                InvestigationFinding.investigation_id == investigation_id,
            ))
            if finding is None:
                return _investigation_error("finding_id must reference a finding in this investigation", 400)
        record = InvestigationEvidence(
            investigation_id=investigation_id, finding_id=finding_id, evidence_type=evidence_type,
            title=title, content=content, source=source,
        )
        db_session.add(record)
        db_session.flush()
        db_session.add(InvestigationEvent(
            investigation_id=investigation_id, event_type="evidence_added", message="Evidence added",
        ))
        result = _serialize_evidence(record)
    return jsonify({"item": result}), 201


@app.route("/api/investigations/<int:investigation_id>/timeline", methods=["GET"])
@_investigation_read_rate_limit()
@require_authentication
def list_investigation_timeline(investigation_id):
    return _list_child_records(
        investigation_id, InvestigationEvent, _serialize_event,
        [InvestigationEvent.created_at.desc(), InvestigationEvent.id.desc()],
    )


@app.after_request
def security_response_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def encode_base64(text: str) -> str:
    """Encode a UTF‑8 string to Base64."""
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def decode_base64(b64_text: str):
    """Decode a Base64 string to UTF‑8.
    Returns a tuple (success: bool, result: str, error: str | None).
    """
    try:
        decoded_bytes = base64.b64decode(b64_text, validate=True)
        return True, decoded_bytes.decode("utf-8"), None
    except Exception as e:
        return False, "", str(e)


def encode_url(text: str) -> str:
    """URL‑encode a string using percent‑encoding."""
    return urllib.parse.quote(text)


def decode_url(encoded: str) -> str:
    """Decode a percent‑encoded URL string."""
    return urllib.parse.unquote(encoded)


def encode_hex(text: str) -> str:
    """Convert a UTF‑8 string to its hexadecimal representation."""
    return text.encode("utf-8").hex()


def decode_hex(hex_str: str):
    """Decode a hexadecimal string back to UTF‑8.
    Returns a tuple (success, result, error).
    """
    try:
        decoded_bytes = bytes.fromhex(hex_str)
        return True, decoded_bytes.decode("utf-8"), None
    except ValueError as e:
        return False, "", str(e)


HASH_ALGORITHMS = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha512224": "sha512_224",
    "sha512256": "sha512_256",
    "sha3224": "sha3_224",
    "sha3256": "sha3_256",
    "sha3384": "sha3_384",
    "sha3512": "sha3_512",
    "shake128": "shake_128",
    "shake256": "shake_256",
}
SHAKE_OUTPUT_BYTES = 32


def hash_text(text: str, algorithm: str):
    """Hash UTF-8 text using a supported hashlib algorithm.

    Algorithm names are case-insensitive; whitespace, hyphens, and slashes
    are ignored. SHAKE algorithms use a fixed 32-byte output.
    Returns a tuple (success, result, error).
    """
    algo = re.sub(r"[\s/-]", "", algorithm).lower()
    hashlib_name = HASH_ALGORITHMS.get(algo)
    if hashlib_name is None:
        return False, "", f"Unsupported hash algorithm: {algorithm}"
    try:
        digest = hashlib.new(hashlib_name, text.encode("utf-8"))
        result = digest.hexdigest(SHAKE_OUTPUT_BYTES) if algo.startswith("shake") else digest.hexdigest()
        return True, result, None
    except (TypeError, ValueError):
        return False, "", "Unable to hash input with the requested algorithm"


CHAIN_OPERATIONS = {
    "base64_encode": encode_base64,
    "base64_decode": decode_base64,
    "url_encode": encode_url,
    "url_decode": decode_url,
    "hex_encode": encode_hex,
    "hex_decode": decode_hex,
}


def _chain_error(message):
    return jsonify({"success": False, "result": "", "error": message}), 400


@app.route('/api/chain', methods=['POST'])
@public_api_rate_limit()
def chain():
    if not request.is_json:
        return jsonify({"success": False, "result": "", "error": "Content-Type must be application/json"}), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "result": "", "error": "Malformed JSON payload"}), 400
    if not isinstance(data.get("input_text"), str):
        return _chain_error("'input_text' must be provided as a string")
    steps = data.get("steps")
    if not isinstance(steps, list):
        return _chain_error("'steps' must be a list")
    if not steps:
        return _chain_error("'steps' must contain at least one operation")
    if len(steps) > CHAIN_MAX_STEPS:
        return _chain_error(f"'steps' must contain at most {CHAIN_MAX_STEPS} operations")

    for step in steps:
        if not isinstance(step, dict) or set(step) != {"operation"} or not isinstance(step.get("operation"), str):
            return _chain_error("Each step must contain only an 'operation' string")
        if step["operation"] not in CHAIN_OPERATIONS:
            return _chain_error("A step contains an unsupported operation")

    current = data["input_text"]
    results = []
    for index, step in enumerate(steps):
        operation = step["operation"]
        try:
            transformed = CHAIN_OPERATIONS[operation](current)
            if operation in {"base64_decode", "hex_decode"}:
                success, output, _error = transformed
                if not success:
                    return jsonify({"success": False, "result": "", "error": f"Step {index} failed", "steps": results, "failed_step": index}), 400
            else:
                output = transformed
            if len(output.encode("utf-8")) > CHAIN_MAX_OUTPUT_BYTES:
                return jsonify({"success": False, "result": "", "error": f"Step {index} output exceeded the 64KB limit", "steps": results, "failed_step": index}), 400
        except Exception:
            return jsonify({"success": False, "result": "", "error": f"Step {index} failed", "steps": results, "failed_step": index}), 400
        current = output
        results.append({"operation": operation, "output": output})
    return jsonify({"steps": results, "final": current})


@app.route('/api/process', methods=['POST'])
@public_api_rate_limit()
def process():
    if not request.is_json:
        return jsonify({"success": False, "result": "", "error": "Content-Type must be application/json"}), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "result": "", "error": "Malformed JSON payload"}), 400
    input_text = data.get('input_text')
    operation = data.get('operation')
    hash_algorithm = data.get('hash_algorithm')
    # Validate required fields
    if not isinstance(input_text, str) or not isinstance(operation, str):
        return jsonify({"success": False, "result": "", "error": "'input_text' and 'operation' must be provided as strings"}), 400
    # Validate supported operations early
    supported_ops = {
        'base64_encode',
        'base64_decode',
        'url_encode',
        'url_decode',
        'hex_encode',
        'hex_decode',
        'hash',
        'identify_hash',
    }
    if operation not in supported_ops:
        return jsonify({"success": False, "result": "", "error": f"Unsupported operation: {operation}"}), 400
    # For hashing, ensure hash_algorithm is present and normalized later in hash_text
    if operation == 'hash' and not isinstance(hash_algorithm, str):
        return jsonify({"success": False, "result": "", "error": "'hash_algorithm' must be provided for hashing operations"}), 400
    if operation == 'base64_encode':
        result = encode_base64(input_text)
        return jsonify({"success": True, "result": result, "error": None})
    elif operation == 'base64_decode':
        success, result, err = decode_base64(input_text)
        return jsonify({"success": success, "result": result, "error": err}), (200 if success else 400)
    elif operation == 'url_encode':
        result = encode_url(input_text)
        return jsonify({"success": True, "result": result, "error": None})
    elif operation == 'url_decode':
        result = decode_url(input_text)
        return jsonify({"success": True, "result": result, "error": None})
    elif operation == 'hex_encode':
        result = encode_hex(input_text)
        return jsonify({"success": True, "result": result, "error": None})
    elif operation == 'hex_decode':
        success, result, err = decode_hex(input_text)
        return jsonify({"success": success, "result": result, "error": err}), (200 if success else 400)
    elif operation == 'hash':
        success, result, err = hash_text(input_text, hash_algorithm)
        return jsonify({"success": success, "result": result, "error": err}), (200 if success else 400)
    elif operation == 'identify_hash':
        stripped = input_text.strip()
        if not stripped:
            return jsonify({
                "success": False,
                "result": "",
                "error": "Input text cannot be empty for hash identification",
            }), 400
        try:
            analysis = analyze_hashes(input_text)
            return jsonify({
                "success": True,
                "result": analysis["result"],
                "error": None,
                "input_length": analysis["input_length"],
                "character_format": analysis["character_format"],
                "candidates": analysis["candidates"],
                "is_ambiguous": analysis["is_ambiguous"],
                "warning": analysis["warning"],
                "recommendation": analysis["recommendation"],
                "lines": analysis.get("lines", []),
            })
        except ValueError as e:
            return jsonify({
                "success": False,
                "result": "",
                "error": str(e),
            }), 400
    else:
        return jsonify({
            "success": False,
            "result": "",
            "error": f"Unsupported operation: {operation}"
        }), 400


@app.route('/api/identify-hash', methods=['POST'])
@public_api_rate_limit()
def identify_hash_endpoint():
    """Dedicated endpoint for hash identification and candidate analysis."""
    if not request.is_json:
        return jsonify({"success": False, "result": "", "error": "Content-Type must be application/json"}), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "result": "", "error": "Malformed JSON payload"}), 400
    input_text = data.get('hash')
    if input_text is None:
        input_text = data.get('input_text')
    if not isinstance(input_text, str):
        return jsonify({"success": False, "result": "", "error": "'hash' or 'input_text' must be provided as a string"}), 400
    stripped = input_text.strip()
    if not stripped:
        return jsonify({"success": False, "result": "", "error": "Input text cannot be empty for hash identification"}), 400
    try:
        analysis = analyze_hashes(input_text)
        return jsonify(analysis)
    except ValueError as e:
        return jsonify({"success": False, "result": "", "error": str(e)}), 400


@app.route('/api/extract-iocs', methods=['POST'])
@public_api_rate_limit()
def extract_iocs_endpoint():
    if not request.is_json:
        return jsonify({"success": False, "results": [], "summary": {}, "error": "Content-Type must be application/json"}), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "results": [], "summary": {}, "error": "Malformed JSON payload"}), 400
    input_text, categories = data.get("input_text"), data.get("categories")
    if not isinstance(input_text, str):
        return jsonify({"success": False, "results": [], "summary": {}, "error": "'input_text' must be provided as a string"}), 400
    if not input_text.strip():
        return jsonify({"success": False, "results": [], "summary": {}, "error": "Input text cannot be empty"}), 400
    if not isinstance(categories, list) or not categories or any(not isinstance(item, str) for item in categories):
        return jsonify({"success": False, "results": [], "summary": {}, "error": "'categories' must be a non-empty array of category identifiers"}), 400
    if any(item not in IOC_CATEGORIES for item in categories):
        return jsonify({"success": False, "results": [], "summary": {}, "error": "Unsupported category"}), 400
    results = extract_iocs(input_text, list(dict.fromkeys(categories)))
    counts = {category: sum(item["occurrences"] for item in results if item["category"] == category) for category in sorted(IOC_CATEGORIES)}
    return jsonify({"success": True, "results": results, "summary": {"unique": len(results), "occurrences": sum(item["occurrences"] for item in results), "by_category": counts}, "error": None})


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


@app.errorhandler(413)
def request_too_large(_error):
    if request.path == "/api/extract-iocs":
        return jsonify({"success": False, "results": [], "summary": {}, "error": "Payload too large (max 10KB)"}), 413
    return jsonify({"success": False, "result": "", "error": "Payload too large (max 10KB)"}), 413


@app.errorhandler(ClientIpUnavailable)
def client_ip_unavailable(_error):
    return _safe_api_error("Unable to verify client IP"), 503


@app.errorhandler(RateLimitExceeded)
def rate_limit_exceeded(error):
    # Preserve Flask-Limiter headers while guaranteeing the public JSON error shape.
    response = error.get_response() or _rate_limit_response(None)
    response.set_data(app.json.dumps(_safe_api_error("Rate limit exceeded. Try again later.").get_json()))
    response.content_type = "application/json"
    response.status_code = 429
    return response


@app.errorhandler(Exception)
def storage_or_unexpected_error(error):
    # A limiter storage outage must never silently disable request limiting.
    from limits.errors import StorageError

    if isinstance(error, StorageError):
        app.logger.error("Rate-limit storage is unavailable")
        return _safe_api_error("Request protection is temporarily unavailable"), 503
    if _is_database_unavailable(error):
        app.logger.warning("Database service is unavailable (%s)", type(error).__name__)
        if request.path.startswith("/api/auth/"):
            return _auth_error("Authentication service unavailable", 503)
        if request.path.startswith("/api/investigations"):
            return _investigation_error("Investigation service unavailable", 503)
        return _safe_api_error("Database service unavailable"), 503
    app.logger.error("Unhandled request error (%s)", type(error).__name__)
    return _safe_api_error("Internal server error"), 500


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"success": False, "result": "", "error": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"success": False, "result": "", "error": "Method not allowed"}), 405


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
