from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import urllib.parse
import hashlib
import os
import re
import ipaddress

from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded

from hash_identifier import analyze_hashes

CHAIN_MAX_STEPS = 10
CHAIN_MAX_OUTPUT_BYTES = 64 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024


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


class ClientIpUnavailable(Exception):
    """Raised when the trusted deployment proxy does not provide a usable client IP."""


def verified_client_ip() -> str:
    # Render traffic is assumed to arrive through Cloudflare; only CF-Connecting-IP is trusted there.
    # A missing or invalid value fails closed on rate-limited routes. X-Forwarded-For is never trusted.
    if app.config.get("TRUST_RENDER_CLOUDFLARE_IP", _is_render):
        candidate = request.headers.get("CF-Connecting-IP", "")
        if not candidate or "," in candidate:
            raise ClientIpUnavailable
        try:
            return str(ipaddress.ip_address(candidate.strip()))
        except ValueError as error:
            raise ClientIpUnavailable from error
    # Local/test requests use the socket peer. Forwarded headers are never trusted here.
    return request.remote_addr or "unknown"


def _rate_limit_response(_request_limit):
    response = jsonify({"success": False, "result": "", "error": "Rate limit exceeded. Try again later."})
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


def _is_trusted_origin(origin: str) -> bool:
    if origin == '*':
        return False
    try:
        parsed = urllib.parse.urlsplit(origin)
        parsed.port  # Accessing port validates its syntax and range.
        return (
            parsed.scheme in {'http', 'https'}
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
if os.getenv('RENDER') and not frontend_origin:
    raise RuntimeError("FRONTEND_ORIGIN must be configured in production")
if frontend_origin:
    origins = [o.strip() for o in frontend_origin.split(',') if o.strip()]
else:
    # Default development origin
    origins = ['http://localhost:3000']
if not origins or any(not _is_trusted_origin(origin) for origin in origins):
    raise RuntimeError("FRONTEND_ORIGIN must contain explicit HTTP(S) origins without paths or wildcards")
CORS(app, resources={r"/*": {"origins": origins}})


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


def hash_text(text: str, algorithm: str):
    """Hash the input text using the specified algorithm.
    Supported algorithms: md5, sha256, sha512 (case‑insensitive, hyphens/spaces ignored).
    Returns a tuple (success, result, error)."""
    algo = re.sub(r"[\s-]", "", algorithm).lower()
    try:
        if algo == "md5":
            digest = hashlib.md5(text.encode("utf-8")).hexdigest()
        elif algo == "sha256":
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        elif algo == "sha512":
            digest = hashlib.sha512(text.encode("utf-8")).hexdigest()
        else:
            return False, "", f"Unsupported hash algorithm: {algorithm}"
        return True, digest, None
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


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"success": False, "result": "", "error": "Payload too large (max 10KB)"}), 413


@app.errorhandler(ClientIpUnavailable)
def client_ip_unavailable(_error):
    return jsonify({"success": False, "result": "", "error": "Unable to verify client IP"}), 503


@app.errorhandler(RateLimitExceeded)
def rate_limit_exceeded(error):
    # Preserve Flask-Limiter headers while guaranteeing the public JSON error shape.
    response = error.get_response() or _rate_limit_response(None)
    response.set_data(app.json.dumps({"success": False, "result": "", "error": "Rate limit exceeded. Try again later."}))
    response.content_type = "application/json"
    response.status_code = 429
    return response


@app.errorhandler(Exception)
def storage_or_unexpected_error(error):
    # A limiter storage outage must never silently disable request limiting.
    from limits.errors import StorageError

    if isinstance(error, StorageError):
        app.logger.error("Rate-limit storage is unavailable")
        return jsonify({"success": False, "result": "", "error": "Request protection is temporarily unavailable"}), 503
    app.logger.error("Unhandled request error (%s)", type(error).__name__)
    return jsonify({"success": False, "result": "", "error": "Internal server error"}), 500


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"success": False, "result": "", "error": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"success": False, "result": "", "error": "Method not allowed"}), 405


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
