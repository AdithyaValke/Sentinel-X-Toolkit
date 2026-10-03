from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import urllib.parse
import hashlib
import os
import re

from hash_identifier import analyze_hashes

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024
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
CORS(app, resources={r"/*": {"origins": origins}})


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


@app.route('/api/process', methods=['POST'])
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


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"success": False, "result": "", "error": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"success": False, "result": "", "error": "Method not allowed"}), 405


@app.errorhandler(Exception)
def unexpected_error(_error):
    app.logger.exception("Unhandled request error")
    return jsonify({"success": False, "result": "", "error": "Internal server error"}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
