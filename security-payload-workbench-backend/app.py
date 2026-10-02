from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import urllib.parse
import hashlib
import os

app = Flask(__name__)
# Allow CORS for the specified origins
CORS(app, resources={r"/*": {"origins": os.getenv('FRONTEND_ORIGIN', '*')}})


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
    Supported algorithms: md5, sha256, sha512.
    Returns a tuple (success, result, error).
    """
    algo = algorithm.lower()
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
    except Exception as e:
        return False, "", str(e)

@app.route('/api/process', methods=['POST'])
def process():
    if request.content_length is not None and request.content_length > 10 * 1024:
        return jsonify({"success": False, "result": "", "error": "Payload too large (max 10KB)"}), 413
    data = request.get_json(silent=True) or {}
    input_text = data.get('input_text')
    operation = data.get('operation')
    hash_algorithm = data.get('hash_algorithm')

    if not isinstance(input_text, str) or not isinstance(operation, str):
        return jsonify({
            "success": False,
            "result": "",
            "error": "'input_text' and 'operation' must be provided as strings"
        })

    if operation == 'base64_encode':
        result = encode_base64(input_text)
        return jsonify({"success": True, "result": result, "error": None})
    elif operation == 'base64_decode':
        success, result, err = decode_base64(input_text)
        return jsonify({"success": success, "result": result, "error": err})
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
        return jsonify({"success": success, "result": result, "error": err})
    elif operation == 'hash':
        if not isinstance(hash_algorithm, str):
            return jsonify({"success": False, "result": "", "error": "'hash_algorithm' must be provided for hashing operations"})
        success, result, err = hash_text(input_text, hash_algorithm)
        return jsonify({"success": success, "result": result, "error": err})
    else:
        return jsonify({
            "success": False,
            "result": "",
            "error": f"Unsupported operation: {operation}"
        })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
