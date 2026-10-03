import hashlib

import pytest

from app import app


@pytest.fixture
def client():
    app.testing = True
    app.config["PROPAGATE_EXCEPTIONS"] = False
    with app.test_client() as test_client:
        yield test_client


def post_process(client, operation, input_text, hash_algorithm=None):
    payload = {"input_text": input_text, "operation": operation}
    if hash_algorithm is not None:
        payload["hash_algorithm"] = hash_algorithm
    return client.post("/api/process", json=payload)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


@pytest.mark.parametrize(("operation", "source", "expected"), [
    ("base64_encode", "hello", "aGVsbG8="),
    ("base64_decode", "aGVsbG8=", "hello"),
    ("url_encode", "hello world!", "hello%20world%21"),
    ("url_decode", "hello%20world%21", "hello world!"),
    ("hex_encode", "hello", "68656c6c6f"),
    ("hex_decode", "68656c6c6f", "hello"),
    ("base64_encode", "", ""),
    ("hex_encode", "snowman ☃", "736e6f776d616e20e29883"),
    ("url_encode", "snowman ☃", "snowman%20%E2%98%83"),
])
def test_operations(client, operation, source, expected):
    response = post_process(client, operation, source)
    assert response.status_code == 200
    assert response.get_json() == {"success": True, "result": expected, "error": None}


@pytest.mark.parametrize(("algorithm", "expected"), [
    ("MD5", hashlib.md5(b"hello").hexdigest()),
    ("SHA-256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    ("SHA-512", hashlib.sha512(b"hello").hexdigest()),
])
def test_hash_vectors(client, algorithm, expected):
    response = post_process(client, "hash", "hello", algorithm)
    assert response.status_code == 200
    assert response.get_json() == {"success": True, "result": expected, "error": None}


def test_hash_normalization_and_invalid_algorithm(client):
    assert post_process(client, "hash", "hello", " sha-256 ").get_json()["success"]
    response = post_process(client, "hash", "hello", "sha1")
    assert response.status_code == 400
    assert response.get_json()["success"] is False


@pytest.mark.parametrize("operation,input_text", [("base64_decode", "%%%"), ("hex_decode", "xyz"), ("hex_decode", "ff")])
def test_invalid_encoded_data(client, operation, input_text):
    response = post_process(client, operation, input_text)
    assert response.status_code == 400
    assert response.get_json()["success"] is False
    assert response.get_json()["result"] == ""


def test_invalid_operation_and_missing_fields(client):
    assert post_process(client, "nope", "data").status_code == 400
    response = client.post("/api/process", json={"input_text": "missing operation"})
    assert response.status_code == 400
    assert set(response.get_json()) == {"success", "result", "error"}


def test_json_and_content_type_validation(client):
    assert client.post("/api/process", data="{", content_type="application/json").status_code == 400
    assert client.post("/api/process", data="{}", content_type="text/plain").status_code == 415
    assert client.post("/api/process", json=[]).status_code == 400


def test_oversized_payload(client):
    response = post_process(client, "base64_encode", "a" * (11 * 1024))
    assert response.status_code == 413
    assert "traceback" not in response.get_data(as_text=True).lower()


def test_cors_and_http_errors(client):
    response = client.options(
        "/api/process",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"},
    )
    assert response.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    rejected = client.options(
        "/api/process",
        headers={"Origin": "https://untrusted.example", "Access-Control-Request-Method": "POST"},
    )
    assert "Access-Control-Allow-Origin" not in rejected.headers
    assert client.get("/api/process").status_code == 405
    assert client.get("/does-not-exist").status_code == 404


def test_unexpected_error_does_not_leak_details(client, monkeypatch):
    def explode(_text):
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr("app.encode_base64", explode)
    response = post_process(client, "base64_encode", "anything")
    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"
    assert "sensitive internal detail" not in response.get_data(as_text=True)


# ============================================================================
# Identify Hash Tests
# ============================================================================

def test_identify_hash_32_char_hex_ambiguous(client):
    """Test Case 1 & 14: 32-character hex digest matches MD5, NTLM, MD4, and LM."""
    h = "5d41402abc4b2a76b9719d911017c592"
    response = post_process(client, "identify_hash", h)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"] == "Matches: MD5 (Hashcat: 0), NTLM (Hashcat: 1000), or MD4 (Hashcat: 900)"
    assert data["input_length"] == 32
    assert data["character_format"] == "hexadecimal"
    assert data["is_ambiguous"] is True
    assert "cannot definitively identify" in data["warning"]
    candidate_algos = [c["algorithm"] for c in data["candidates"]]
    assert "MD5" in candidate_algos
    assert "NTLM" in candidate_algos
    assert "MD4" in candidate_algos
    assert "LM" in candidate_algos


def test_identify_hash_40_char_hex(client):
    """Test Case 2: 40-character hex digest matches SHA-1."""
    h = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    response = post_process(client, "identify_hash", h)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"] == "Matches: SHA-1 (Hashcat: 100)"
    assert data["input_length"] == 40
    assert any(c["algorithm"] == "SHA-1" for c in data["candidates"])


def test_identify_hash_64_char_hex(client):
    """Test Case 3: 64-character hex digest matches SHA-256."""
    h = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    response = post_process(client, "identify_hash", h)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"] == "Matches: SHA-256 (Hashcat: 1400)"
    assert data["input_length"] == 64
    assert any(c["algorithm"] == "SHA-256" for c in data["candidates"])


def test_identify_hash_128_char_hex(client):
    """Test Case 4: 128-character hex digest matches SHA-512."""
    h = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
    response = post_process(client, "identify_hash", h)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"] == "Matches: SHA-512 (Hashcat: 1700)"
    assert data["input_length"] == 128
    assert any(c["algorithm"] == "SHA-512" for c in data["candidates"])


def test_identify_hash_bcrypt_format(client):
    """Test Case 5: Valid bcrypt format with $2a$, $2b$, or $2y$ prefix and length 60."""
    bcrypt_sample = "$2a$12$e8KERg7gm.bQ1qV8q6uP5.9M5M.x2Y7Wv0.qP4P.r8X1V3Z2Y7Wv0"
    response = post_process(client, "identify_hash", bcrypt_sample)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"] == "Matches: bcrypt (Hashcat: 3200)"
    assert data["input_length"] == 60
    assert data["character_format"] == "modular_crypt_bcrypt"
    assert any(c["algorithm"] == "bcrypt" for c in data["candidates"])


def test_identify_hash_argon2_format(client):
    """Test Case 6: Valid Argon2 format."""
    argon2_sample = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPuxWCsUzbsRUhq"
    response = post_process(client, "identify_hash", argon2_sample)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"] == "Matches: Argon2 (Hashcat: 25300)"
    assert data["character_format"] == "modular_crypt_argon2"
    assert any("Argon2" in c["algorithm"] for c in data["candidates"])


def test_identify_hash_unsupported_string(client):
    """Test Case 7: Unsupported string."""
    response = post_process(client, "identify_hash", "not_a_valid_hash_format_xyz_123")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"] == "Unknown Hash Format. Check length and character set."
    assert data["candidates"] == []


def test_identify_hash_empty_input(client):
    """Test Case 8: Empty and whitespace-only input."""
    res_empty = post_process(client, "identify_hash", "")
    assert res_empty.status_code == 400
    assert res_empty.get_json()["success"] is False

    res_spaces = post_process(client, "identify_hash", "   \t\n  ")
    assert res_spaces.status_code == 400
    assert res_spaces.get_json()["success"] is False


def test_identify_hash_invalid_hex_characters(client):
    """Test Case 9: 32 chars but invalid hex chars."""
    bad_hex = "5d41402abc4b2a76b9719d911017c59g"  # ends with 'g'
    response = post_process(client, "identify_hash", bad_hex)
    assert response.status_code == 200
    data = response.get_json()
    assert data["result"] == "Unknown Hash Format. Check length and character set."
    assert data["candidates"] == []


def test_identify_hash_whitespace_trimming(client):
    """Test Case 10: Leading and trailing whitespace should be trimmed."""
    h = "  5d41402abc4b2a76b9719d911017c592 \n\t "
    response = post_process(client, "identify_hash", h)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["input_length"] == 32
    assert "MD5" in [c["algorithm"] for c in data["candidates"]]


def test_identify_hash_uppercase_hex(client):
    """Test Case 11: Uppercase hex characters supported."""
    h = "5D41402ABC4B2A76B9719D911017C592"
    response = post_process(client, "identify_hash", h)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["character_format"] == "hexadecimal"
    assert data["input_length"] == 32
    assert "MD5" in [c["algorithm"] for c in data["candidates"]]


def test_identify_hash_multiple_lines(client):
    """Test Case 12: Multiple lines analyzed independently."""
    multiline = "5d41402abc4b2a76b9719d911017c592\n2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    response = post_process(client, "identify_hash", multiline)
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert len(data["lines"]) == 2
    assert "MD5" in [c["algorithm"] for c in data["lines"][0]["candidates"]]
    assert "SHA-256" in [c["algorithm"] for c in data["lines"][1]["candidates"]]


def test_identify_hash_oversized_input(client):
    """Test Case 13: Oversized input rejected."""
    oversized = "a" * 5000
    response = post_process(client, "identify_hash", oversized)
    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_identify_hash_malformed_prefixed_formats(client):
    """Test Case 15: Malformed prefixed hash formats."""
    # bcrypt prefix but length != 60
    malformed_bcrypt = "$2a$12$short"
    res1 = post_process(client, "identify_hash", malformed_bcrypt)
    assert res1.status_code == 200
    assert res1.get_json()["result"] == "Unknown Hash Format. Check length and character set."

    # Unix prefix with wrong length
    malformed_unix = "$1$toolong"
    res2 = post_process(client, "identify_hash", malformed_unix)
    assert res2.status_code == 200
    assert res2.get_json()["result"] == "Unknown Hash Format. Check length and character set."


def test_identify_hash_other_formats(client):
    """Test additional recognizable formats: CRC32, MySQL, Unix crypt, scrypt."""
    # CRC32: 8 hex chars
    res_crc = post_process(client, "identify_hash", "a1b2c3d4")
    assert res_crc.status_code == 200
    assert any(c["algorithm"] == "CRC32" for c in res_crc.get_json()["candidates"])

    # MySQL 4.1 prefixed: * + 40 hex chars
    res_mysql = post_process(client, "identify_hash", "*" + "a" * 40)
    assert res_mysql.status_code == 200
    assert any("MySQL" in c["algorithm"] for c in res_mysql.get_json()["candidates"])


def test_dedicated_identify_hash_endpoint(client):
    """Test dedicated POST /api/identify-hash route."""
    h = "5d41402abc4b2a76b9719d911017c592"
    # accepts 'hash' key
    res1 = client.post("/api/identify-hash", json={"hash": h})
    assert res1.status_code == 200
    assert res1.get_json()["input_length"] == 32

    # accepts 'input_text' key
    res2 = client.post("/api/identify-hash", json={"input_text": h})
    assert res2.status_code == 200
    assert res2.get_json()["input_length"] == 32

    # rejects missing / invalid
    res_invalid = client.post("/api/identify-hash", json={"hash": ""})
    assert res_invalid.status_code == 400
