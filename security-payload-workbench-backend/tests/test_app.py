import hashlib

import pytest

from app import app, limiter, _is_trusted_origin, _rate_limit_configuration


@pytest.fixture
def client():
    app.testing = True
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 60
    app.config["TRUST_RENDER_CLOUDFLARE_IP"] = False
    limiter.reset()
    with app.test_client() as test_client:
        yield test_client
    limiter.reset()


def post_process(client, operation, input_text, hash_algorithm=None):
    payload = {"input_text": input_text, "operation": operation}
    if hash_algorithm is not None:
        payload["hash_algorithm"] = hash_algorithm
    return client.post("/api/process", json=payload)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_extract_iocs_categories_context_and_counts(client):
    text = "Alert from 192.0.2.8 and 2001:db8::1\nvisit hxxps://bad[.]example/path and bad[.]example\ncontact ops@example.org\n" + "a"*32 + " " + "b"*40 + " " + "c"*64 + " " + "d"*128 + "\n192.0.2.8"
    response = client.post('/api/extract-iocs', json={"input_text": text, "categories": ["ip", "domain", "hash", "email"]})
    assert response.status_code == 200
    data = response.get_json()
    by_value = {item["value"]: item for item in data["results"]}
    assert by_value["192.0.2.8"]["occurrences"] == 2
    assert by_value["2001:db8::1"]["category"] == "ip"
    assert by_value["hxxps://bad[.]example/path"]["category"] == "domain"
    assert by_value["bad[.]example"]["category"] == "domain"
    assert by_value["ops@example.org"]["context"].startswith("contact")
    assert {len(value) for value in by_value if set(value) <= set('abcd')} >= {32, 40, 64, 128}
    only = client.post('/api/extract-iocs', json={"input_text": "192.0.2.2 host.example", "categories": ["domain"]}).get_json()
    assert [row["category"] for row in only["results"]] == ["domain"]


@pytest.mark.parametrize(("value", "category"), [
    ("192.0.2.1", "ip"),
    ("192[.]0[.]2[.]1", "ip"),
    ("hxxps://192.0.2.1/path", "ip"),
    ("10[.]0[.]0[.]15", "ip"),
    ("2001:db8::1", "ip"),
    ("backup-c2[.]net", "domain"),
    ("evil-c2[.]com", "domain"),
    ("hxxps://malicious[.]example[.]com/payload.exe", "domain"),
    ("attacker[@]example[.]com", "email"),
    ("backup-c2-01.example.net", "domain"),
    ("999[.]999[.]999[.]999", None),
])
def test_ioc_defanged_classification_is_exclusive(client, value, category):
    response = client.post('/api/extract-iocs', json={"input_text": value, "categories": ["ip", "domain", "email"]})
    assert response.status_code == 200
    results = response.get_json()["results"]
    assert [row["category"] for row in results] == ([category] if category else [])
    if category:
        expected_value = "192.0.2.1" if value == "hxxps://192.0.2.1/path" else value
        assert results[0]["value"] == expected_value


def test_defanged_ip_and_email_do_not_leak_into_domain_results(client):
    text = "192[.]0[.]2[.]1 192.0.2.1 attacker[@]example[.]com backup-c2[.]net"
    results = client.post('/api/extract-iocs', json={"input_text": text, "categories": ["ip", "domain", "email"]}).get_json()["results"]
    by_category = {}
    for row in results:
        by_category.setdefault(row["category"], []).append(row)
    assert [row["value"] for row in by_category["ip"]] == ["192.0.2.1", "192[.]0[.]2[.]1"]
    assert [row["value"] for row in by_category["email"]] == ["attacker[@]example[.]com"]
    assert [row["value"] for row in by_category["domain"]] == ["backup-c2[.]net"]
    assert all(row["context"] == text for row in results)


def test_hash_occurrences_and_context_are_preserved(client):
    digest = "a" * 32
    response = client.post('/api/extract-iocs', json={"input_text": f"sample {digest}\nrepeat {digest}", "categories": ["hash"]})
    assert response.status_code == 200
    assert response.get_json()["results"] == [{"category": "hash", "value": digest, "occurrences": 2, "context": f"sample {digest}"}]


@pytest.mark.parametrize(("payload", "status"), [
    ({"input_text": "  ", "categories": ["ip"]}, 400),
    ({"input_text": "x"}, 400),
    ({"input_text": 7, "categories": ["ip"]}, 400),
    ({"input_text": "x", "categories": "ip"}, 400),
    ({"input_text": "x", "categories": ["bad"]}, 400),
])
def test_extract_iocs_validation(client, payload, status):
    assert client.post('/api/extract-iocs', json=payload).status_code == status


def test_extract_iocs_malformed_empty_no_match_invalid_indicators_and_limits(client):
    assert client.post('/api/extract-iocs', data="{", content_type="application/json").status_code == 400
    assert client.post('/api/extract-iocs', json={"input_text": "none", "categories": ["ip"]}).get_json()["results"] == []
    data = client.post('/api/extract-iocs', json={"input_text": "999.1.1.1 12345678901234567890123456789012x", "categories": ["ip", "hash"]}).get_json()
    assert data["results"] == []
    assert client.post('/api/extract-iocs', json={"input_text": "x"*11000, "categories": ["ip"]}).status_code == 413


def test_extract_iocs_security_headers_and_rate_limit_share(client):
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 1
    response = client.post('/api/extract-iocs', json={"input_text": "none", "categories": ["ip"]})
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert client.post('/api/extract-iocs', json={"input_text": "none", "categories": ["ip"]}).status_code == 429


def test_chain_valid_two_and_ten_steps(client):
    response = client.post("/api/chain", json={"input_text": "hello world", "steps": [
        {"operation": "url_encode"}, {"operation": "base64_encode"},
    ]})
    assert response.status_code == 200
    assert response.get_json() == {"steps": [
        {"operation": "url_encode", "output": "hello%20world"},
        {"operation": "base64_encode", "output": "aGVsbG8lMjB3b3JsZA=="},
    ], "final": "aGVsbG8lMjB3b3JsZA=="}
    ten = client.post("/api/chain", json={"input_text": "x", "steps": [{"operation": "url_encode"}] * 10})
    assert ten.status_code == 200
    assert len(ten.get_json()["steps"]) == 10


@pytest.mark.parametrize(("payload", "fragment"), [
    ({"input_text": "x", "steps": []}, "at least one"),
    ({"input_text": "x", "steps": [{"operation": "url_encode"}] * 11}, "at most"),
    ({"input_text": "x", "steps": [{"operation": "nope"}]}, "unsupported"),
    ({"input_text": "x", "steps": [{"operation": "identify_hash"}]}, "unsupported"),
    ({"input_text": "x", "steps": "url_encode"}, "list"),
    ({"input_text": 7, "steps": [{"operation": "url_encode"}]}, "string"),
    ({"input_text": "x", "steps": ["url_encode"]}, "string"),
    ({"input_text": "x", "steps": [{"operation": "url_encode", "extra": 1}]}, "string"),
])
def test_chain_validation(client, payload, fragment):
    response = client.post("/api/chain", json=payload)
    assert response.status_code == 400
    assert set(response.get_json()) == {"success", "result", "error"}
    assert fragment in response.get_json()["error"]
    assert "traceback" not in response.get_data(as_text=True).lower()


def test_chain_mid_failure_and_output_amplification(client):
    failed = client.post("/api/chain", json={"input_text": "%%%", "steps": [
        {"operation": "url_encode"}, {"operation": "base64_decode"},
    ]})
    assert failed.status_code == 400
    assert "Step 1" in failed.get_json()["error"]
    assert "traceback" not in failed.get_data(as_text=True).lower()
    amplified = client.post("/api/chain", json={"input_text": "a" * 9000, "steps": [
        {"operation": "hex_encode"}, {"operation": "hex_encode"}, {"operation": "hex_encode"},
    ]})
    assert amplified.status_code == 400
    assert "Step 2" in amplified.get_json()["error"]


def test_chain_request_limits_and_rate_limit(client):
    assert client.post("/api/chain", data="{}", content_type="text/plain").status_code == 415
    assert client.post("/api/chain", data='{"input_text":"' + ('x' * (11 * 1024)) + '"}', content_type="application/json").status_code == 413
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 1
    payload = {"input_text": "x", "steps": [{"operation": "url_encode"}]}
    assert client.post("/api/chain", json=payload).status_code == 200
    limited = client.post("/api/chain", json=payload)
    assert limited.status_code == 429
    assert "traceback" not in limited.get_data(as_text=True).lower()


def test_api_security_headers(client):
    response = post_process(client, "base64_encode", "hello")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_render_client_ip_trust_fails_closed_without_header_and_accepts_valid_ip(client):
    app.config["TRUST_RENDER_CLOUDFLARE_IP"] = True
    missing = post_process(client, "base64_encode", "hello")
    assert missing.status_code == 503
    assert missing.get_json() == {"success": False, "result": "", "error": "Unable to verify client IP"}

    accepted = client.post(
        "/api/process",
        json={"input_text": "hello", "operation": "base64_encode"},
        headers={"CF-Connecting-IP": "203.0.113.10"},
    )
    assert accepted.status_code == 200


@pytest.mark.parametrize("origin", ["https://payload-workbench.vercel.app", "http://localhost:3000", "https://example.org/"])
def test_explicit_cors_origins_are_accepted(origin):
    assert _is_trusted_origin(origin)


@pytest.mark.parametrize("origin", ["*", "https://*.example.org", "https://example.org/path", "https://user:pass@example.org", "https://example.org:bad", "file:///tmp"])
def test_wildcard_and_non_origin_cors_values_are_rejected(origin):
    assert not _is_trusted_origin(origin)


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
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert response.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "Content-Type" in response.headers["Access-Control-Allow-Headers"]
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


def test_identify_hash_line_limit(client):
    fifty_lines = "\n".join(["a" * 32] * 50)
    fifty_one_lines = "\n".join(["a" * 32] * 51)
    requests = [
        ("/api/process", {"input_text": fifty_lines, "operation": "identify_hash"}, 200),
        ("/api/identify-hash", {"hash": fifty_lines}, 200),
        ("/api/process", {"input_text": fifty_one_lines, "operation": "identify_hash"}, 400),
        ("/api/identify-hash", {"hash": fifty_one_lines}, 400),
    ]
    for path, payload, expected_status in requests:
        response = client.post(path, json=payload)
        assert response.status_code == expected_status
        if expected_status == 400:
            assert response.get_json() == {
                "success": False,
                "result": "",
                "error": "Hash identification accepts at most 50 non-empty lines",
            }
        else:
            assert response.get_json()["success"] is True


def test_hash_converter_and_identify_hash_coexist_independently(client):
    """Regression Test: Verify Hash Converter ('hash' operation) and Identify Hash Function

    ('identify_hash' operation) work independently without intercepting or conflicting.
    """
    raw_text = "secure_test_payload"

    # 1. Generate hash via Hash Converter (operation: 'hash')
    conv_response = post_process(client, "hash", raw_text, "SHA-256")
    assert conv_response.status_code == 200
    conv_data = conv_response.get_json()
    assert conv_data["success"] is True
    generated_hash = conv_data["result"]
    assert len(generated_hash) == 64
    assert generated_hash == hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    # 2. Identify candidate algorithms via Identify Hash Function (operation: 'identify_hash')
    id_response = post_process(client, "identify_hash", generated_hash)
    assert id_response.status_code == 200
    id_data = id_response.get_json()
    assert id_data["success"] is True
    assert id_data["input_length"] == 64
    assert id_data["character_format"] == "hexadecimal"
    assert any(c["algorithm"] == "SHA-256" for c in id_data["candidates"])

    # 3. Verify Hash Converter MD5 and SHA-512 remain fully functional
    md5_resp = post_process(client, "hash", raw_text, "MD5")
    assert md5_resp.status_code == 200
    assert md5_resp.get_json()["result"] == hashlib.md5(raw_text.encode("utf-8")).hexdigest()

    sha512_resp = post_process(client, "hash", raw_text, "SHA-512")
    assert sha512_resp.status_code == 200
    assert sha512_resp.get_json()["result"] == hashlib.sha512(raw_text.encode("utf-8")).hexdigest()


def test_rate_limit_threshold_shared_between_endpoints_and_429_shape(client):
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 2
    assert post_process(client, "base64_encode", "one").status_code == 200
    assert client.post("/api/identify-hash", json={"hash": "5d41402abc4b2a76b9719d911017c592"}).status_code == 200

    limited = post_process(client, "base64_encode", "three")
    assert limited.status_code == 429
    assert limited.get_json() == {
        "success": False,
        "result": "",
        "error": "Rate limit exceeded. Try again later.",
    }
    assert "Retry-After" in limited.headers


def test_moving_window_storage_supports_memory_and_redis_uris():
    from limits.storage import storage_from_string
    from limits.strategies import MovingWindowRateLimiter

    assert isinstance(limiter.limiter, MovingWindowRateLimiter)
    for uri in ("memory://", "redis://localhost:6379/0"):
        storage = storage_from_string(uri)
        assert callable(storage.get_moving_window)
        assert callable(storage.acquire_entry)


def test_rate_limit_resets_after_window_with_controlled_clock(client, monkeypatch):
    import limits.storage.memory

    now = [600.0]
    monkeypatch.setattr(limits.storage.memory.time, "time", lambda: now[0])
    limiter.reset()
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 1
    assert post_process(client, "base64_encode", "one").status_code == 200
    assert post_process(client, "base64_encode", "two").status_code == 429

    now[0] = 661.0
    assert post_process(client, "base64_encode", "after window").status_code == 200


def test_moving_window_enforces_limit_across_fixed_window_boundary(client, monkeypatch):
    import limits.storage.memory

    now = [659.9]
    monkeypatch.setattr(limits.storage.memory.time, "time", lambda: now[0])
    limiter.reset()
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 1
    assert post_process(client, "base64_encode", "before boundary").status_code == 200

    now[0] = 660.1
    assert post_process(client, "base64_encode", "after boundary").status_code == 429


def test_render_ip_uses_only_cloudflare_header_and_rejects_bad_values(client):
    app.config["TRUST_RENDER_CLOUDFLARE_IP"] = True
    app.config["API_RATE_LIMIT_PER_MINUTE"] = 1
    first = client.post(
        "/api/process",
        json={"input_text": "one", "operation": "base64_encode"},
        headers={"CF-Connecting-IP": "198.51.100.12", "X-Forwarded-For": "203.0.113.99"},
    )
    limited = client.post(
        "/api/process",
        json={"input_text": "two", "operation": "base64_encode"},
        headers={"CF-Connecting-IP": "198.51.100.12", "X-Forwarded-For": "192.0.2.4"},
    )
    other = client.post(
        "/api/process",
        json={"input_text": "three", "operation": "base64_encode"},
        headers={"CF-Connecting-IP": "198.51.100.13", "X-Forwarded-For": "198.51.100.12"},
    )
    assert first.status_code == 200
    assert limited.status_code == 429
    assert other.status_code == 200

    for malformed in ("", "garbage", "198.51.100.1, 203.0.113.1"):
        response = client.post(
            "/api/process",
            json={"input_text": "x", "operation": "base64_encode"},
            headers={"CF-Connecting-IP": malformed, "X-Forwarded-For": "198.51.100.55"},
        )
        assert response.status_code == 503
        assert response.get_json()["error"] == "Unable to verify client IP"


def test_render_rate_limit_requires_redis_and_valid_limit_configuration():
    with pytest.raises(RuntimeError, match="RATE_LIMIT_STORAGE_URI"):
        _rate_limit_configuration({"RENDER": "true"})
    with pytest.raises(RuntimeError, match="shared Redis-compatible"):
        _rate_limit_configuration({"RENDER": "true", "RATE_LIMIT_STORAGE_URI": "memory://"})
    assert _rate_limit_configuration({"RENDER": "true", "RATE_LIMIT_STORAGE_URI": "redis://private/0"}) == (
        True, "redis://private/0", 60
    )
    assert _rate_limit_configuration({}) == (False, None, 60)
    with pytest.raises(RuntimeError, match="positive integer"):
        _rate_limit_configuration({"API_RATE_LIMIT_PER_MINUTE": "0"})


def test_limiter_storage_failure_fails_closed_with_safe_503(client, monkeypatch):
    from limits.errors import StorageError

    def unavailable(*_args, **_kwargs):
        raise StorageError("private storage connection detail")

    monkeypatch.setattr(limiter.storage, "acquire_entry", unavailable)
    response = post_process(client, "base64_encode", "input")
    assert response.status_code == 503
    assert response.get_json() == {
        "success": False,
        "result": "",
        "error": "Request protection is temporarily unavailable",
    }
    assert "private storage connection detail" not in response.get_data(as_text=True)

