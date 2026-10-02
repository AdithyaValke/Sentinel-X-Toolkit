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
