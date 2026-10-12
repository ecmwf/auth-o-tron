"""Self-contained JWT, protected-resource, PKCE and callback regression tests."""

import asyncio
import base64
import hashlib
import json
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import client
from client import CallbackError, authorization_url, exchange_code, parse_callback
from demo_settings import (
    CALLBACK,
    CLIENT_ID,
    LOCAL_SETTINGS,
    MAX_JSON_BYTES,
    RESOURCE,
    ROLE,
    SCOPE,
    endpoints,
    load_settings,
    local_tls_context,
)
from server import MAX_TOKEN_BYTES, JWTVerifier, create_server

ISSUER = LOCAL_SETTINGS["issuer"]
JWKS_URI = LOCAL_SETTINGS["jwks_uri"]
TOKEN_ENDPOINT = endpoints(ISSUER)["token_endpoint"]


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(key):
    parameters = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {
        "kty": "RSA",
        "n": parameters["n"],
        "e": parameters["e"],
        "kid": "test-key",
        "alg": "RS256",
        "use": "sig",
    }


def claims():
    now = int(time.time())
    return {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "synthetic-subject",
        "jti": "synthetic-id",
        "client_id": CLIENT_ID,
        "iat": now - 2,
        "exp": now + 120,
        "scope": SCOPE,
        "roles": [ROLE],
    }


def sign(key, payload=None, headers=None):
    return jwt.encode(
        claims() if payload is None else payload,
        key,
        algorithm="RS256",
        headers={"kid": "test-key", "typ": "at+jwt", **(headers or {})},
    )


def verifier_for(key, document=None):
    requests = []

    def handle(request):
        requests.append(request)
        assert str(request.url) == JWKS_URI
        assert request.method == "GET"
        return httpx.Response(
            200, json=document if document is not None else {"keys": [public_jwk(key)]}
        )

    verifier = JWTVerifier(
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        LOCAL_SETTINGS,
        transport=httpx.MockTransport(handle),
    )
    return verifier, requests


def test_valid_token_and_bounded_jwks_cache(signing_key):
    verifier, requests = verifier_for(signing_key)
    token = sign(signing_key)

    async def check():
        result = await verifier.verify_token(token)
        assert result is not None
        assert result.resource == RESOURCE and result.scopes == [SCOPE]
        assert result.client_id == CLIENT_ID
        assert await verifier.verify_token(sign(signing_key, headers={"kid": "unknown"})) is None
        assert await verifier.verify_token(token) is not None

    asyncio.run(check())
    assert len(requests) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"iss": ISSUER.rstrip("/")},
        {"aud": "https://127.0.0.1:8444/other"},
        {"aud": [RESOURCE]},
        {"exp": 1},
        {"iat": int(time.time()) + 600},
        {"nbf": int(time.time()) + 600},
        {"exp": "9999999999"},
        {"exp": float("inf")},
        {"iat": float("nan")},
        {"iat": True},
        {"nbf": "0"},
        {"client_id": "other-client"},
        {"sub": ""},
        {"jti": []},
        {"scope": [SCOPE]},
        {"scope": SCOPE + " " + SCOPE},
        {"scope": SCOPE + "\tother"},
        # Local settings require ROLE, so an empty or reader-less list is rejected.
        {"roles": []},
        {"roles": "reader"},
        {"roles": ["admin"]},
        {"roles": [ROLE, 1]},
        {"exp": int(time.time()) + 7200},
    ],
)
def test_invalid_claims(signing_key, change):
    verifier, _ = verifier_for(signing_key)
    assert asyncio.run(verifier.verify_token(sign(signing_key, {**claims(), **change}))) is None


@pytest.mark.parametrize(
    "missing", ["iss", "aud", "exp", "iat", "sub", "jti", "client_id", "scope", "roles"]
)
def test_mandatory_claims(signing_key, missing):
    payload = claims()
    del payload[missing]
    verifier, _ = verifier_for(signing_key)
    assert asyncio.run(verifier.verify_token(sign(signing_key, payload))) is None


@pytest.mark.parametrize(
    "headers",
    [
        {"typ": "JWT"},
        {"typ": "AT+JWT"},
        {"kid": "unknown"},
        {"jku": "https://attacker.invalid/keys"},
        {"x5u": "https://attacker.invalid/cert"},
        {"jwk": {"kty": "RSA"}},
        {"crit": ["exp"]},
        {"kid": 123},
    ],
)
def test_untrusted_headers(signing_key, headers):
    verifier, requests = verifier_for(signing_key)
    if headers == {"kid": 123}:
        # PyJWT's encoder also rejects this; construct the malformed header explicitly.
        parts = sign(signing_key).split(".")
        parts[0] = jwt.utils.base64url_encode(
            json.dumps({"alg": "RS256", "typ": "at+jwt", **headers}).encode()
        ).decode()
        token = ".".join(parts)
    else:
        token = sign(signing_key, headers=headers)
    assert asyncio.run(verifier.verify_token(token)) is None
    assert len(requests) <= 1


def test_algorithm_signature_and_token_bounds(signing_key):
    verifier, _ = verifier_for(signing_key)
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tokens = [
        sign(wrong_key),
        jwt.encode(
            claims(),
            "synthetic-hmac-secret-at-least-32-bytes",
            algorithm="HS256",
            headers={"typ": "at+jwt", "kid": "test-key"},
        ),
        jwt.encode(claims(), None, algorithm="none", headers={"typ": "at+jwt", "kid": "test-key"}),
        "x" * (MAX_TOKEN_BYTES + 1),
        "not.a.jwt",
        "",
        "a.b.c\n",
    ]

    async def check():
        for token in tokens:
            assert await verifier.verify_token(token) is None

    asyncio.run(check())


def test_duplicate_jwt_fields(signing_key):
    parts = sign(signing_key).split(".")
    parts[1] = jwt.utils.base64url_encode(b'{"iss":"first","iss":"second"}').decode()
    verifier, requests = verifier_for(signing_key)
    assert asyncio.run(verifier.verify_token(".".join(parts))) is None
    assert not requests


@pytest.mark.parametrize(
    "problem", ["duplicate", "private", "algorithm", "empty", "too-many", "small-key"]
)
def test_bad_jwks(signing_key, problem):
    entry = public_jwk(signing_key)
    entries = [entry]
    if problem == "duplicate":
        entries *= 2
    elif problem == "private":
        entry["d"] = "private-not-allowed"
    elif problem == "algorithm":
        entry["alg"] = "HS256"
    elif problem == "empty":
        entries = []
    elif problem == "too-many":
        entries *= 9
    elif problem == "small-key":
        entries = [public_jwk(rsa.generate_private_key(public_exponent=65537, key_size=1024))]
    verifier, _ = verifier_for(signing_key, {"keys": entries})
    assert asyncio.run(verifier.verify_token(sign(signing_key))) is None


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://attacker.invalid/keys"}),
        httpx.Response(
            200, content=b"x" * (MAX_JSON_BYTES + 1), headers={"content-type": "application/json"}
        ),
        httpx.Response(
            200, content=b'{"keys":[],"keys":[]}', headers={"content-type": "application/json"}
        ),
        httpx.Response(200, text="not JSON"),
        httpx.Response(
            200,
            content=b"",
            headers={"content-type": "application/json", "content-encoding": "gzip"},
        ),
        httpx.Response(503),
    ],
)
def test_jwks_retrieval_fails_closed_and_retries_are_bounded(signing_key, response):
    calls = []

    def handle(request):
        calls.append(str(request.url))
        return response

    verifier = JWTVerifier(
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        LOCAL_SETTINGS,
        transport=httpx.MockTransport(handle),
    )

    async def check():
        assert await verifier.verify_token(sign(signing_key)) is None
        assert await verifier.verify_token(sign(signing_key)) is None

    asyncio.run(check())
    assert calls == [JWKS_URI]


def test_sdk_protection_metadata_and_real_tool_call(signing_key, capsys):
    verifier, _ = verifier_for(signing_key)
    mcp = create_server(verifier)
    app = mcp.streamable_http_app()

    async def check():
        async with (
            mcp.session_manager.run(),
            httpx.AsyncClient(transport=httpx.ASGITransport(app), trust_env=False) as http,
        ):
            missing = await http.post(RESOURCE)
            assert missing.status_code == 401
            assert (
                'resource_metadata="https://127.0.0.1:8444/.well-known/oauth-protected-resource/mcp"'
                in missing.headers["www-authenticate"]
            )
            invalid = await http.post(RESOURCE, headers={"Authorization": "Bearer invalid"})
            assert invalid.status_code == 401
            metadata = await http.get(
                "https://127.0.0.1:8444/.well-known/oauth-protected-resource/mcp"
            )
            assert metadata.status_code == 200
            body = metadata.json()
            assert body["resource"] == RESOURCE
            assert body["authorization_servers"] == [ISSUER]
            assert body["scopes_supported"] == [SCOPE]
            no_scope = sign(signing_key, {**claims(), "scope": "other:read"})
            forbidden = await http.post(RESOURCE, headers={"Authorization": "Bearer " + no_scope})
            assert forbidden.status_code == 403
            http.headers["Authorization"] = "Bearer " + sign(signing_key)
            await client.call_demo(http)

    asyncio.run(check())
    assert "synthetic tool call succeeded" in capsys.readouterr().out


def callback_query(**changes):
    return "/callback?" + urlencode(
        {"code": "synthetic-code", "state": "test-state", "iss": ISSUER, **changes}
    )


def test_callback_success_denial_and_pkce():
    assert parse_callback(callback_query(), "test-state", ISSUER) == "synthetic-code"
    assert (
        parse_callback(
            "/callback?"
            + urlencode({"error": "access_denied", "state": "test-state", "iss": ISSUER}),
            "test-state",
            ISSUER,
        )
        is None
    )
    verifier = "A" * 43
    url = urlsplit(authorization_url("test-state", verifier, ISSUER))
    query = parse_qs(url.query)
    assert url.scheme == "https" and url.netloc == "127.0.0.1:8443"
    assert query["redirect_uri"] == [CALLBACK]
    assert query["resource"] == [RESOURCE] and query["scope"] == [SCOPE]
    assert query["client_id"] == [CLIENT_ID] and query["state"] == ["test-state"]
    assert query["code_challenge_method"] == ["S256"]
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert query["code_challenge"] == [expected]
    assert "code_verifier" not in query


@pytest.mark.parametrize(
    "target",
    [
        callback_query(state="other"),
        callback_query(iss=ISSUER.rstrip("/")),
        callback_query() + "&state=test-state",
        callback_query() + "&code=second",
        callback_query() + "&iss=" + ISSUER,
        callback_query() + "&error=access_denied",
        callback_query() + "&unknown=x",
        callback_query(code=""),
        callback_query(code="x y"),
        callback_query(code="x\n"),
        callback_query(code="x" * 2049),
        callback_query(code="%ZZ").replace("%25", "%"),
        callback_query() + "#fragment",
        callback_query() + "#",
        callback_query().replace("/callback?", "/other?"),
        "http://127.0.0.1:49152" + callback_query(),
        "/callback?code=x&state=test-state",
        "/callback?code=x&state=test-state&iss=%FF",
        "/callback?code=x&state&iss=x",
        "/callback?" + "x" * 8192,
        "/callback?error=server_error&state=test-state&iss=" + ISSUER,
    ],
)
def test_callback_rejects_invalid_queries(target):
    with pytest.raises(CallbackError):
        parse_callback(target, "test-state", ISSUER)


def test_listener_binds_before_authorize_and_invalid_request_does_not_consume(monkeypatch, capsys):
    test_port = 0

    class TestServer(HTTPServer):
        def __init__(self, address, handler):
            nonlocal test_port
            assert address == ("127.0.0.1", 49152)
            super().__init__(("127.0.0.1", test_port), handler)
            test_port = self.server_port

    monkeypatch.setattr(client, "HTTPServer", TestServer)
    with client.CallbackListener("test-state", ISSUER) as listener:
        with pytest.raises(OSError):
            client.CallbackListener("other-state", ISSUER)
        results = []
        thread = threading.Thread(target=lambda: results.append(listener.wait_for_code(3)))
        thread.start()
        base = f"http://127.0.0.1:{listener.server.server_port}"
        try:
            with httpx.Client(trust_env=False, timeout=2) as http:
                assert http.get(base + callback_query()).status_code == 400
                assert (
                    http.get(
                        base + callback_query(state="wrong"), headers={"Host": "127.0.0.1:49152"}
                    ).status_code
                    == 400
                )
                assert not listener.completed
                valid = http.get(base + callback_query(), headers={"Host": "127.0.0.1:49152"})
                assert valid.status_code == 200
                assert valid.headers["cache-control"] == "no-store"
                assert "synthetic-code" not in valid.text
        finally:
            thread.join(timeout=4)
        assert not thread.is_alive()
        assert results == ["synthetic-code"]
    with client.CallbackListener("fresh-state", ISSUER) as restarted:
        with pytest.raises(CallbackError, match="timed out"):
            restarted.wait_for_code(timeout=0)
        restarted.completed = True
        with pytest.raises(CallbackError, match="denied"):
            restarted.wait_for_code(timeout=0)
    assert "synthetic-code" not in capsys.readouterr().err


def test_token_exchange_exact_bindings(signing_key):
    token = sign(signing_key)

    def handle(request):
        assert request.method == "POST" and str(request.url) == TOKEN_ENDPOINT
        assert "authorization" not in request.headers and "cookie" not in request.headers
        assert parse_qs(request.content.decode()) == {
            "grant_type": ["authorization_code"],
            "client_id": [CLIENT_ID],
            "code": ["synthetic-code"],
            "redirect_uri": [CALLBACK],
            "resource": [RESOURCE],
            "code_verifier": ["A" * 43],
        }
        return httpx.Response(
            200,
            json={"access_token": token, "token_type": "Bearer", "scope": SCOPE, "expires_in": 120},
        )

    async def check():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handle), trust_env=False
        ) as http:
            assert await exchange_code(http, "synthetic-code", "A" * 43, ISSUER) == token

    asyncio.run(check())


@pytest.mark.parametrize(
    "change",
    [
        {"token_type": "Basic"},
        {"scope": "other"},
        {"expires_in": True},
        {"expires_in": 7200},
        {"access_token": "x\r\nInjected: bad"},
        {"access_token": "x" * (MAX_TOKEN_BYTES + 1)},
    ],
)
def test_bad_token_responses(change):
    response = {
        "access_token": "a.b.c",
        "token_type": "Bearer",
        "scope": SCOPE,
        "expires_in": 120,
        **change,
    }

    async def check():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
            trust_env=False,
        ) as http:
            with pytest.raises(ValueError):
                await exchange_code(http, "synthetic-code", "A" * 43, ISSUER)

    asyncio.run(check())


def test_explicit_ca_and_public_settings(tmp_path, signing_key, monkeypatch):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable test CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(signing_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(signing_key, hashes.SHA256())
    )
    (tmp_path / "tls-ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("SSL_CERT_FILE", "/does-not-exist")
    monkeypatch.setenv("HTTPS_PROXY", "http://does-not-exist.invalid:1")
    context = local_tls_context(tmp_path)
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert context.cert_store_stats()["x509_ca"] == 1
    settings = {
        "issuer": ISSUER,
        "resource": RESOURCE,
        "callback": CALLBACK,
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "required_role": ROLE,
        "jwks_uri": JWKS_URI,
    }
    (tmp_path / "settings.json").write_text(json.dumps(settings))
    assert load_settings(tmp_path) == settings
    settings["issuer"] = ISSUER.rstrip("/")
    (tmp_path / "settings.json").write_text(json.dumps(settings))
    with pytest.raises(ValueError):
        load_settings(tmp_path)
