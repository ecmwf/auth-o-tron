"""Remote-issuer mode: settings contract, endpoint derivation, TLS selection, runner scope."""

import argparse
import asyncio
import json
import ssl
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import client
import demo_settings
import prepare_demo
import run_demo
import server

REMOTE = "https://authotron-playground.lumi.apps.dte.destination-earth.eu/"
HERE = Path(__file__).resolve().parent


def write_settings(path: Path, settings: dict) -> Path:
    (path / "settings.json").write_text(json.dumps(settings))
    return path


@pytest.mark.parametrize("issuer", [REMOTE, "https://issuer.example.org:9443/"])
def test_valid_remote_issuers(issuer):
    assert demo_settings.validate_remote_issuer(issuer) == issuer


@pytest.mark.parametrize(
    "issuer",
    [
        None,
        "",
        REMOTE.rstrip("/"),
        REMOTE.replace("https", "http"),
        REMOTE + "realm/",
        REMOTE + "?x=1",
        REMOTE + "#x",
        "https://user@issuer.example.org/",
        "https://Issuer.example.org/",
        "https://127.0.0.1:8443/",
        "https://localhost/",
        "https://issuer.example.org:443/",
        "https://issuer.example.org:0/",
        "https://issuer.example.org:08443/",
        "https://issuer.example.org:65536/",
        "https://-bad.example.org/",
        " https://issuer.example.org/",
        "https://issuer.example.org/\n",
        "https://" + "a" * 250 + ".org/",
    ],
)
def test_invalid_remote_issuers(issuer):
    with pytest.raises(ValueError):
        demo_settings.validate_remote_issuer(issuer)


def test_endpoint_derivation_and_settings_shapes():
    assert demo_settings.endpoints(REMOTE) == {
        "metadata": REMOTE + ".well-known/oauth-authorization-server",
        "authorization_endpoint": REMOTE + "oauth/authorize",
        "token_endpoint": REMOTE + "oauth/token",
        "jwks_uri": REMOTE + "oauth/jwks",
    }
    assert demo_settings.make_settings(REMOTE) == {
        "issuer": REMOTE,
        "resource": "https://127.0.0.1:8444/mcp",
        "callback": "http://127.0.0.1:49152/callback",
        "client_id": "mcp-local",
        "scope": "mcp:read",
        "required_role": "mcp-demo",
        "jwks_uri": REMOTE + "oauth/jwks",
        "issuer_tls": "system",
    }
    assert demo_settings.LOCAL_SETTINGS == {
        "issuer": "https://127.0.0.1:8443/",
        "resource": "https://127.0.0.1:8444/mcp",
        "callback": "http://127.0.0.1:49152/callback",
        "client_id": "mcp-local",
        "scope": "mcp:read",
        "required_role": "reader",
        "jwks_uri": "https://127.0.0.1:8443/oauth/jwks",
    }


def test_load_settings_accepts_exact_local_and_remote(tmp_path):
    assert demo_settings.load_settings(write_settings(tmp_path, demo_settings.LOCAL_SETTINGS))
    remote = demo_settings.make_settings(REMOTE)
    assert demo_settings.load_settings(write_settings(tmp_path, remote)) == remote
    assert demo_settings.is_remote(remote)
    assert not demo_settings.is_remote(demo_settings.LOCAL_SETTINGS)


@pytest.mark.parametrize(
    "change",
    [
        {"extra": "x"},
        {"role": "reader"},
        {"required_role": None},
        {"required_role": "reader"},
        {"issuer_tls": "local"},
        {"issuer_tls": None},
        {"jwks_uri": "https://other.example.org/oauth/jwks"},
        {"issuer": REMOTE.rstrip("/"), "jwks_uri": REMOTE.rstrip("/") + "oauth/jwks"},
        {
            "issuer": "http://issuer.example.org/",
            "jwks_uri": "http://issuer.example.org/oauth/jwks",
        },
        {"resource": "https://127.0.0.1:8445/mcp"},
        {"client_id": "other"},
        {"scope": "mcp:write"},
    ],
)
def test_load_settings_rejects_remote_variants(tmp_path, change):
    with pytest.raises((ValueError, TypeError)):
        demo_settings.load_settings(
            write_settings(tmp_path, {**demo_settings.make_settings(REMOTE), **change})
        )


@pytest.mark.parametrize(
    "settings",
    [
        # Remote issuer without the explicit system-trust marker.
        {k: v for k, v in demo_settings.make_settings(REMOTE).items() if k != "issuer_tls"},
        # Local issuer must never be paired with system trust.
        {**demo_settings.LOCAL_SETTINGS, "issuer_tls": "system"},
        {k: v for k, v in demo_settings.LOCAL_SETTINGS.items() if k != "jwks_uri"},
    ],
)
def test_load_settings_rejects_mode_mixups(tmp_path, settings):
    with pytest.raises(ValueError):
        demo_settings.load_settings(write_settings(tmp_path, settings))


def test_prepare_remote_writes_only_resource_material(tmp_path):
    runtime = prepare_demo.prepare(tmp_path / "runtime", REMOTE)
    assert runtime.stat().st_mode & 0o777 == 0o700
    assert {p.name for p in runtime.iterdir()} == {
        "tls-ca.pem",
        "tls-cert.pem",
        "tls-key.pem",
        "settings.json",
    }
    for file in runtime.iterdir():
        assert file.stat().st_mode & 0o777 == 0o600
    assert demo_settings.load_settings(runtime) == demo_settings.make_settings(REMOTE)


def test_prepare_local_output_unchanged(tmp_path):
    runtime = prepare_demo.prepare(tmp_path / "runtime")
    assert {p.name for p in runtime.iterdir()} == {
        "authotron.json",
        "credentials.json",
        "oauth-private.pem",
        "tls-ca.pem",
        "tls-cert.pem",
        "tls-key.pem",
        "settings.json",
    }
    assert json.loads((runtime / "settings.json").read_text()) == demo_settings.LOCAL_SETTINGS
    config = json.loads((runtime / "authotron.json").read_text())
    assert config["oauth"]["issuer"] == "https://127.0.0.1:8443/"


def test_prepare_remote_invalid_issuer_cleans_up(tmp_path):
    with pytest.raises(ValueError):
        prepare_demo.prepare(tmp_path / "runtime", REMOTE.rstrip("/"))
    assert not (tmp_path / "runtime").exists()
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            str(HERE / "prepare_demo.py"),
            "--runtime-dir",
            str(tmp_path / "cli"),
            "--issuer",
            "http://issuer.example.org/",
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2 and b"--issuer" in result.stderr
    assert not (tmp_path / "cli").exists()


def test_tls_context_selection(tmp_path, monkeypatch):
    runtime = prepare_demo.prepare(tmp_path / "runtime", REMOTE)
    settings = demo_settings.load_settings(runtime)
    calls = []
    original = ssl.create_default_context

    def recording(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(ssl, "create_default_context", recording)
    remote = demo_settings.issuer_tls_context(settings, runtime)
    assert calls == [((), {})]
    assert remote.check_hostname and remote.verify_mode == ssl.CERT_REQUIRED
    assert remote.minimum_version >= ssl.TLSVersion.TLSv1_2
    resource = demo_settings.local_tls_context(runtime)
    assert resource.check_hostname and resource.verify_mode == ssl.CERT_REQUIRED
    assert resource.cert_store_stats()["x509_ca"] == 1
    calls.clear()
    local = demo_settings.issuer_tls_context(demo_settings.LOCAL_SETTINGS, runtime)
    assert calls == [] and local.cert_store_stats()["x509_ca"] == 1


def test_client_uses_system_trust_for_issuer_and_local_ca_for_resource(tmp_path, monkeypatch):
    runtime = prepare_demo.prepare(tmp_path / "runtime", REMOTE)
    system = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(demo_settings, "system_tls_context", lambda: system)
    events = []

    class Listener:
        def __init__(self, state, issuer):
            events.append(("listener", issuer))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def wait_for_code(self):
            return "synthetic-code"

    def http_client(tls):
        events.append(("client", tls))
        return httpx.AsyncClient(trust_env=False, transport=httpx.MockTransport(None))

    async def exchange(http, code, verifier, issuer):
        events.append(("exchange", issuer))
        return "a.b.c"

    async def call_demo(http):
        events.append(("call", http.headers["Authorization"]))

    monkeypatch.setattr(client, "CallbackListener", Listener)
    monkeypatch.setattr(client, "http_client", http_client)
    monkeypatch.setattr(client, "exchange_code", exchange)
    monkeypatch.setattr(client, "call_demo", call_demo)
    monkeypatch.setattr(client.webbrowser, "open", lambda url: events.append(("open", url)))
    asyncio.run(client.run(runtime, no_browser=False))
    assert events[0] == ("listener", REMOTE)
    assert events[1][1].startswith(REMOTE + "oauth/authorize?")
    assert events[2] == ("client", system)
    assert events[3] == ("exchange", REMOTE)
    assert events[4][0] == "client" and events[4][1] is not system
    assert events[4][1].cert_store_stats()["x509_ca"] == 1
    assert events[5] == ("call", "Bearer a.b.c")


def test_remote_endpoints_used_by_client_and_verifier():
    url = client.authorization_url("s", "A" * 43, REMOTE)
    assert url.startswith(REMOTE + "oauth/authorize?")
    query = "/callback?code=c&state=s&iss=" + REMOTE
    assert client.parse_callback(query, "s", REMOTE) == "c"
    with pytest.raises(client.CallbackError):
        client.parse_callback(query, "s", demo_settings.LOCAL_ISSUER)

    def token(request):
        assert str(request.url) == REMOTE + "oauth/token"
        return httpx.Response(
            200,
            json={
                "access_token": "a.b.c",
                "token_type": "Bearer",
                "scope": "mcp:read",
                "expires_in": 60,
            },
        )

    async def exchange():
        async with httpx.AsyncClient(transport=httpx.MockTransport(token)) as http:
            return await client.exchange_code(http, "c", "A" * 43, REMOTE)

    assert asyncio.run(exchange()) == "a.b.c"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    parameters = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk = {"kty": "RSA", "n": parameters["n"], "e": parameters["e"], "kid": "k"}
    jwk.update(alg="RS256", use="sig")
    seen = []

    def jwks(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"keys": [jwk]})

    verifier = server.JWTVerifier(
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        demo_settings.make_settings(REMOTE),
        transport=httpx.MockTransport(jwks),
    )
    now = int(time.time())
    claims = {
        "iss": REMOTE,
        "aud": demo_settings.RESOURCE,
        "sub": "s",
        "jti": "j",
        "client_id": demo_settings.CLIENT_ID,
        "iat": now,
        "exp": now + 60,
        "scope": demo_settings.SCOPE,
        "roles": [demo_settings.REMOTE_ROLE],
    }

    def sign(payload):
        return jwt.encode(payload, key, algorithm="RS256", headers={"kid": "k", "typ": "at+jwt"})

    async def verify():
        # Remote settings require the playground's OAuth role.
        assert await verifier.verify_token(sign(claims)) is not None
        assert (
            await verifier.verify_token(sign({**claims, "roles": ["other", "mcp-demo"]}))
            is not None
        )
        for roles in ([], ["other"], [demo_settings.ROLE], ["mcp-demo-x"]):
            assert await verifier.verify_token(sign({**claims, "roles": roles})) is None
        # The claim shape is enforced independently of membership.
        for roles in (None, "mcp-demo", [1], [""], ["r"] * 65, ["mcp-demo", 1]):
            assert await verifier.verify_token(sign({**claims, "roles": roles})) is None
        assert await verifier.verify_token(sign({**claims, "aud": "https://x.example/"})) is None
        assert await verifier.verify_token(sign({**claims, "scope": "other"})) is not None
        local = {**claims, "iss": demo_settings.LOCAL_ISSUER}
        assert await verifier.verify_token(sign(local)) is None

    asyncio.run(verify())
    assert seen == [REMOTE + "oauth/jwks"]
    mcp = server.create_server(verifier)
    assert str(mcp.settings.auth.issuer_url) == REMOTE


class FakeProcess:
    returncode = None

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9

    async def wait(self):
        return self.returncode


class StopAfterStartup(Exception):
    pass


def runner_args(runtime, **changes):
    values = dict(
        runtime_dir=runtime, authotron_bin=None, startup_timeout=5, show_credentials=False
    )
    return argparse.Namespace(**{**values, **changes})


def patch_runner(monkeypatch):
    launched, sites, ports, ready = [], [], [], []

    async def spawn(*command, **kwargs):
        launched.append(list(command))
        return FakeProcess()

    class Site:
        def __init__(self, runner, host, port, ssl_context):
            sites.append((host, port))

        async def start(self):
            pass

    async def wait_ready(session, settings, contexts, processes, timeout):
        ready.append((settings, contexts))
        raise StopAfterStartup

    monkeypatch.setattr(run_demo.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(run_demo.web, "TCPSite", Site)
    monkeypatch.setattr(run_demo, "check_ports", lambda selected: ports.append(selected))
    monkeypatch.setattr(run_demo, "wait_ready", wait_ready)
    return launched, sites, ports, ready


def test_runner_remote_starts_only_mcp_and_8444(tmp_path, monkeypatch):
    runtime = prepare_demo.prepare(tmp_path / "runtime", REMOTE)
    system = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(run_demo, "system_tls_context", lambda: system)
    launched, sites, ports, ready = patch_runner(monkeypatch)
    with pytest.raises(StopAfterStartup):
        asyncio.run(run_demo.run(runner_args(runtime)))
    assert len(launched) == 1 and launched[0][1].endswith("server.py")
    assert sites == [("127.0.0.1", 8444)]
    assert ports == [(8001, 8444)]
    settings, (issuer_tls, resource_tls) = ready[0]
    assert settings["issuer"] == REMOTE
    assert issuer_tls is system and resource_tls is not system


def test_runner_local_unchanged(tmp_path, monkeypatch):
    runtime = prepare_demo.prepare(tmp_path / "runtime")
    launched, sites, ports, ready = patch_runner(monkeypatch)
    binary = Path(sys.executable)
    with pytest.raises(StopAfterStartup):
        asyncio.run(run_demo.run(runner_args(runtime, authotron_bin=binary)))
    assert launched[0] == [str(binary.resolve())] and launched[1][1].endswith("server.py")
    assert sites == [("127.0.0.1", 8443), ("127.0.0.1", 8444)]
    assert ports == [(8000, 8001, 8443, 8444)]
    issuer_tls, resource_tls = ready[0][1]
    assert issuer_tls is resource_tls


@pytest.mark.parametrize(
    "remote, changes",
    [
        (True, {"authotron_bin": Path(sys.executable)}),
        (True, {"show_credentials": True}),
        (False, {}),
    ],
)
def test_runner_rejects_mode_mismatched_options(tmp_path, monkeypatch, remote, changes):
    runtime = prepare_demo.prepare(tmp_path / "runtime", REMOTE if remote else None)
    launched, *_ = patch_runner(monkeypatch)
    with pytest.raises(run_demo.UsageError):
        asyncio.run(run_demo.run(runner_args(runtime, **changes)))
    assert launched == []


def test_wait_ready_checks_remote_metadata_and_mcp_401():
    requests = []
    issuer_tls, resource_tls = object(), object()

    class Response:
        def __init__(self, status, body=None):
            self.status, self.body = status, body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def json(self):
            return self.body

    responses = iter(
        [
            Response(200, {"issuer": REMOTE.rstrip("/")}),
            Response(401),
            Response(200, {"issuer": REMOTE}),
            Response(200),
            Response(401),
        ]
    )

    def get(url, ssl):
        requests.append((url, ssl))
        return next(responses)

    settings = demo_settings.make_settings(REMOTE)
    session = SimpleNamespace(get=get)

    async def check():
        await run_demo.wait_ready(session, settings, (issuer_tls, resource_tls), [], 5)

    asyncio.run(check())
    metadata = (REMOTE + ".well-known/oauth-authorization-server", issuer_tls)
    resource = (settings["resource"], resource_tls)
    assert requests == [metadata, resource, metadata, resource, resource]
