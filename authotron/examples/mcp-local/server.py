"""Stateless MCP resource server; the demo runner supplies the public TLS proxy."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import ssl
import time
from pathlib import Path

import httpx
import jwt
import uvicorn
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

ISSUER = "https://127.0.0.1:8443/"
RESOURCE = "https://127.0.0.1:8444/mcp"
CALLBACK = "http://127.0.0.1:49152/callback"
CLIENT_ID = "mcp-local"
SCOPE = "mcp:read"
ROLE = "reader"
JWKS_URI = "https://127.0.0.1:8443/oauth/jwks"
MAX_TOKEN_BYTES = 16384
MAX_JSON_BYTES = 65536


def strict_json(raw: bytes) -> dict:
    """Accept objects with unique names: {\"a\":1}, never {\"a\":1,\"a\":2}."""

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("Nonstandard JSON constant")

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting too deep") from exc
    if not isinstance(value, dict):
        raise TypeError("Expected a JSON object")
    return value


def load_settings(runtime_dir: Path) -> dict:
    with (runtime_dir / "settings.json").open("rb") as source:
        raw = source.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Settings too large")
    settings = strict_json(raw)
    expected = {
        "issuer": ISSUER,
        "resource": RESOURCE,
        "callback": CALLBACK,
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "jwks_uri": JWKS_URI,
    }
    if any(settings.get(key) != value for key, value in expected.items()):
        raise ValueError("Settings do not match the fixed local demo")
    if settings.get("role", ROLE) != ROLE:
        raise ValueError("Settings do not match the demo role")
    return settings


def local_tls_context(runtime_dir: Path) -> ssl.SSLContext:
    # Constructing explicitly avoids loading OS roots or SSL_CERT_FILE/SSL_CERT_DIR.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(runtime_dir / "tls-ca.pem"))
    return context


async def bounded_json(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> dict:
    """Bound both decoded response bytes and the complete HTTP operation."""
    async with asyncio.timeout(10):
        async with client.stream(
            method, url, headers={"Accept-Encoding": "identity"}, **kwargs
        ) as response:
            response.raise_for_status()
            if response.headers.get("content-type", "").split(";")[0] != "application/json":
                raise ValueError("Expected JSON response")
            if response.headers.get("content-encoding", "identity") != "identity":
                raise ValueError("Compressed auth responses are not supported")
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=8192):
                body.extend(chunk)
                if len(body) > MAX_JSON_BYTES:
                    raise ValueError("Response too large")
            return strict_json(bytes(body))


class JWTVerifier:
    """Fixed trust anchors, bounded JWKS cache, and fail-closed access-token checks."""

    def __init__(self, tls: ssl.SSLContext, *, transport: httpx.AsyncBaseTransport | None = None):
        self.tls = tls
        self.transport = transport
        self._keys: dict[str, jwt.PyJWK] = {}
        self._expires = 0.0
        self._retry_after = 0.0
        self._lock = asyncio.Lock()

    async def _trusted_keys(self) -> dict[str, jwt.PyJWK]:
        async with self._lock:
            now = time.monotonic()
            if now < self._expires:
                return self._keys
            if now < self._retry_after:
                return {}
            self._retry_after = now + 5
            async with httpx.AsyncClient(
                verify=self.tls,
                trust_env=False,
                follow_redirects=False,
                timeout=5,
                transport=self.transport,
            ) as client:
                document = await bounded_json(client, "GET", JWKS_URI)
            entries = document.get("keys")
            if not isinstance(entries, list) or not 1 <= len(entries) <= 8:
                raise ValueError("Invalid JWKS")
            keys = {}
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {
                    "kty",
                    "alg",
                    "use",
                    "kid",
                    "n",
                    "e",
                }:
                    raise ValueError("Expected public RSA JWK")
                if (entry["kty"], entry["alg"], entry["use"]) != ("RSA", "RS256", "sig"):
                    raise ValueError("Unexpected JWK algorithm")
                kid = entry["kid"]
                if not isinstance(kid, str) or not 1 <= len(kid) <= 128 or kid in keys:
                    raise ValueError("Invalid key identifier")
                for name, limit in (("n", 700), ("e", 12)):
                    if not isinstance(entry[name], str) or not re.fullmatch(
                        rf"[A-Za-z0-9_-]{{1,{limit}}}", entry[name]
                    ):
                        raise ValueError("Invalid RSA parameters")
                key = jwt.PyJWK.from_dict(entry, algorithm="RS256")
                if not 2048 <= key.key.key_size <= 4096:
                    raise ValueError("Unexpected RSA size")
                keys[kid] = key
            self._keys = keys
            self._expires = time.monotonic() + 60
            return keys

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            if not isinstance(token, str) or not 1 <= len(token) <= MAX_TOKEN_BYTES:
                return None
            if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
                return None
            header_part, payload_part, _ = token.split(".")
            header = strict_json(jwt.utils.base64url_decode(header_part))
            payload = strict_json(jwt.utils.base64url_decode(payload_part))
            if any(type(payload.get(name)) is not int for name in ("iat", "exp")):
                return None
            if "nbf" in payload and type(payload["nbf"]) is not int:
                return None
            if header.get("alg") != "RS256" or header.get("typ") != "at+jwt":
                return None
            if set(header) - {"alg", "typ", "kid"}:
                return None
            kid = header.get("kid")
            if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
                return None
            key = (await self._trusted_keys()).get(kid)
            if key is None:
                return None
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                issuer=ISSUER,
                audience=RESOURCE,
                options={
                    "strict_aud": True,
                    "require": [
                        "iss",
                        "aud",
                        "exp",
                        "iat",
                        "sub",
                        "jti",
                        "client_id",
                        "scope",
                        "roles",
                    ],
                },
            )
            if not 0 < claims["exp"] - claims["iat"] <= 3600:
                return None
            if claims["client_id"] != CLIENT_ID:
                return None
            if any(
                not isinstance(claims[name], str) or not 1 <= len(claims[name]) <= 256
                for name in ("sub", "jti")
            ):
                return None
            scope = claims["scope"]
            if (
                not isinstance(scope, str)
                or len(scope) > 1024
                or not re.fullmatch(
                    r"[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*", scope
                )
            ):
                return None
            scopes = scope.split(" ")
            if len(set(scopes)) != len(scopes):
                return None
            roles = claims["roles"]
            if (
                not isinstance(roles, list)
                or not 1 <= len(roles) <= 64
                or any(not isinstance(role, str) or not 1 <= len(role) <= 128 for role in roles)
                or ROLE not in roles
            ):
                return None
            return AccessToken(
                token=token,
                client_id=CLIENT_ID,
                scopes=scopes,
                expires_at=claims["exp"],
                resource=RESOURCE,
            )
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, httpx.HTTPError, TimeoutError):
            # Neither rejected tokens nor upstream diagnostics belong in logs or responses.
            return None


def create_server(verifier: JWTVerifier) -> FastMCP:
    mcp = FastMCP(
        "Auth-O-Tron local demo",
        host="127.0.0.1",
        port=8001,
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(ISSUER),
            resource_server_url=AnyHttpUrl(RESOURCE),
            required_scopes=[SCOPE],
        ),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:8001", "127.0.0.1:8444"],
            allowed_origins=["https://127.0.0.1:8444"],
        ),
    )

    @mcp.tool()
    def demo_status() -> dict[str, str]:
        """Return fixed synthetic data without reading files or contacting services."""
        return {"status": "ok", "message": "Synthetic MCP data", "scope": SCOPE}

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        load_settings(args.runtime_dir)
        verifier = JWTVerifier(local_tls_context(args.runtime_dir))
        uvicorn.run(
            create_server(verifier).streamable_http_app(),
            host="127.0.0.1",
            port=8001,
            access_log=False,
            proxy_headers=False,
            log_level="warning",
        )
    except (OSError, ValueError, TypeError):
        parser.exit(1, "MCP server could not start; check the public runtime settings and CA.\n")


if __name__ == "__main__":
    main()
