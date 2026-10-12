"""Single source of truth for the demo's public settings and derived OAuth endpoints.

Two modes exist:
- local: Authotron runs behind https://127.0.0.1:8443/ and is trusted via tls-ca.pem.
- remote: a public issuer (e.g. https://issuer.example.org/) is trusted via system roots;
  settings.json then carries "issuer_tls": "system".
The MCP resource is always local (https://127.0.0.1:8444/mcp) and trusted via tls-ca.pem.
"""

from __future__ import annotations

import json
import re
import ssl
from pathlib import Path

LOCAL_ISSUER = "https://127.0.0.1:8443/"
RESOURCE = "https://127.0.0.1:8444/mcp"
CALLBACK = "http://127.0.0.1:49152/callback"
CLIENT_ID = "mcp-local"
SCOPE = "mcp:read"
ROLE = "reader"
# The playground issuer (../ecmwf-api-key/render_api_key.py) requires this role for SCOPE.
REMOTE_ROLE = "mcp-demo"
SYSTEM_TRUST = "system"
MAX_JSON_BYTES = 65536

# Valid: https://issuer.example.org/ and https://issuer.example.org:9443/
# Invalid: http://..., missing trailing slash, paths, queries, userinfo, uppercase,
# IP literals, single-label hosts (localhost), explicit :443, leading-zero ports.
_REMOTE_ISSUER = re.compile(
    r"https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    r"(?::(?P<port>[1-9][0-9]{0,4}))?/"
)


def validate_remote_issuer(value: object) -> str:
    """Return the issuer unchanged if it is an absolute HTTPS origin with a trailing slash."""
    if not isinstance(value, str) or len(value) > 256:
        raise ValueError("issuer must be a string")
    match = _REMOTE_ISSUER.fullmatch(value)
    if match is None:
        raise ValueError("issuer must look like https://host.example/ (lowercase, trailing slash)")
    port = match.group("port")
    if port is not None and (int(port) > 65535 or port == "443"):
        raise ValueError("issuer port must be valid and non-default")
    return value


def endpoints(issuer: str) -> dict[str, str]:
    """Derive Authotron's fixed endpoint layout from the issuer."""
    return {
        "metadata": issuer + ".well-known/oauth-authorization-server",
        "authorization_endpoint": issuer + "oauth/authorize",
        "token_endpoint": issuer + "oauth/token",
        "jwks_uri": issuer + "oauth/jwks",
    }


def make_settings(issuer: str | None = None) -> dict:
    """Settings written by prepare_demo.py; None selects the local issuer.

    ``required_role`` is part of the contract: the local Authotron config grants ROLE, so
    local tokens must carry it. Remote issuers (the playground) issue SCOPE only to users
    holding REMOTE_ROLE, so remote tokens must carry REMOTE_ROLE.
    """
    base = {
        "issuer": LOCAL_ISSUER if issuer is None else validate_remote_issuer(issuer),
        "resource": RESOURCE,
        "callback": CALLBACK,
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "required_role": ROLE if issuer is None else REMOTE_ROLE,
    }
    base["jwks_uri"] = endpoints(base["issuer"])["jwks_uri"]
    if issuer is not None:
        base["issuer_tls"] = SYSTEM_TRUST
    return base


LOCAL_SETTINGS = make_settings()


def is_remote(settings: dict) -> bool:
    return settings.get("issuer_tls") == SYSTEM_TRUST


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


def validate_settings(settings: dict) -> dict:
    """Accept exactly the local settings, or exactly make_settings(<valid remote issuer>)."""
    if "issuer_tls" in settings:
        if settings["issuer_tls"] != SYSTEM_TRUST:
            raise ValueError("Unsupported issuer TLS mode")
        expected = make_settings(validate_remote_issuer(settings.get("issuer")))
    else:
        expected = LOCAL_SETTINGS
    if settings != expected:
        raise ValueError("Settings do not match the demo contract")
    return settings


def load_settings(runtime_dir: Path) -> dict:
    with (runtime_dir / "settings.json").open("rb") as source:
        raw = source.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Settings too large")
    return validate_settings(strict_json(raw))


def local_tls_context(runtime_dir: Path) -> ssl.SSLContext:
    # Constructing explicitly avoids loading OS roots or SSL_CERT_FILE/SSL_CERT_DIR.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(runtime_dir / "tls-ca.pem"))
    return context


def system_tls_context() -> ssl.SSLContext:
    # Default system roots with certificate and hostname verification.
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def issuer_tls_context(settings: dict, runtime_dir: Path) -> ssl.SSLContext:
    """Remote issuers use system trust; the local issuer shares the resource's local CA."""
    return system_tls_context() if is_remote(settings) else local_tls_context(runtime_dir)
