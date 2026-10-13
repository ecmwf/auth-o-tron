#!/usr/bin/env python3
"""Render a disposable direct ECMWF API-key playground, without applying it."""

import argparse
import base64
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import stat
from pathlib import Path
from urllib.parse import urlsplit

import yaml

_EXAMPLES = Path(__file__).parents[1]


def _load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, _EXAMPLES / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preview = _load_module("ecmwf_login_preview", "kubernetes-login-preview/render.py")
private_paths = _load_module(
    "preview_private_paths", "kubernetes-login-preview/private_paths.py"
)
NAMESPACE = preview.NAMESPACE
SECRET_NAME = "authotron-ecmwf-browser"
PROVIDER = {
    "type": "ecmwf-api",
    "name": "ECMWF API Provider",
    "realm": "ecmwf",
    "uri": "https://api.ecmwf.int/v1",
    "browser": {"id": "ecmwf-api-key", "label": "ECMWF API key"},
}
BASIC_ID = "password"
BASIC_LABEL = "Username and password"
BASIC_PROVIDER_NAME = "Playground Basic Provider"
BASIC_USERNAME = "browser-demo"
LOGO_PATH = "/static/aviso-logo.png"
# Official Valkey 9.1.2-alpine multiarchitecture index.
VALKEY_IMAGE = "docker.io/valkey/valkey@sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11"
VALKEY_NAME = f"{preview.RELEASE}-browser-valkey"
VALKEY_PASSWORD_ENV = "AOT_UI__BROWSER_SESSION__BACKEND__PASSWORD"
BASIC_REALM = "browser-demo"
# Opt-in OAuth profile matching the mcp-local remote-mode client registration;
# test_render_api_key.py guards these values against ../mcp-local/demo_settings.py.
# Prometheus metrics on a separate in-cluster port: the Service exposes it, the
# Ingress never routes to it. Scrape it via the Service or `kubectl port-forward`.
METRICS_PORT = 9090
METRICS_PORT_NAME = "http-metrics"
OAUTH_KEY_DIR = "/run/secrets/oauth"
OAUTH_KEY_NAME = "signing.pem"
OAUTH_SECRET_KEY = "oauth-signing.pem"
OAUTH_VOLUME = "oauth-signing"
OAUTH_RESOURCE = "https://127.0.0.1:8444/mcp"
OAUTH_SCOPE = "mcp:read"
# `mcp:read` requires this role: the Basic demo user gets it from its augmenter
# and ECMWF users only via --oauth-allow-ecmwf-uid. mcp-local's remote settings
# require the same single role.
OAUTH_ROLE = "mcp-demo"
OAUTH_REQUIRED_ROLES = (OAUTH_ROLE,)
# Demo lifetime at the server maximum (60..=3600 seconds); clients renew it with
# their rotating refresh token instead of repeating the browser flow.
OAUTH_ACCESS_TOKEN_TTL_SECONDS = 3600
# Every rendered client gets refresh tokens: 30 days idle, 90 days after sign-in.
# Server bounds: each lifetime 300..=34560000 seconds (400 days), idle <= absolute.
OAUTH_REFRESH_TOKENS = {
    "enabled": True,
    "idle_ttl_seconds": 30 * 86400,
    "absolute_ttl_seconds": 90 * 86400,
}
OAUTH_REFRESH_TTL_RANGE = range(300, 34560000 + 1)
# API-key sign-ins keep refresh tokens for at most 30 days after sign-in, whatever
# the client allows; password sign-ins follow the client lifetime above.
OAUTH_API_KEY_REFRESH_MAX_LIFETIME_SECONDS = 30 * 86400
# Opt-in Aviso MCP resource (--oauth-aviso-resource): any authenticated browser user
# of the playground may use it, so its scope requires no role.
OAUTH_AVISO_SCOPE = "aviso:read"
# ECMWF uids become `username` in realm `ecmwf`; bounded like the server's browser uid.
OAUTH_MAX_ECMWF_UIDS = 32
OAUTH_MAX_UID_LENGTH = 128
OAUTH_CLIENT = {
    "client_id": "mcp-local",
    "display_name": "Local MCP demo",
    "application_type": "native",
    "redirect_uris": ["http://127.0.0.1:49152/callback"],
    "resources": [{"resource": OAUTH_RESOURCE, "scopes": [OAUTH_SCOPE]}],
    "refresh_tokens": dict(OAUTH_REFRESH_TOKENS),
}
# Pre-registered public MCP clients, checked against vendor docs (2026-10). Loopback
# HTTP callbacks require `native` and match any request port on the server, so a
# registered port is irrelevant; `native` clients may also list HTTPS callbacks.
# Hosted-only clients use `web`. Every row must pass checked_mcp_client.
MCP_CLIENTS = (
    {
        "client_id": "claude-code",
        "display_name": "Claude Code",
        "application_type": "native",
        "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
    },
    {
        "client_id": "claude-ai",
        "display_name": "Claude (web, Desktop, mobile)",
        "application_type": "web",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
    },
    {
        "client_id": "codex",
        "display_name": "OpenAI Codex",
        "application_type": "native",
        "redirect_uris": ["http://127.0.0.1/callback"],
    },
    {
        "client_id": "chatgpt",
        "display_name": "ChatGPT",
        "application_type": "web",
        "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
    },
    {
        "client_id": "gemini-cli",
        "display_name": "Gemini CLI",
        "application_type": "native",
        "redirect_uris": ["http://localhost/oauth/callback"],
    },
    {
        "client_id": "vscode",
        "display_name": "Visual Studio Code",
        "application_type": "native",
        # VS Code documents the path-less loopback spelling; matching is literal on
        # path, so the trailing-slash form is registered too.
        "redirect_uris": [
            "http://127.0.0.1:33418",
            "http://127.0.0.1:33418/",
            "https://vscode.dev/redirect",
            "https://insiders.vscode.dev/redirect",
        ],
    },
    {
        "client_id": "cursor",
        "display_name": "Cursor",
        "application_type": "native",
        "redirect_uris": [
            "http://localhost/callback",
            "https://www.cursor.com/agents/mcp/oauth/callback",
        ],
    },
    {
        "client_id": "mcp-inspector",
        "display_name": "MCP Inspector",
        "application_type": "native",
        "redirect_uris": [
            "http://127.0.0.1/oauth/callback",
            "http://localhost/oauth/callback",
            "http://localhost/oauth/callback/debug",
        ],
    },
)
# Keycloak demo SSO (../browser-sso): an OIDC sign-in method whose Keycloak client
# render_sso.py registers with the same method id and client id. With it, refresh
# families of the MCP_CLIENTS follow alice's Keycloak offline session.
OIDC_METHOD_ID = "demo-sso"
OIDC_LABEL = "Demo SSO (Keycloak)"
OIDC_REALM = "demo-sso"
OIDC_CLIENT_ID = "authotron-playground"
# Key of the client secret in render_sso.py's private secret bundle.
OIDC_BUNDLE_KEY = "authotron-client-secret"
OIDC_DIR = "/run/secrets/oidc"
OIDC_VOLUME = "oidc"
OIDC_SECRET_KEYS = {
    "oidc-client-secret": "client-secret",
    "oidc-upstream.key": "upstream.key",
}
# Each client receives floor(cap / client_count) non-borrowable transaction slots.
OAUTH_MAX_AUTHORIZATION_TRANSACTIONS = 1024
OAUTH_LOOPBACK_HOSTS = ("127.0.0.1", "[::1]", "localhost")
OAUTH_RESERVED_CALLBACK_QUERY = {
    "code",
    "state",
    "iss",
    "error",
    "error_description",
    "error_uri",
}
# NGINX admission rejects dotted paths with Exact/Prefix, so the metadata document
# uses ImplementationSpecific (prefix semantics); every other OAuth route is Exact.
OAUTH_PATH_RULES = (
    ("/oauth/authorize", "Exact"),
    ("/oauth/continue", "Exact"),
    ("/oauth/consent", "Exact"),
    ("/oauth/token", "Exact"),
    ("/oauth/revoke", "Exact"),
    ("/oauth/jwks", "Exact"),
    ("/.well-known/oauth-authorization-server", "ImplementationSpecific"),
)


def checked_session_options(
    valkey_password, replicas, session_ttl_seconds, transaction_ttl_seconds
):
    for value, low, high in (
        (replicas, 1, None),
        (session_ttl_seconds, 60, 86400),
        (transaction_ttl_seconds, 30, 900),
    ):
        if type(value) is not int or value < low or (high is not None and value > high):
            raise ValueError("invalid browser session lifetime or replica count")
    if replicas > 1 and valkey_password is None:
        raise ValueError("multiple application replicas require Valkey")
    if valkey_password is not None:
        checked_token(valkey_password)


def checked_valkey_storage(size, storage_class):
    """Valid: ("1Gi", None), ("512Mi", "longhorn"). Invalid: ("1G", None),
    ("0Gi", None), ("1Gi", "Bad_Class")."""
    if not isinstance(size, str) or not re.fullmatch(r"[1-9][0-9]{0,3}(Mi|Gi)", size):
        raise ValueError("Valkey storage size must look like 512Mi or 1Gi")
    if storage_class is not None and (
        not isinstance(storage_class, str)
        or len(storage_class) > 253
        or not re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", storage_class)
    ):
        raise ValueError("Valkey storage class must be a Kubernetes resource name")


def checked_ecmwf_uids(uids, oauth_enabled):
    """Valid: ("user_ecmwf",). Invalid: "user_ecmwf" (bare str), ("",), (" a",),
    ("a", "a"), or any uid without OAuth."""
    if isinstance(uids, (str, bytes)):
        # tuple("abc") would silently allowlist the single characters.
        raise ValueError("ECMWF OAuth allowlist must be a sequence of uids, not a str")
    uids = tuple(uids)
    if uids and not oauth_enabled:
        raise ValueError("--oauth-allow-ecmwf-uid requires the OAuth profile")
    if len(uids) > OAUTH_MAX_ECMWF_UIDS or len(set(uids)) != len(uids):
        raise ValueError("ECMWF OAuth allowlist must be short and unique")
    for uid in uids:
        if (
            not isinstance(uid, str)
            or not 1 <= len(uid) <= OAUTH_MAX_UID_LENGTH
            or uid != uid.strip()
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in uid)
        ):
            raise ValueError("invalid ECMWF uid in OAuth allowlist")
    return uids


def checked_callback(value, application_type):
    """Mirror of the server's callback rules.
    Valid: https://claude.ai/api/mcp/auth_callback, native http://localhost/callback.
    Invalid: web http://127.0.0.1/cb, http://127.0.0.2/cb, http://localhost:0/cb,
    https://a.example/cb#x, https://a.example/cb?state=1."""
    if not isinstance(value, str) or not value or len(value) > 2048 or "\\" in value:
        raise ValueError("invalid OAuth callback")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid OAuth callback")
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("invalid OAuth callback percent escape")
    url = urlsplit(value)
    try:
        port = url.port
    except ValueError:
        raise ValueError("invalid OAuth callback port") from None
    if (
        not url.hostname
        or url.netloc.endswith(":")
        or port == 0
        or "@" in url.netloc
        or "#" in value
    ):
        raise ValueError("invalid OAuth callback")
    host = url.netloc.rsplit(":", 1)[0] if port is not None else url.netloc
    if url.scheme == "https" and value.startswith("https://"):
        pass
    elif (
        value.startswith("http://")
        and application_type == "native"
        and host in OAUTH_LOOPBACK_HOSTS
    ):
        pass
    else:
        raise ValueError("OAuth callback must be HTTPS or a native loopback URI")
    names = {pair.split("=", 1)[0] for pair in url.query.split("&") if pair}
    if names & OAUTH_RESERVED_CALLBACK_QUERY:
        raise ValueError("OAuth callback query must not contain reserved parameters")
    return value


def checked_mcp_client(client):
    """Mirror of the server's client rules for one OAUTH client entry."""
    if not isinstance(client, dict) or not {
        "client_id",
        "display_name",
        "application_type",
        "redirect_uris",
    } <= set(client) <= {
        "client_id",
        "display_name",
        "application_type",
        "redirect_uris",
        "resources",
        "refresh_tokens",
    }:
        raise ValueError("unexpected OAuth client fields")
    if "refresh_tokens" in client:
        checked_refresh_tokens(client["refresh_tokens"])
    if not isinstance(client["client_id"], str) or not re.fullmatch(
        r"[A-Za-z0-9._-]{1,128}", client["client_id"]
    ):
        raise ValueError("invalid OAuth client_id")
    name = client["display_name"]
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name.encode()) > 128
        or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in name)
    ):
        raise ValueError("invalid OAuth display_name")
    if client["application_type"] not in ("web", "native"):
        raise ValueError("invalid OAuth application_type")
    uris = client["redirect_uris"]
    if not isinstance(uris, list) or not 1 <= len(uris) <= 8:
        raise ValueError("OAuth redirect_uris must contain 1..8 callbacks")
    if len(set(uris)) != len(uris):
        raise ValueError("duplicate OAuth redirect URI")
    for uri in uris:
        checked_callback(uri, client["application_type"])
    return client


def checked_refresh_tokens(policy):
    """Mirror of the server's per-client refresh-token policy rules."""
    required = {"enabled", "idle_ttl_seconds", "absolute_ttl_seconds"}
    if not isinstance(policy, dict) or not (
        required <= set(policy) <= required | {"upstream_offline_access"}
    ):
        raise ValueError("unexpected OAuth refresh_tokens fields")
    idle, absolute = policy["idle_ttl_seconds"], policy["absolute_ttl_seconds"]
    if (
        not isinstance(policy["enabled"], bool)
        or any(type(v) is not int for v in (idle, absolute))
        or idle not in OAUTH_REFRESH_TTL_RANGE
        or absolute not in OAUTH_REFRESH_TTL_RANGE
        or idle > absolute
    ):
        raise ValueError("invalid OAuth refresh_tokens lifetimes")
    upstream = policy.get("upstream_offline_access", False)
    if not isinstance(upstream, bool) or (upstream and not policy["enabled"]):
        raise ValueError("upstream_offline_access requires enabled refresh tokens")
    return policy


def checked_mcp_clients(clients):
    clients = [checked_mcp_client(c) for c in clients]
    ids = [c["client_id"] for c in clients]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate OAuth client_id")
    if not len(clients) <= OAUTH_MAX_AUTHORIZATION_TRANSACTIONS <= 100000:
        raise ValueError("OAuth transaction capacity needs one slot per client")
    return clients


def checked_oauth_profile(oauth_enabled, valkey_password):
    """OAuth state shares the browser backend; the playground requires Valkey."""
    if oauth_enabled and valkey_password is None:
        raise ValueError("the OAuth profile requires the shared Valkey profile")


def secret_env(name, key):
    return {
        "name": name,
        "valueFrom": {"secretKeyRef": {"name": SECRET_NAME, "key": key}},
    }


def valkey_config(password):
    checked_token(password)
    return (
        "bind 0.0.0.0\nprotected-mode yes\nport 6379\n"
        f"requirepass {password}\n"
        # OAuth refresh tokens must survive restarts: AOF on the PVC, no RDB snapshots.
        'appendonly yes\nappendfsync everysec\nsave ""\n'
        "maxmemory 128mb\nmaxmemory-policy noeviction\n"
        'logfile ""\ndaemonize no\ndir /data\n'
    )


def valkey_resources(app_labels, password, storage_size="1Gi", storage_class=None):
    checked_valkey_storage(storage_size, storage_class)
    claim_spec = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": storage_size}},
    }
    if storage_class is not None:
        claim_spec["storageClassName"] = storage_class
    labels = {
        "app.kubernetes.io/name": VALKEY_NAME,
        "app.kubernetes.io/instance": preview.RELEASE,
    }
    metadata = {"name": VALKEY_NAME, "namespace": NAMESPACE}
    annotations = {
        "checksum/valkey-config": hashlib.sha256(
            valkey_config(password).encode()
        ).hexdigest(),
        "checksum/valkey-password": hashlib.sha256(password.encode()).hexdigest(),
    }
    probe = {
        "exec": {
            "command": [
                "sh",
                "-ec",
                'test "$(valkey-cli -h 127.0.0.1 ping)" = PONG',
            ]
        },
        "periodSeconds": 10,
        "timeoutSeconds": 3,
        "failureThreshold": 3,
    }
    return [
        {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {**metadata, "labels": copy.deepcopy(labels)},
            "spec": claim_spec,
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": metadata,
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels, "annotations": annotations},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 1000,
                            "runAsGroup": 1000,
                            "fsGroup": 1000,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [
                            {
                                "name": "valkey",
                                "image": VALKEY_IMAGE,
                                "command": ["valkey-server", "/etc/valkey/valkey.conf"],
                                "env": [
                                    secret_env("VALKEYCLI_AUTH", "valkey-password")
                                ],
                                "ports": [
                                    {
                                        "name": "valkey",
                                        "containerPort": 6379,
                                        "protocol": "TCP",
                                    }
                                ],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                                "volumeMounts": [
                                    {
                                        "name": "valkey-config",
                                        "mountPath": "/etc/valkey",
                                        "readOnly": True,
                                    },
                                    {"name": "data", "mountPath": "/data"},
                                ],
                                "readinessProbe": copy.deepcopy(probe),
                                "livenessProbe": {
                                    **copy.deepcopy(probe),
                                    "initialDelaySeconds": 10,
                                },
                            }
                        ],
                        "volumes": [
                            {
                                "name": "valkey-config",
                                "secret": {
                                    "secretName": SECRET_NAME,
                                    "defaultMode": 0o440,
                                    "items": [
                                        {"key": "valkey.conf", "path": "valkey.conf"}
                                    ],
                                },
                            },
                            {
                                "name": "data",
                                "persistentVolumeClaim": {"claimName": VALKEY_NAME},
                            },
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": metadata,
            "spec": {
                "type": "ClusterIP",
                "selector": labels,
                "ports": [
                    {
                        "name": "valkey",
                        "port": 6379,
                        "targetPort": "valkey",
                        "protocol": "TCP",
                    }
                ],
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata,
            "spec": {
                "podSelector": {"matchLabels": labels},
                "policyTypes": ["Ingress"],
                "ingress": [
                    {
                        "from": [
                            {"podSelector": {"matchLabels": copy.deepcopy(app_labels)}}
                        ],
                        "ports": [{"protocol": "TCP", "port": 6379}],
                    }
                ],
            },
        },
    ]


def checked_token(token):
    # Valid: canonical URL-safe encoding of 32 bytes. Invalid: padded/base64 text.
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise ValueError("expected a generated 32-byte URL-safe credential")
    raw = base64.urlsafe_b64decode(token + "=")
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != token:
        raise ValueError("noncanonical credential")
    return token


def directory_fd(path, create=False):
    """Walk using directory descriptors: no symlink ancestry or traversal races."""
    if ".." in Path(path).parts:
        raise ValueError("private paths must not contain parent traversal")
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_fd(parent_fd, name, flags):
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent_fd)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.getuid()
    ):
        os.close(fd)
        raise ValueError(
            "private files must be owned regular files with one link and mode 0600"
        )
    return fd


def outside_git(path):
    return private_paths.outside_git(path)


def checked_output_directory(path, project):
    return private_paths.checked_private_path(
        path, project, preview.SOURCE_FILES, preview.RESERVED_SOURCE_DIRS
    )


def checked_credential_path(path, project):
    return checked_output_directory(path, project)


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate credential JSON key")
        result[key] = value
    return result


def private_json(path, generate, validate):
    """Persist generated credentials only in owned private files outside Git."""
    path = outside_git(path)
    parent = directory_fd(path.parent)
    try:
        try:
            fd = private_fd(parent, path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except FileExistsError:
            fd = private_fd(parent, path.name, os.O_RDONLY)
            with os.fdopen(fd) as stream:
                text = stream.read(4097)
            if len(text) > 4096:
                raise ValueError("credential file is too large")
            try:
                return validate(json.loads(text, object_pairs_hook=unique_json_object))
            except (ValueError, TypeError):
                raise ValueError("invalid private credential file") from None
        payload = generate()
        validated = validate(payload)
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return validated
    finally:
        os.close(parent)


def signing_secret(path):
    def validate(payload):
        if not isinstance(payload, dict) or set(payload) != {"jwt-secret"}:
            raise ValueError("signing-secret file must contain only jwt-secret")
        return checked_token(payload["jwt-secret"])

    return private_json(
        path, lambda: {"jwt-secret": secrets.token_urlsafe(32)}, validate
    )


def checked_basic_credentials(payload):
    if (
        not isinstance(payload, dict)
        or set(payload) != {"username", "password"}
        or payload["username"] != BASIC_USERNAME
    ):
        raise ValueError("expected generated playground Basic credentials")
    checked_token(payload["password"])
    return dict(payload)


def basic_credentials(path):
    return private_json(
        path,
        lambda: {"username": BASIC_USERNAME, "password": secrets.token_urlsafe(32)},
        checked_basic_credentials,
    )


def valkey_secret(path):
    def validate(payload):
        if not isinstance(payload, dict) or set(payload) != {"valkey-password"}:
            raise ValueError("expected generated Valkey credentials")
        return checked_token(payload["valkey-password"])

    return private_json(
        path, lambda: {"valkey-password": secrets.token_urlsafe(32)}, validate
    )


def upstream_key(path):
    """The key sealing upstream refresh tokens, generated on first use."""

    def validate(payload):
        if not isinstance(payload, dict) or set(payload) != {"upstream-key"}:
            raise ValueError("upstream key file must contain only upstream-key")
        return checked_upstream_key(payload["upstream-key"])

    return private_json(
        path,
        lambda: {"upstream-key": base64.b64encode(secrets.token_bytes(32)).decode()},
        validate,
    )


def sso_client_secret(path):
    """Only `authotron-client-secret` from render_sso.py's existing private bundle; this
    renderer never creates or changes that file."""
    path = outside_git(path)
    parent = directory_fd(path.parent)
    try:
        fd = private_fd(parent, path.name, os.O_RDONLY)
    finally:
        os.close(parent)
    with os.fdopen(fd) as stream:
        text = stream.read(4097)
    try:
        if len(text) > 4096:
            raise ValueError
        bundle = json.loads(text, object_pairs_hook=unique_json_object)
        return checked_token(bundle[OIDC_BUNDLE_KEY])
    except (ValueError, TypeError, KeyError):
        raise ValueError(
            "SSO secret file must be render_sso.py's bundle with "
            f"{OIDC_BUNDLE_KEY}; render the SSO stack first"
        ) from None


def checked_oauth_key(payload):
    """Accept only a canonical unencrypted RSA-2048 PKCS8 PEM; return the PEM text."""
    if (
        not isinstance(payload, dict)
        or set(payload) != {"private-key-pem"}
        or not isinstance(payload["private-key-pem"], str)
    ):
        raise ValueError("OAuth key file must contain only private-key-pem")
    pem = payload["private-key-pem"]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except Exception:
        raise ValueError("invalid OAuth signing key") from None
    if (
        not isinstance(key, rsa.RSAPrivateKey)
        or key.key_size != 2048
        or key.public_key().public_numbers().e != 65537
        or oauth_pem(key) != pem
    ):
        raise ValueError("expected a generated RSA-2048 PKCS8 OAuth signing key")
    return pem


def oauth_pem(key):
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def oauth_signing_key(path):
    def generate():
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return {"private-key-pem": oauth_pem(key)}

    return private_json(path, generate, checked_oauth_key)


def oauth_kid(pem):
    """Derive a public key ID, e.g. playground-0123456789abcdef, from the SPKI."""
    from cryptography.hazmat.primitives import serialization

    checked_oauth_key({"private-key-pem": pem})
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"playground-{hashlib.sha256(spki).hexdigest()[:16]}"


def checked_aviso_resource(value, oauth_enabled):
    """Canonical HTTPS resource URI without query, fragment or userinfo.
    Valid: https://aviso-mcp.example.org/mcp. Invalid: http://a.example/mcp,
    https://A.example/mcp, https://a.example:443/mcp, https://a.example/mcp?x=1."""
    if value is None:
        return None
    if not oauth_enabled:
        raise ValueError("--oauth-aviso-resource requires the OAuth profile")
    match = isinstance(value, str) and re.fullmatch(
        r"https://([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)(?::([0-9]{1,5}))?"
        r"(/[A-Za-z0-9._~/-]*)",
        value,
    )
    if (
        not match
        or ".." in match[1]
        or (
            match[2] is not None
            # Canonical ports only: no default 443 and no leading zero.
            and (match[2] == "443" or match[2][0] == "0" or int(match[2]) > 65535)
        )
        or "//" in match[3]
        or value == OAUTH_RESOURCE
    ):
        raise ValueError("invalid Aviso OAuth resource URI")
    return value


def checked_oidc_issuer(value):
    """HTTPS issuer of the demo SSO realm, compared exactly with its discovery document.
    Valid: https://sso.example.org/realms/aviso-demo. Invalid: http://sso.example.org/r,
    https://sso.example.org/realms/a/, https://sso.example.org/r?x=1, https://sso/r."""
    match = isinstance(value, str) and re.fullmatch(
        r"https://([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)"
        r"((?:/[A-Za-z0-9._~-]+)+)",
        value,
    )
    if not match or len(value) > 2048 or "/../" in value + "/" or "/./" in value + "/":
        raise ValueError("invalid demo SSO issuer")
    return value


def checked_upstream_key(value):
    """32 random bytes in canonical standard Base64, as the server's key files hold.
    Valid: the 44 characters `openssl rand -base64 32` writes. Invalid: unpadded or
    URL-safe text, or a 16-byte key."""
    try:
        raw = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
    except ValueError:
        raw = b""
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ValueError("expected a generated 32-byte upstream token key")
    return value


def checked_oidc(oidc, oauth_enabled):
    """Demo SSO sign-in: the issuer, the Keycloak client secret and the key sealing
    upstream refresh tokens. It needs the OAuth profile, whose clients it couples."""
    if oidc is None:
        return None
    if not oauth_enabled:
        raise ValueError("the demo SSO method requires the OAuth profile")
    if not isinstance(oidc, dict) or set(oidc) != {
        "issuer",
        "client_secret",
        "upstream_key",
    }:
        raise ValueError("unexpected demo SSO settings")
    checked_oidc_issuer(oidc["issuer"])
    checked_token(oidc["client_secret"])
    checked_upstream_key(oidc["upstream_key"])
    return oidc


def upstream_kid(key):
    """Key id derived from the key, e.g. upstream-0123456789abcdef: a new key gets a
    new id."""
    checked_upstream_key(key)
    return f"upstream-{hashlib.sha256(base64.b64decode(key)).hexdigest()[:16]}"


def oidc_method(issuer):
    return {
        "id": OIDC_METHOD_ID,
        "label": OIDC_LABEL,
        "realm": OIDC_REALM,
        "issuer": checked_oidc_issuer(issuer),
        "client_id": OIDC_CLIENT_ID,
        "client_secret_file": f"{OIDC_DIR}/{OIDC_SECRET_KEYS['oidc-client-secret']}",
        "scopes": ["profile", "email"],
        "offline_access": True,
    }


def checked_trusted_proxies(values, oauth_enabled):
    """Canonical CIDRs of the reverse proxies whose X-Forwarded-For is trusted.
    Valid: 10.70.13.40/32, 10.26.28.0/24. Invalid: 10.26.28.1/24 (host bits),
    0.0.0.0/0 (trusts every client), 10.70.13.40 (no prefix)."""
    values = tuple(values)
    if not values:
        return ()
    if not oauth_enabled:
        raise ValueError("--trusted-proxy requires the OAuth profile")
    if len(values) > 64 or len(set(values)) != len(values):
        raise ValueError("at most 64 distinct trusted proxy CIDRs")
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (TypeError, ValueError):
            raise ValueError("invalid trusted proxy CIDR") from None
        if "/" not in value or str(network) != value or network.prefixlen == 0:
            raise ValueError("invalid trusted proxy CIDR")
    return values


def oauth_clients(aviso_resource=None, upstream=False):
    """mcp-local first (its fixed callback and local-only binding are unchanged),
    then the MCP client table bound to the local and optional Aviso resources. With
    `upstream`, the table clients (long-lived tools and agents) couple their refresh
    families to the demo SSO offline session."""
    bindings = [{"resource": OAUTH_RESOURCE, "scopes": [OAUTH_SCOPE]}]
    if aviso_resource is not None:
        bindings.append({"resource": aviso_resource, "scopes": [OAUTH_AVISO_SCOPE]})
    refresh = dict(OAUTH_REFRESH_TOKENS)
    if upstream:
        refresh["upstream_offline_access"] = True
    return checked_mcp_clients(
        [copy.deepcopy(OAUTH_CLIENT)]
        + [
            {
                **copy.deepcopy(c),
                "resources": copy.deepcopy(bindings),
                "refresh_tokens": dict(refresh),
            }
            for c in MCP_CLIENTS
        ]
    )


def oauth_config(
    host, kid, realms, aviso_resource=None, trusted_proxies=(), upstream_kid=None
):
    realms = list(dict.fromkeys(realms))
    resources = [
        {
            "resource": OAUTH_RESOURCE,
            "allowed_realms": list(realms),
            "scopes": [
                {"name": OAUTH_SCOPE, "required_roles": list(OAUTH_REQUIRED_ROLES)}
            ],
        }
    ]
    if aviso_resource is not None:
        resources.append(
            {
                "resource": aviso_resource,
                "allowed_realms": list(realms),
                "scopes": [{"name": OAUTH_AVISO_SCOPE, "required_roles": []}],
            }
        )
    config = {
        "enabled": True,
        "issuer": f"https://{host}/",
        "access_token_ttl_seconds": OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        "max_authorization_transactions": OAUTH_MAX_AUTHORIZATION_TRANSACTIONS,
        "signing": {
            "active_kid": kid,
            "keys": [
                {"kid": kid, "private_key_file": f"{OAUTH_KEY_DIR}/{OAUTH_KEY_NAME}"}
            ],
        },
        "clients": oauth_clients(aviso_resource, upstream_kid is not None),
        "resources": resources,
    }
    if trusted_proxies:
        config["endpoint_rate_limit"] = {"trusted_proxies": list(trusted_proxies)}
    if upstream_kid is not None:
        key_file = f"{OIDC_DIR}/{OIDC_SECRET_KEYS['oidc-upstream.key']}"
        config["upstream_token_encryption"] = {
            "active_kid": upstream_kid,
            "keys": [{"kid": upstream_kid, "key_file": key_file}],
        }
    return config


def private_write(parent, name, text):
    fd = private_fd(parent, name, os.O_WRONLY | os.O_CREAT)
    with os.fdopen(fd, "w") as stream:
        stream.truncate(0)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def resource_map(resources):
    """Reject foreign namespaces before any copying or normalization."""
    mapped = {}
    allowed = preview.ALLOWED_API_KIND_PAIRS | {
        ("v1", "Secret"),
        ("networking.k8s.io/v1", "NetworkPolicy"),
        ("v1", "PersistentVolumeClaim"),
    }
    for doc in resources:
        if (
            not isinstance(doc, dict)
            or (doc.get("apiVersion"), doc.get("kind")) not in allowed
        ):
            raise ValueError("unexpected resource kind or API version")
        metadata = doc.get("metadata", {})
        if not isinstance(metadata, dict) or metadata.get("namespace") != NAMESPACE:
            raise ValueError("every resource must explicitly target the playground")
        identity = (doc["apiVersion"], doc["kind"], metadata.get("name"))
        if not isinstance(identity[2], str) or identity in mapped:
            raise ValueError("invalid or duplicate resource identity")
        mapped[identity] = doc
    return mapped


def transform(
    baseline,
    host,
    token,
    basic=None,
    *,
    valkey_password=None,
    replicas=1,
    session_ttl_seconds=300,
    transaction_ttl_seconds=300,
    oauth_key=None,
    oauth_allow_ecmwf_uids=(),
    oauth_aviso_resource=None,
    oauth_trusted_proxies=(),
    valkey_storage_size="1Gi",
    valkey_storage_class=None,
    oidc=None,
):
    checked_session_options(
        valkey_password, replicas, session_ttl_seconds, transaction_ttl_seconds
    )
    checked_oauth_profile(oauth_key is not None, valkey_password)
    checked_valkey_storage(valkey_storage_size, valkey_storage_class)
    ecmwf_uids = checked_ecmwf_uids(oauth_allow_ecmwf_uids, oauth_key is not None)
    aviso = checked_aviso_resource(oauth_aviso_resource, oauth_key is not None)
    proxies = checked_trusted_proxies(oauth_trusted_proxies, oauth_key is not None)
    oidc = checked_oidc(oidc, oauth_key is not None)
    checked_token(token)
    resources = copy.deepcopy(baseline)
    config_map = next(d for d in resources if d["kind"] == "ConfigMap" and "data" in d)
    config = yaml.safe_load(config_map["data"]["config.yaml"])
    if config["providers"] or config["store"]["enabled"] or not config["ui"]["enabled"]:
        raise ValueError("expected the provider-empty public branding fixture")
    # Provider order is the chooser order: Basic (when enabled) precedes ECMWF.
    config["providers"] = [copy.deepcopy(PROVIDER)]
    config["jwt"]["secret"] = ""
    config["ui"]["branding"]["logo_url"] = LOGO_PATH
    config["ui"]["browser_session"] = {
        "public_origin": f"https://{host}",
        "session_ttl_seconds": session_ttl_seconds,
        "transaction_ttl_seconds": transaction_ttl_seconds,
        "backend": {"type": "memory"}
        if valkey_password is None
        else {
            "type": "valkey",
            "url": f"redis://{VALKEY_NAME}:6379/0",
            "key_prefix": f"authotron:browser:{preview.RELEASE}",
            "connect_timeout_ms": 2000,
            "operation_timeout_ms": 1000,
        },
    }
    if basic is not None:
        checked_basic_credentials(basic)
        config["providers"].insert(
            0,
            {
                "type": "plain",
                "name": BASIC_PROVIDER_NAME,
                "realm": BASIC_REALM,
                "users": [],
                "browser": {"id": BASIC_ID, "label": BASIC_LABEL},
            },
        )
        config["augmenters"] = [
            {
                "type": "plain_advanced",
                "name": "Playground Basic roles",
                "realm": BASIC_REALM,
                "match": {"username": [BASIC_USERNAME]},
                "augment": {
                    # The demo user holds the OAuth scope role only when OAuth is on.
                    "roles": ["demo-user", "augmented"]
                    + ([OAUTH_ROLE] if oauth_key is not None else []),
                    "attributes": {"email": "browser-demo@example.invalid"},
                },
            }
        ]
    if ecmwf_uids:
        # API-key users get the OAuth role only through this explicit uid allowlist.
        config.setdefault("augmenters", []).append(
            {
                "type": "plain_advanced",
                "name": "Playground ECMWF OAuth allowlist",
                "realm": PROVIDER["realm"],
                "match": {"username": list(ecmwf_uids)},
                "augment": {"roles": [OAUTH_ROLE]},
            }
        )
    if oidc is not None:
        config["ui"]["oidc"] = [oidc_method(oidc["issuer"])]
    if oauth_key is not None:
        api_key = next(p for p in config["providers"] if p["type"] == PROVIDER["type"])
        api_key["browser"]["refresh_max_lifetime_seconds"] = (
            OAUTH_API_KEY_REFRESH_MAX_LIFETIME_SECONDS
        )
        realms = [p["realm"] for p in config["providers"] if p.get("browser")]
        realms += [method["realm"] for method in config["ui"].get("oidc", [])]
        config["oauth"] = oauth_config(
            host,
            oauth_kid(oauth_key),
            realms,
            aviso,
            proxies,
            None if oidc is None else upstream_kid(oidc["upstream_key"]),
        )
    config["metrics"] = {"enabled": True, "port": METRICS_PORT}
    config_map["data"]["config.yaml"] = yaml.safe_dump(config)
    service = next(d for d in resources if d["kind"] == "Service")
    service["spec"]["ports"].append(
        {
            "name": METRICS_PORT_NAME,
            "port": METRICS_PORT,
            "targetPort": METRICS_PORT,
            "protocol": "TCP",
        }
    )
    deployment = next(d for d in resources if d["kind"] == "Deployment")
    deployment["spec"]["replicas"] = replicas
    template = deployment["spec"]["template"]
    template["metadata"]["annotations"]["authotron.ecmwf.int/signing-sha256"] = (
        hashlib.sha256(token.encode()).hexdigest()
    )
    template["spec"]["containers"][0]["ports"].append(
        {"name": METRICS_PORT_NAME, "containerPort": METRICS_PORT, "protocol": "TCP"}
    )
    mounted_yaml = config_map["data"]["config.yaml"]
    template["spec"]["containers"][0]["env"].append(
        {
            "name": "AOT_JWT__SECRET",
            "valueFrom": {"secretKeyRef": {"name": SECRET_NAME, "key": "jwt-secret"}},
        }
    )
    ingress = next(d for d in resources if d["kind"] == "Ingress")
    paths = ingress["spec"]["rules"][0]["http"]["paths"]
    # Widen the preview's Exact `/login/` to one Prefix covering the method forms,
    # the account page, and their trailing-slash redirects; the app 404s the rest.
    login_subtree = next(p for p in paths if p["path"] == "/login/")
    login_subtree["pathType"] = "Prefix"
    if oauth_key is not None:
        for path, path_type in OAUTH_PATH_RULES:
            paths.append(
                {
                    "path": path,
                    "pathType": path_type,
                    "backend": copy.deepcopy(paths[0]["backend"]),
                }
            )
    resources.append(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": SECRET_NAME, "namespace": NAMESPACE},
            "type": "Opaque",
            "data": {"jwt-secret": base64.b64encode(token.encode()).decode("ascii")},
        }
    )
    if basic is not None:
        private_config = copy.deepcopy(config)
        private_config["providers"][0]["users"] = [{**basic, "roles": []}]
        private_yaml = yaml.safe_dump(private_config)
        resources[-1]["data"]["config.yaml"] = base64.b64encode(
            private_yaml.encode()
        ).decode("ascii")
        volume = next(
            v for v in template["spec"]["volumes"] if v["name"] == "config-volume"
        )
        volume.pop("configMap")
        volume["secret"] = {
            "secretName": SECRET_NAME,
            "items": [{"key": "config.yaml", "path": "config.yaml"}],
        }
        mounted_yaml = private_yaml
    if oauth_key is not None:
        resources[-1]["data"][OAUTH_SECRET_KEY] = base64.b64encode(
            oauth_key.encode("ascii")
        ).decode("ascii")
        template["spec"]["volumes"].append(
            {
                "name": OAUTH_VOLUME,
                # 0440 plus the pod's fsGroup 1000 lets the non-root app read the key
                # without making it world-readable.
                "secret": {
                    "secretName": SECRET_NAME,
                    "defaultMode": 0o440,
                    "items": [{"key": OAUTH_SECRET_KEY, "path": OAUTH_KEY_NAME}],
                },
            }
        )
        template["spec"]["containers"][0]["volumeMounts"].append(
            {"name": OAUTH_VOLUME, "mountPath": OAUTH_KEY_DIR, "readOnly": True}
        )
        template["metadata"]["annotations"]["checksum/oauth-signing-key"] = (
            hashlib.sha256(oauth_key.encode("ascii")).hexdigest()
        )
    if oidc is not None:
        values = {
            "oidc-client-secret": oidc["client_secret"],
            "oidc-upstream.key": oidc["upstream_key"],
        }
        resources[-1]["data"].update(
            {
                key: base64.b64encode(value.encode("ascii")).decode("ascii")
                for key, value in values.items()
            }
        )
        template["spec"]["volumes"].append(
            {
                "name": OIDC_VOLUME,
                "secret": {
                    "secretName": SECRET_NAME,
                    "defaultMode": 0o440,
                    "items": [
                        {"key": key, "path": path}
                        for key, path in OIDC_SECRET_KEYS.items()
                    ],
                },
            }
        )
        template["spec"]["containers"][0]["volumeMounts"].append(
            {"name": OIDC_VOLUME, "mountPath": OIDC_DIR, "readOnly": True}
        )
        template["metadata"]["annotations"]["checksum/oidc-credentials"] = (
            hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()
        )
    if valkey_password is not None:
        secret = resources[-1]
        secret["data"].update(
            {
                "valkey-password": base64.b64encode(valkey_password.encode()).decode(
                    "ascii"
                ),
                "valkey.conf": base64.b64encode(
                    valkey_config(valkey_password).encode()
                ).decode("ascii"),
            }
        )
        template["spec"]["containers"][0]["env"].append(
            secret_env(VALKEY_PASSWORD_ENV, "valkey-password")
        )
        shared = valkey_resources(
            template["metadata"]["labels"],
            valkey_password,
            valkey_storage_size,
            valkey_storage_class,
        )
        template["metadata"]["annotations"].update(
            shared[1]["spec"]["template"]["metadata"]["annotations"]
        )
        resources.extend(shared)
    template["metadata"]["annotations"]["checksum/config"] = hashlib.sha256(
        mounted_yaml.encode()
    ).hexdigest()
    return resources


def validate_resources(
    resources,
    baseline,
    host,
    image,
    token,
    basic=None,
    *,
    valkey_password=None,
    replicas=1,
    session_ttl_seconds=300,
    transaction_ttl_seconds=300,
    oauth_key=None,
    oauth_allow_ecmwf_uids=(),
    oauth_aviso_resource=None,
    oauth_trusted_proxies=(),
    valkey_storage_size="1Gi",
    valkey_storage_class=None,
    oidc=None,
):
    """Compare the full output to the narrowly transformed, validated prototype."""
    preview.validate_inputs(host, image)
    checked_token(token)
    originals = resource_map(baseline)
    if len(originals) != 5:
        raise ValueError("expected five baseline resources")
    source = next(d for d in baseline if d["kind"] == "ConfigMap" and "binaryData" in d)
    expected_ids = {
        ("v1", "ConfigMap", f"{preview.RELEASE}-config"),
        ("v1", "ConfigMap", source["metadata"]["name"]),
        ("v1", "Service", preview.RELEASE),
        ("apps/v1", "Deployment", preview.RELEASE),
        ("networking.k8s.io/v1", "Ingress", preview.RELEASE),
    }
    if set(originals) != expected_ids:
        raise ValueError("unexpected baseline resource identity")
    cm = originals[("v1", "ConfigMap", f"{preview.RELEASE}-config")]
    config = yaml.safe_load(cm["data"]["config.yaml"])
    deployment = originals[("apps/v1", "Deployment", preview.RELEASE)]
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    probes = {key: container[key] for key in ("livenessProbe", "readinessProbe")}
    values = {
        "config": config,
        "ingress": {
            "hosts": [{"host": host}],
            "tls": [{"hosts": [host], "secretName": f"{preview.RELEASE}-tls"}],
        },
    }
    preview.validate_preview(
        baseline,
        values,
        preview.preview_pod(
            image, source["metadata"]["name"], config["server"]["port"], probes
        ),
    )
    expected = resource_map(
        transform(
            baseline,
            host,
            token,
            basic,
            valkey_password=valkey_password,
            replicas=replicas,
            session_ttl_seconds=session_ttl_seconds,
            transaction_ttl_seconds=transaction_ttl_seconds,
            oauth_key=oauth_key,
            oauth_allow_ecmwf_uids=oauth_allow_ecmwf_uids,
            oauth_aviso_resource=oauth_aviso_resource,
            oauth_trusted_proxies=oauth_trusted_proxies,
            valkey_storage_size=valkey_storage_size,
            valkey_storage_class=valkey_storage_class,
            oidc=oidc,
        )
    )
    if resource_map(resources) != expected:
        raise ValueError(
            "resources differ from the approved direct-login transformation"
        )


def render_api_key(
    project,
    chart,
    host,
    image,
    token,
    basic=None,
    *,
    valkey_password=None,
    replicas=1,
    session_ttl_seconds=300,
    transaction_ttl_seconds=300,
    oauth_key=None,
    oauth_allow_ecmwf_uids=(),
    oauth_aviso_resource=None,
    oauth_trusted_proxies=(),
    valkey_storage_size="1Gi",
    valkey_storage_class=None,
    oidc=None,
):
    preview.validate_inputs(host, image)
    checked_token(token)
    checked_session_options(
        valkey_password, replicas, session_ttl_seconds, transaction_ttl_seconds
    )
    checked_oauth_profile(oauth_key is not None, valkey_password)
    checked_valkey_storage(valkey_storage_size, valkey_storage_class)
    ecmwf_uids = checked_ecmwf_uids(oauth_allow_ecmwf_uids, oauth_key is not None)
    aviso = checked_aviso_resource(oauth_aviso_resource, oauth_key is not None)
    proxies = checked_trusted_proxies(oauth_trusted_proxies, oauth_key is not None)
    checked_oidc(oidc, oauth_key is not None)
    if oauth_key is not None:
        checked_oauth_key({"private-key-pem": oauth_key})
    if basic is not None:
        checked_basic_credentials(basic)
    baseline, archive = preview.render_preview(project, chart, host, image)
    options = dict(
        valkey_password=valkey_password,
        replicas=replicas,
        session_ttl_seconds=session_ttl_seconds,
        transaction_ttl_seconds=transaction_ttl_seconds,
        valkey_storage_size=valkey_storage_size,
        valkey_storage_class=valkey_storage_class,
    )
    if oauth_key is not None:
        options["oauth_key"] = oauth_key
    if ecmwf_uids:
        options["oauth_allow_ecmwf_uids"] = ecmwf_uids
    if aviso is not None:
        options["oauth_aviso_resource"] = aviso
    if proxies:
        options["oauth_trusted_proxies"] = proxies
    if oidc is not None:
        options["oidc"] = oidc
    resources = transform(baseline, host, token, basic, **options)
    validate_resources(resources, baseline, host, image, token, basic, **options)
    return resources, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chart", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--build-image", required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--sso-issuer",
        metavar="URL",
        help="offer the Keycloak demo SSO realm at this issuer as an OIDC method",
    )
    parser.add_argument(
        "--sso-secret-file",
        type=Path,
        help="render_sso.py's private bundle holding the Keycloak client secret",
    )
    parser.add_argument(
        "--upstream-key-file",
        type=Path,
        help="private key file sealing upstream refresh tokens (generated if absent)",
    )
    parser.add_argument("--basic-secret-file", type=Path)
    parser.add_argument("--valkey-secret-file", type=Path)
    parser.add_argument("--oauth-secret-file", type=Path)
    parser.add_argument(
        "--oauth-allow-ecmwf-uid",
        action="append",
        default=[],
        dest="oauth_allow_ecmwf_uids",
        metavar="UID",
        help="grant the OAuth role to this ECMWF API-key uid (repeatable)",
    )
    parser.add_argument(
        "--oauth-aviso-resource",
        metavar="URL",
        help=f"also register this Aviso MCP resource with scope {OAUTH_AVISO_SCOPE}",
    )
    parser.add_argument(
        "--trusted-proxy",
        action="append",
        default=[],
        dest="oauth_trusted_proxies",
        metavar="CIDR",
        help="trust X-Forwarded-For from this ingress CIDR for OAuth rate limits "
        "(repeatable)",
    )
    parser.add_argument("--replicas", type=int, default=1)
    parser.add_argument("--session-ttl-seconds", type=int, default=300)
    parser.add_argument("--transaction-ttl-seconds", type=int, default=300)
    parser.add_argument(
        "--valkey-storage-size",
        default="1Gi",
        metavar="SIZE",
        help="Valkey AOF PersistentVolumeClaim size (default: 1Gi)",
    )
    parser.add_argument(
        "--valkey-storage-class",
        metavar="NAME",
        help="Valkey PersistentVolumeClaim storage class (default: cluster default)",
    )
    args = parser.parse_args()
    preview.validate_inputs(args.host, args.build_image)
    # A synthetic valid token checks profile selection before creating credentials.
    checked_session_options(
        "A" * 43 if args.valkey_secret_file else None,
        args.replicas,
        args.session_ttl_seconds,
        args.transaction_ttl_seconds,
    )
    checked_oauth_profile(bool(args.oauth_secret_file), args.valkey_secret_file)
    checked_valkey_storage(args.valkey_storage_size, args.valkey_storage_class)
    checked_ecmwf_uids(args.oauth_allow_ecmwf_uids, bool(args.oauth_secret_file))
    checked_aviso_resource(args.oauth_aviso_resource, bool(args.oauth_secret_file))
    checked_trusted_proxies(args.oauth_trusted_proxies, bool(args.oauth_secret_file))
    sso_flags = (args.sso_issuer, args.sso_secret_file, args.upstream_key_file)
    if any(sso_flags) and not all(sso_flags):
        raise ValueError(
            "--sso-issuer, --sso-secret-file and --upstream-key-file go together"
        )
    if args.sso_issuer:
        checked_oidc_issuer(args.sso_issuer)
        if not args.oauth_secret_file:
            raise ValueError("the demo SSO method requires the OAuth profile")
    project = Path(__file__).resolve().parents[3]
    output_dir = checked_output_directory(args.output_dir, project)
    credential_paths = [
        checked_credential_path(path, project)
        for path in (
            args.secret_file,
            args.basic_secret_file,
            args.valkey_secret_file,
            args.oauth_secret_file,
            args.sso_secret_file,
            args.upstream_key_file,
        )
        if path
    ]
    if len(set(credential_paths)) != len(credential_paths):
        raise ValueError("credential file paths must be distinct")
    if any(
        a != b and a.is_relative_to(b)
        for a in credential_paths
        for b in credential_paths
    ):
        raise ValueError("credential files must not overlap credential directories")
    output_file = output_dir / "resources.yaml"
    if any(
        path.is_relative_to(output_file) or output_dir.is_relative_to(path)
        for path in credential_paths
    ):
        raise ValueError("output must not overwrite a credential file")
    token = signing_secret(args.secret_file)
    basic = (
        basic_credentials(args.basic_secret_file) if args.basic_secret_file else None
    )
    valkey_password = (
        valkey_secret(args.valkey_secret_file) if args.valkey_secret_file else None
    )
    oauth = (
        {"oauth_key": oauth_signing_key(args.oauth_secret_file)}
        if args.oauth_secret_file
        else {}
    )
    if args.oauth_allow_ecmwf_uids:
        oauth["oauth_allow_ecmwf_uids"] = tuple(args.oauth_allow_ecmwf_uids)
    if args.oauth_aviso_resource:
        oauth["oauth_aviso_resource"] = args.oauth_aviso_resource
    if args.oauth_trusted_proxies:
        oauth["oauth_trusted_proxies"] = tuple(args.oauth_trusted_proxies)
    if args.sso_issuer:
        oauth["oidc"] = {
            "issuer": args.sso_issuer,
            "client_secret": sso_client_secret(args.sso_secret_file),
            "upstream_key": upstream_key(args.upstream_key_file),
        }
    resources, _ = render_api_key(
        project,
        args.chart,
        args.host,
        args.build_image,
        token,
        basic,
        valkey_password=valkey_password,
        replicas=args.replicas,
        session_ttl_seconds=args.session_ttl_seconds,
        transaction_ttl_seconds=args.transaction_ttl_seconds,
        valkey_storage_size=args.valkey_storage_size,
        valkey_storage_class=args.valkey_storage_class,
        **oauth,
    )
    output = directory_fd(output_dir, create=True)
    try:
        private_write(
            output, "resources.yaml", yaml.safe_dump_all(resources, sort_keys=False)
        )
    finally:
        os.close(output)
    print(f"Validated {len(resources)} resources for {NAMESPACE}.")
    print(f"Direct login: https://{args.host}/login")
    if oauth:
        print(f"OAuth issuer: https://{args.host}/")
    if args.sso_issuer:
        print(f"Demo SSO issuer: {args.sso_issuer}")


if __name__ == "__main__":
    main()
