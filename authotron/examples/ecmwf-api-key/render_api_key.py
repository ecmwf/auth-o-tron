#!/usr/bin/env python3
"""Render a disposable direct ECMWF API-key playground, without applying it."""

import argparse
import base64
import copy
import hashlib
import importlib.util
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
shared_images = _load_module("shared_images", "shared_images.py")
NAMESPACE = preview.NAMESPACE
SECRET_NAME = "authotron-ecmwf-browser"
PROVIDER = {
    "type": "ecmwf-api",
    "name": "ECMWF API Provider",
    "realm": "ecmwf",
    "uri": "https://api.ecmwf.int/v1",
    "browser": {"label": "ECMWF API key"},
}
BASIC_LABEL = "Username and password"
BASIC_PROVIDER_NAME = "Playground Basic Provider"
BASIC_USERNAME = "browser-demo"
LOGO_PATH = "/static/aviso-logo.png"
VALKEY_IMAGE = shared_images.VALKEY_IMAGE
VALKEY_NAME = f"{preview.RELEASE}-browser-valkey"
VALKEY_PASSWORD_ENV = "AOT_UI__BROWSER_SESSION__BACKEND__PASSWORD"
BASIC_REALM = "browser-demo"
# Opt-in OAuth profile matching the mcp-local remote-mode client registration;
# test_render_api_key.py guards these values against ../mcp-local/demo_settings.py.
OAUTH_KEY_DIR = "/run/secrets/oauth"
OAUTH_KEY_NAME = "signing.pem"
OAUTH_SECRET_KEY = "oauth-signing.pem"
OAUTH_VOLUME = "oauth-signing"
OAUTH_RESOURCE = "https://127.0.0.1:8444/mcp"
OAUTH_SCOPE = "mcp:read"
# The demo tool is synthetic: any verified direct-login user qualifies. mcp-local's
# remote settings mirror this with "required_role": null.
OAUTH_REQUIRED_ROLES = ()
OAUTH_CLIENT = {
    "client_id": "mcp-local",
    "display_name": "Local MCP demo",
    "application_type": "native",
    "redirect_uris": ["http://127.0.0.1:49152/callback"],
    "resources": [{"resource": OAUTH_RESOURCE, "scopes": [OAUTH_SCOPE]}],
}
# NGINX admission rejects dotted paths with Exact/Prefix, so the metadata document
# uses ImplementationSpecific (prefix semantics); every other OAuth route is Exact.
OAUTH_PATH_RULES = (
    ("/oauth/authorize", "Exact"),
    ("/oauth/continue", "Exact"),
    ("/oauth/consent", "Exact"),
    ("/oauth/token", "Exact"),
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
        'appendonly no\nsave ""\nmaxmemory 128mb\nmaxmemory-policy noeviction\n'
        'logfile ""\ndaemonize no\ndir /data\n'
    )


def valkey_resources(app_labels, password):
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
                            {"name": "data", "emptyDir": {}},
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


def oauth_config(host, kid, realms):
    return {
        "enabled": True,
        "issuer": f"https://{host}/",
        "signing": {
            "active_kid": kid,
            "keys": [
                {"kid": kid, "private_key_file": f"{OAUTH_KEY_DIR}/{OAUTH_KEY_NAME}"}
            ],
        },
        "clients": [copy.deepcopy(OAUTH_CLIENT)],
        "resources": [
            {
                "resource": OAUTH_RESOURCE,
                "allowed_realms": list(dict.fromkeys(realms)),
                "scopes": [
                    {"name": OAUTH_SCOPE, "required_roles": list(OAUTH_REQUIRED_ROLES)}
                ],
            }
        ],
    }


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
):
    checked_session_options(
        valkey_password, replicas, session_ttl_seconds, transaction_ttl_seconds
    )
    checked_oauth_profile(oauth_key is not None, valkey_password)
    checked_token(token)
    resources = copy.deepcopy(baseline)
    config_map = next(d for d in resources if d["kind"] == "ConfigMap" and "data" in d)
    config = yaml.safe_load(config_map["data"]["config.yaml"])
    if config["providers"] or config["store"]["enabled"] or not config["ui"]["enabled"]:
        raise ValueError("expected the provider-empty public branding fixture")
    # Provider order is the chooser order: Basic (when enabled) precedes ECMWF.
    config["providers"] = [copy.deepcopy(PROVIDER)]
    config["jwt"]["secret"] = ""
    config["ui"].setdefault("sso", [])
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
            "key_prefix": f"authotron:browser:v1:{preview.RELEASE}",
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
                "browser": {"label": BASIC_LABEL},
            },
        )
        config["augmenters"] = [
            {
                "type": "plain_advanced",
                "name": "Playground Basic roles",
                "realm": BASIC_REALM,
                "match": {"username": [BASIC_USERNAME]},
                "augment": {
                    "roles": ["demo-user", "augmented"],
                    "attributes": {"email": "browser-demo@example.invalid"},
                },
            }
        ]
    if oauth_key is not None:
        realms = [p["realm"] for p in config["providers"] if p.get("browser")]
        config["oauth"] = oauth_config(host, oauth_kid(oauth_key), realms)
    config_map["data"]["config.yaml"] = yaml.safe_dump(config)
    deployment = next(d for d in resources if d["kind"] == "Deployment")
    deployment["spec"]["replicas"] = replicas
    template = deployment["spec"]["template"]
    template["metadata"]["annotations"]["authotron.ecmwf.int/signing-sha256"] = (
        hashlib.sha256(token.encode()).hexdigest()
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
        shared = valkey_resources(template["metadata"]["labels"], valkey_password)
        template["metadata"]["annotations"].update(
            shared[0]["spec"]["template"]["metadata"]["annotations"]
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
    sso=None,
    basic=None,
    *,
    valkey_password=None,
    replicas=1,
    session_ttl_seconds=300,
    transaction_ttl_seconds=300,
    oauth_key=None,
):
    preview.validate_inputs(host, image)
    checked_token(token)
    checked_session_options(
        valkey_password, replicas, session_ttl_seconds, transaction_ttl_seconds
    )
    checked_oauth_profile(oauth_key is not None, valkey_password)
    if oauth_key is not None:
        checked_oauth_key({"private-key-pem": oauth_key})
    if basic is not None:
        checked_basic_credentials(basic)
    baseline, archive = preview.render_preview(project, chart, host, image, sso)
    options = dict(
        valkey_password=valkey_password,
        replicas=replicas,
        session_ttl_seconds=session_ttl_seconds,
        transaction_ttl_seconds=transaction_ttl_seconds,
    )
    if oauth_key is not None:
        options["oauth_key"] = oauth_key
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
    parser.add_argument("--browser-start-url")
    parser.add_argument("--basic-secret-file", type=Path)
    parser.add_argument("--valkey-secret-file", type=Path)
    parser.add_argument("--oauth-secret-file", type=Path)
    parser.add_argument("--replicas", type=int, default=1)
    parser.add_argument("--session-ttl-seconds", type=int, default=300)
    parser.add_argument("--transaction-ttl-seconds", type=int, default=300)
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
    project = Path(__file__).resolve().parents[3]
    output_dir = checked_output_directory(args.output_dir, project)
    credential_paths = [
        checked_credential_path(path, project)
        for path in (
            args.secret_file,
            args.basic_secret_file,
            args.valkey_secret_file,
            args.oauth_secret_file,
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
    actions = None
    if args.browser_start_url:
        value = args.browser_start_url
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.fragment
            or "\\" in value
        ):
            raise ValueError(
                "browser start URL must be a configured HTTPS client endpoint"
            )
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(
                "browser start URL must not contain whitespace or controls"
            )
        preview.validate_inputs(url.hostname, args.build_image)
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError("invalid browser start URL port")
        actions = [{"label": "Continue with demo SSO", "start_url": value}]
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
    resources, _ = render_api_key(
        project,
        args.chart,
        args.host,
        args.build_image,
        token,
        actions,
        basic,
        valkey_password=valkey_password,
        replicas=args.replicas,
        session_ttl_seconds=args.session_ttl_seconds,
        transaction_ttl_seconds=args.transaction_ttl_seconds,
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


if __name__ == "__main__":
    main()
