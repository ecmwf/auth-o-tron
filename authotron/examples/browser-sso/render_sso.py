#!/usr/bin/env python3
"""Render the reviewable Keycloak demo SSO bundle; never apply or publish resources."""

import argparse
import base64
from dataclasses import dataclass
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat

import yaml

_EXAMPLES = Path(__file__).parents[1]


def _load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, _EXAMPLES / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preview = _load_module("login_preview", "kubernetes-login-preview/render.py")
private_paths = _load_module(
    "preview_private_paths", "kubernetes-login-preview/private_paths.py"
)
NAMESPACE = preview.NAMESPACE
SECRET_NAME = "authotron-browser-sso"
PREFIX = "authotron-sso-"
SESSION_SECONDS = 900
# Multiarchitecture index pin of Keycloak 26.8.0.
KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741"
SECRET_KEYS = {
    "demo-user-password",
    "authotron-client-secret",
    "e2e-admin-secret",
}
# Auth-O-Tron's OIDC sign-in method on the login playground; render_api_key.py
# configures the same method id and client id (guarded by its tests).
AUTHOTRON_METHOD_ID = "demo-sso"
AUTHOTRON_CLIENT_ID = "authotron-playground"
# Fixed ids: `sub` of the demo user stays stable across Keycloak restarts, and the
# e2e admin addresses the client's offline sessions without client lookups.
AUTHOTRON_CLIENT_UUID = "c307be16-5d3f-43da-9130-f74645cdf791"
DEMO_USER_ID = "cde07bd3-b04d-4390-b75c-e7bfb4135940"
# Service account for end-to-end checks through `kubectl port-forward` only: the
# admin API has no ingress route.
E2E_ADMIN_CLIENT_ID = "authotron-e2e-admin"
E2E_ADMIN_ROLES = ("manage-users", "view-users")
# Offline sessions follow the playground's OAuth refresh-token lifetimes.
OFFLINE_IDLE_SECONDS = 30 * 86400
OFFLINE_MAX_SECONDS = 90 * 86400


def trusted_addresses(value):
    """Canonical addresses or networks of the ingress peers, such as the ingress pod
    range, in Keycloak's `--proxy-trusted-addresses` form. Valid: 10.70.0.0/16,
    10.26.28.1, 10.26.28.1/32 (as 10.26.28.1), 2001:db8::/64. Invalid: 0.0.0.0/0,
    ::/0, 10.70.1.0/16 (host bits set), a repeated entry."""
    result = []
    for item in value.split(","):
        try:
            network = ipaddress.ip_network(item.strip(), strict=True)
        except ValueError:
            raise ValueError(
                "trusted proxies must be canonical IP addresses or networks"
            ) from None
        if network.prefixlen == 0:
            raise ValueError("trusted proxies must not cover every address")
        entry = (
            str(network.network_address)
            if network.prefixlen == network.max_prefixlen
            else str(network)
        )
        if entry in result:
            raise ValueError("duplicate trusted proxy address")
        result.append(entry)
    return tuple(result)


@dataclass(frozen=True)
class Profile:
    ui_host: str
    issuer_host: str
    trusted_proxies: tuple[str, ...]

    def __post_init__(self):
        for host in (self.ui_host, self.issuer_host):
            preview.validate_host(host)
        if self.ui_host == self.issuer_host:
            raise ValueError("UI and issuer hosts must be distinct")
        if not isinstance(self.trusted_proxies, tuple) or not self.trusted_proxies:
            raise ValueError("trusted proxy addresses are mandatory")
        if trusted_addresses(",".join(self.trusted_proxies)) != self.trusted_proxies:
            raise ValueError("trusted proxies must be canonical addresses or networks")

    realm = "aviso-demo"

    @property
    def ui_origin(self):
        return f"https://{self.ui_host}"

    @property
    def issuer(self):
        return f"https://{self.issuer_host}/realms/{self.realm}"

    @property
    def realm_filename(self):
        return f"{self.realm}-realm.json"

    @property
    def issuer_paths(self):
        base = f"/realms/{self.realm}"
        return (
            (base + "/.well-known/openid-configuration", "ImplementationSpecific"),
            (base + "/protocol/openid-connect/auth", "Exact"),
            (base + "/protocol/openid-connect/token", "Exact"),
            (base + "/protocol/openid-connect/revoke", "Exact"),
            (base + "/protocol/openid-connect/certs", "Exact"),
            (base + "/protocol/openid-connect/userinfo", "Exact"),
            (base + "/login-actions/", "Prefix"),
            ("/resources/", "Prefix"),
        )

    @property
    def authotron_callback(self):
        return f"{self.ui_origin}/login/method/{AUTHOTRON_METHOD_ID}/callback"


def resource(kind, name, **fields):
    api = {
        "Deployment": "apps/v1",
        "Ingress": "networking.k8s.io/v1",
    }.get(kind, "v1")
    return {
        "apiVersion": api,
        "kind": kind,
        "metadata": {"name": name, "namespace": NAMESPACE},
        **fields,
    }


def secret_env(name, key):
    return {
        "name": name,
        "valueFrom": {"secretKeyRef": {"name": SECRET_NAME, "key": key}},
    }


def realm_config(profile):
    # Keycloak import substitutes these environment variables, not literal credentials.
    return {
        "realm": profile.realm,
        "enabled": True,
        "registrationAllowed": False,
        "accessTokenLifespan": 60,
        "ssoSessionIdleTimeout": SESSION_SECONDS,
        "ssoSessionMaxLifespan": SESSION_SECONDS,
        "clientSessionIdleTimeout": SESSION_SECONDS,
        "clientSessionMaxLifespan": SESSION_SECONDS,
        # Every refresh rotates the refresh token and spends the old one.
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
        "offlineSessionIdleTimeout": OFFLINE_IDLE_SECONDS,
        "offlineSessionMaxLifespanEnabled": True,
        "offlineSessionMaxLifespan": OFFLINE_MAX_SECONDS,
        "clients": [
            {
                "id": AUTHOTRON_CLIENT_UUID,
                "clientId": AUTHOTRON_CLIENT_ID,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": "${AUTHOTRON_CLIENT_SECRET}",
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False,
                "implicitFlowEnabled": False,
                "serviceAccountsEnabled": False,
                "consentRequired": False,
                "redirectUris": [profile.authotron_callback],
                "webOrigins": [],
                # `basic` provides `sub` and `auth_time`; offline access is optional.
                "defaultClientScopes": ["basic", "profile", "email"],
                "optionalClientScopes": ["offline_access"],
                "attributes": {"pkce.code.challenge.method": "S256"},
            },
            {
                "clientId": E2E_ADMIN_CLIENT_ID,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": "${E2E_ADMIN_SECRET}",
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "implicitFlowEnabled": False,
                "serviceAccountsEnabled": True,
                "consentRequired": False,
                "redirectUris": [],
                "webOrigins": [],
            },
        ],
        "users": [
            {
                "id": DEMO_USER_ID,
                "username": "alice",
                "enabled": True,
                "firstName": "Alice",
                "lastName": "Demo",
                "email": "alice@example.org",
                "emailVerified": True,
                "requiredActions": [],
                "realmRoles": [f"default-roles-{profile.realm}", "offline_access"],
                "credentials": [
                    {
                        "type": "password",
                        "value": "${DEMO_USER_PASSWORD}",
                        "temporary": False,
                    }
                ],
            },
            {
                "username": "service-account-" + E2E_ADMIN_CLIENT_ID,
                "enabled": True,
                "serviceAccountClientId": E2E_ADMIN_CLIENT_ID,
                "clientRoles": {"realm-management": list(E2E_ADMIN_ROLES)},
            },
        ],
    }


def mount(name, path, readonly=False):
    return {"name": name, "mountPath": path, "readOnly": readonly}


def keycloak_deployment(profile):
    security = {
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }
    labels = {"app.kubernetes.io/name": PREFIX + "keycloak"}
    probe = {"tcpSocket": {"port": 8080}}
    container = {
        "name": "keycloak",
        "image": KEYCLOAK_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["/work/bin/kc.sh"],
        "args": [
            "start",
            "--optimized",
            "--db=dev-file",
            "--import-realm",
            "--http-enabled=true",
            "--http-port=8080",
            f"--hostname=https://{profile.issuer_host}",
            "--hostname-backchannel-dynamic=false",
            "--hostname-strict=true",
            "--proxy-headers=xforwarded",
            "--proxy-trusted-addresses=" + ",".join(profile.trusted_proxies),
        ],
        "env": [
            secret_env("AUTHOTRON_CLIENT_SECRET", "authotron-client-secret"),
            secret_env("E2E_ADMIN_SECRET", "e2e-admin-secret"),
            secret_env("DEMO_USER_PASSWORD", "demo-user-password"),
            {"name": "JAVA_OPTS_KC_HEAP", "value": "-Xms128m -Xmx512m"},
        ],
        "ports": [{"name": "http", "containerPort": 8080}],
        "securityContext": security,
        "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"cpu": "1", "memory": "1Gi"},
        },
        "volumeMounts": [
            mount("work", "/work"),
            mount("tmp", "/tmp"),
            mount("realm", "/work/data/import", True),
        ],
        "readinessProbe": {**probe, "periodSeconds": 10},
        "livenessProbe": {**probe, "initialDelaySeconds": 60, "periodSeconds": 10},
    }
    init = {
        "name": "build-keycloak",
        "image": KEYCLOAK_IMAGE,
        "command": ["bash", "-ec"],
        "args": ["cp -R /opt/keycloak/. /work/; /work/bin/kc.sh build --db=dev-file"],
        "env": [{"name": "JAVA_OPTS_KC_HEAP", "value": "-Xms128m -Xmx512m"}],
        "volumeMounts": [mount("work", "/work"), mount("tmp", "/tmp")],
        "resources": {
            "requests": {"cpu": "100m", "memory": "256Mi"},
            "limits": {"cpu": "1", "memory": "1Gi"},
        },
        "securityContext": security.copy(),
    }
    pod = {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "fsGroup": 1000,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "initContainers": [init],
        "containers": [container],
        "volumes": [
            {"name": "tmp", "emptyDir": {"sizeLimit": "128Mi"}},
            {"name": "work", "emptyDir": {"sizeLimit": "2Gi"}},
            {"name": "realm", "configMap": {"name": PREFIX + "realm"}},
        ],
    }
    return resource(
        "Deployment",
        PREFIX + "keycloak",
        spec={
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": pod},
        },
    )


def render_public_sso(profile):
    realm = json.dumps(realm_config(profile), sort_keys=True)
    deployment = keycloak_deployment(profile)
    deployment["spec"]["template"]["metadata"]["annotations"] = {
        "checksum/config": hashlib.sha256(json.dumps([realm]).encode()).hexdigest()
    }
    ingress = resource(
        "Ingress",
        PREFIX + "keycloak",
        spec={
            "ingressClassName": "nginx",
            "tls": [
                {"hosts": [profile.issuer_host], "secretName": PREFIX + "keycloak-tls"}
            ],
            "rules": [
                {
                    "host": profile.issuer_host,
                    "http": {
                        "paths": [
                            {
                                "path": path,
                                "pathType": path_type,
                                "backend": {
                                    "service": {
                                        "name": PREFIX + "keycloak",
                                        "port": {"number": 8080},
                                    }
                                },
                            }
                            for path, path_type in profile.issuer_paths
                        ]
                    },
                }
            ],
        },
    )
    ingress["metadata"]["annotations"] = dict(preview.ANNOTATIONS)
    return [
        resource("ConfigMap", PREFIX + "realm", data={profile.realm_filename: realm}),
        deployment,
        resource(
            "Service",
            PREFIX + "keycloak",
            spec={
                "type": "ClusterIP",
                "selector": {"app.kubernetes.io/name": PREFIX + "keycloak"},
                "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
            },
        ),
        ingress,
    ]


def validate_secrets(bundle):
    if not isinstance(bundle, dict) or set(bundle) != SECRET_KEYS:
        raise ValueError("invalid secret bundle keys")
    for value in bundle.values():
        if (
            not isinstance(value, str)
            or len(value) < 32
            or not all(c.isalnum() or c in "-_" for c in value)
        ):
            raise ValueError("invalid secret bundle value")


def secret_resource(bundle):
    validate_secrets(bundle)
    return resource(
        "Secret",
        SECRET_NAME,
        type="Opaque",
        data={
            key: base64.b64encode(bundle[key].encode()).decode()
            for key in sorted(SECRET_KEYS)
        },
    )


def bind_credentials(resources, bundle):
    """Roll Keycloak when a credential it consumes changes; keep raw values out of Pod
    metadata. Callers validate ``bundle`` first (via ``secret_resource``)."""
    for doc in resources:
        if doc["kind"] != "Deployment":
            continue
        template = doc["spec"]["template"]
        keys = {
            env["valueFrom"]["secretKeyRef"]["key"]
            for container in template["spec"]["containers"]
            for env in container.get("env", [])
            if env.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
            == SECRET_NAME
        }
        if keys:
            checksum = hashlib.sha256(
                json.dumps(
                    {key: bundle[key] for key in sorted(keys)}, sort_keys=True
                ).encode()
            ).hexdigest()
            template["metadata"].setdefault("annotations", {})[
                "checksum/credentials"
            ] = checksum


def validate_sso(resources, profile):
    """Fail closed against the fixed composition, including every Pod and route field."""
    if NAMESPACE != "authotron-playground":
        raise ValueError("unexpected target namespace")
    expected = render_public_sso(profile)
    allowed = {(doc["apiVersion"], doc["kind"]) for doc in expected} | {
        ("v1", "Secret")
    }
    seen = {}
    for doc in resources:
        if (
            not isinstance(doc, dict)
            or (doc.get("apiVersion"), doc.get("kind")) not in allowed
        ):
            raise ValueError("unexpected resource kind or API version")
        metadata = doc.get("metadata", {})
        if metadata.get("namespace") != NAMESPACE:
            raise ValueError("unexpected target namespace")
        identity = (doc["kind"], metadata.get("name"))
        if identity in seen:
            raise ValueError("duplicate resource identity")
        seen[identity] = doc
    secret = seen.get(("Secret", SECRET_NAME), {})
    try:
        bundle = {
            key: base64.b64decode(value, validate=True).decode()
            for key, value in secret.get("data", {}).items()
        }
    except (ValueError, UnicodeError):
        raise ValueError("invalid encoded Secret") from None
    expected.append(secret_resource(bundle))
    bind_credentials(expected, bundle)
    wanted = {(doc["kind"], doc["metadata"]["name"]): doc for doc in expected}
    if seen != wanted:
        raise ValueError(
            "SSO bundle differs from the fixed, namespace-confined profile"
        )
    for doc in resources:
        if doc["kind"] == "ConfigMap" and any(
            value in json.dumps(doc) for value in bundle.values()
        ):
            raise ValueError("credential in public ConfigMap")


def check_path(path):
    path = Path(os.path.abspath(path))
    for ancestor in (*reversed(path.parents), path):
        if ancestor.is_symlink():
            raise ValueError("symlink output paths are not allowed")
    return path


def write_file(path, data, private=False, exclusive=False):
    path = check_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    if exclusive:
        flags |= os.O_EXCL
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("output must be a regular, unlinked file")
        os.fchmod(stream.fileno(), 0o600 if private else 0o644)
        stream.truncate(0)
        stream.write(data if isinstance(data, bytes) else data.encode())


def checked_private_path(path, project):
    return check_path(
        private_paths.checked_private_path(
            path, project, preview.SOURCE_FILES, preview.RESERVED_SOURCE_DIRS
        )
    )


def load_or_create_secrets(path, *, project=None):
    if project is None:
        project = Path(__file__).resolve().parents[3]
    path = checked_private_path(path, project)
    if path.exists():
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError("existing secret file must be regular and mode 0600")
            try:
                bundle = json.load(stream)
            except (ValueError, UnicodeError):
                raise ValueError("invalid secret bundle file") from None
        if not isinstance(bundle, dict) or not set(bundle) <= SECRET_KEYS:
            raise ValueError("invalid secret bundle keys")
        # A bundle from before a key was introduced gains only the missing keys.
        missing = SECRET_KEYS - set(bundle)
        bundle.update({key: secrets.token_urlsafe(32) for key in missing})
        validate_secrets(bundle)
        if missing:
            write_file(path, json.dumps(bundle, sort_keys=True) + "\n", private=True)
        return bundle
    bundle = {key: secrets.token_urlsafe(32) for key in SECRET_KEYS}
    write_file(
        path, json.dumps(bundle, sort_keys=True) + "\n", private=True, exclusive=True
    )
    return bundle


def render_bundle(profile, bundle):
    if NAMESPACE != "authotron-playground":
        raise ValueError("unexpected target namespace")
    sso = render_public_sso(profile) + [secret_resource(bundle)]
    bind_credentials(sso, bundle)
    validate_sso(sso, profile)
    return sso


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("secret-file", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("ui-host", "issuer-host", "trusted-proxy-addresses"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        profile = Profile(
            args.ui_host,
            args.issuer_host,
            trusted_addresses(args.trusted_proxy_addresses),
        )
        if NAMESPACE != "authotron-playground":
            raise ValueError("unexpected target namespace")
        project = Path(__file__).resolve().parents[3]
        output = checked_private_path(args.output_dir, project)
        secret_path = checked_private_path(args.secret_file, project)
        bundle_path = output / "sso-resources.yaml"
        if output.is_relative_to(secret_path) or secret_path.is_relative_to(
            bundle_path
        ):
            raise ValueError("secret file must be separate from rendered outputs")
        checked_private_path(bundle_path, project)
        output.mkdir(parents=True, exist_ok=True)
        bundle = load_or_create_secrets(secret_path, project=project)
        sso = render_bundle(profile, bundle)
        write_file(bundle_path, yaml.safe_dump_all(sso, sort_keys=False), private=True)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Rendering failed: {error}\n")
    print(f"Validated {len(sso)} SSO resources for {NAMESPACE}.")
    print(f"Issuer: {profile.issuer}")
    print(f"Auth-O-Tron callback: {profile.authotron_callback}")


if __name__ == "__main__":
    main()
