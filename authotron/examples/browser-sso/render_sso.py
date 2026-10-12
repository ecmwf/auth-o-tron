#!/usr/bin/env python3
"""Render reviewable browser SSO bundles; never apply or publish resources."""

import argparse
import base64
from dataclasses import dataclass
import html
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
from urllib.parse import quote

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
shared_images = _load_module("shared_images", "shared_images.py")
NAMESPACE = preview.NAMESPACE
SECRET_NAME = "authotron-browser-sso"
INGRESS_PEER = {
    "namespaceSelector": {
        "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
    },
    "podSelector": {
        "matchLabels": {
            "app.kubernetes.io/component": "controller",
            "app.kubernetes.io/instance": "rke2-ingress-nginx",
            "app.kubernetes.io/name": "lumi-rke2-cls",
        }
    },
}
PREFIX = "authotron-sso-"
SESSION_SECONDS = 900
REFRESH_SECONDS = 30
IMAGES = {
    # Multiarchitecture index pins: Keycloak 26.8.0, proxy 7.15.5 and
    # unprivileged Nginx 1.28.2-alpine; Valkey is pinned in shared_images.py.
    "keycloak": "quay.io/keycloak/keycloak@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741",
    "oauth2-proxy": "quay.io/oauth2-proxy/oauth2-proxy@sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916",
    "valkey": shared_images.VALKEY_IMAGE,
    "nginx": "docker.io/nginxinc/nginx-unprivileged@sha256:7377697a821c131a924a7105fafbe7414db4e9fcc77a6f08f776f33f141ec3f8",
}
SECRET_KEYS = {
    "client-secret",
    "cookie-secret",
    "valkey-password",
    "demo-user-password",
}
APP_PATHS = (
    ("/", "Exact"),
    ("/account", "Exact"),
    ("/assets/", "Prefix"),
    ("/oauth2/start", "Exact"),
    ("/oauth2/callback", "Exact"),
    ("/oauth2/userinfo", "Exact"),
)


def trusted_addresses(value):
    """Accept host addresses only: 10.26.28.1/32 is valid; 0.0.0.0/0 is not."""
    result = []
    for item in value.split(","):
        try:
            network = ipaddress.ip_network(item.strip(), strict=True)
        except ValueError:
            raise ValueError(
                "trusted proxies must be individual IP addresses"
            ) from None
        if network.prefixlen != network.max_prefixlen:
            raise ValueError("trusted proxies require /32 or /128 host prefixes")
        address = str(network.network_address)
        if address in result:
            raise ValueError("duplicate trusted proxy address")
        result.append(address)
    return tuple(result)


@dataclass(frozen=True)
class Profile:
    ui_host: str
    issuer_host: str
    app_host: str
    build_image: str
    trusted_proxies: tuple[str, ...]

    def __post_init__(self):
        for host in (self.ui_host, self.issuer_host, self.app_host):
            preview.validate_inputs(host, self.build_image)
        if len({self.ui_host, self.issuer_host, self.app_host}) != 3:
            raise ValueError("UI, issuer and application hosts must be distinct")
        if not isinstance(self.trusted_proxies, tuple) or not self.trusted_proxies:
            raise ValueError("trusted proxy addresses are mandatory")
        if trusted_addresses(",".join(self.trusted_proxies)) != self.trusted_proxies:
            raise ValueError(
                "trusted proxies must be canonical individual IP addresses"
            )

    realm = "aviso-demo"
    client_id = "aviso-browser-demo"
    return_path = "/account"

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
            (base + "/protocol/openid-connect/certs", "Exact"),
            (base + "/protocol/openid-connect/userinfo", "Exact"),
            (base + "/login-actions/", "Prefix"),
            ("/resources/", "Prefix"),
        )

    @property
    def callback(self):
        return f"https://{self.app_host}/oauth2/callback"

    @property
    def start_url(self):
        return f"https://{self.app_host}/oauth2/start?rd={quote(self.return_path, safe='')}"

    @property
    def sign_in_actions(self):
        return [{"label": "Continue with demo SSO", "start_url": self.start_url}]


def resource(kind, name, **fields):
    api = {
        "Deployment": "apps/v1",
        "Ingress": "networking.k8s.io/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
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
        "clients": [
            {
                "clientId": profile.client_id,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": "${BROWSER_CLIENT_SECRET}",
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False,
                "implicitFlowEnabled": False,
                "serviceAccountsEnabled": False,
                "consentRequired": False,
                "redirectUris": [profile.callback],
                "webOrigins": [],
                "defaultClientScopes": ["profile", "email"],
                "attributes": {"pkce.code.challenge.method": "S256"},
                "protocolMappers": [
                    {
                        "name": "browser-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.client.audience": profile.client_id,
                            "id.token.claim": "true",
                            "access.token.claim": "true",
                        },
                    }
                ],
            }
        ],
        "users": [
            {
                "username": "alice",
                "enabled": True,
                "firstName": "Alice",
                "lastName": "Demo",
                "email": "alice@example.org",
                "emailVerified": True,
                "requiredActions": [],
                "credentials": [
                    {
                        "type": "password",
                        "value": "${DEMO_USER_PASSWORD}",
                        "temporary": False,
                    }
                ],
            }
        ],
    }


def proxy_args(profile):
    return [
        "--provider=keycloak-oidc",
        "--http-address=0.0.0.0:4180",
        f"--client-id={profile.client_id}",
        f"--oidc-issuer-url={profile.issuer}",
        f"--redirect-url={profile.callback}",
        "--scope=openid profile email",
        "--code-challenge-method=S256",
        "--insecure-oidc-skip-nonce=false",
        "--insecure-oidc-allow-unverified-email=false",
        "--insecure-oidc-skip-issuer-verification=false",
        "--email-domain=example.org",
        "--session-store-type=redis",
        f"--redis-connection-url=redis://{PREFIX}valkey:6379/0",
        "--cookie-name=__Host-aviso_demo",
        "--cookie-secure=true",
        "--cookie-httponly=true",
        "--cookie-path=/",
        "--cookie-samesite=lax",
        "--cookie-csrf-samesite=lax",
        "--cookie-csrf-per-request=true",
        "--cookie-csrf-per-request-limit=5",
        "--cookie-csrf-expire=5m",
        f"--cookie-refresh={REFRESH_SECONDS}s",
        f"--cookie-expire={SESSION_SECONDS}s",
        "--pass-access-token=false",
        "--pass-authorization-header=false",
        "--set-authorization-header=false",
        "--pass-basic-auth=false",
        "--pass-user-headers=false",
        "--skip-auth-strip-headers=true",
        "--reverse-proxy=true",
        f"--upstream=http://{PREFIX}nginx:8080",
        "--skip-auth-route=GET=^/$",
        "--api-route=^/account$",
        "--api-route=^/assets/",
        "--force-json-errors=true",
        "--request-logging=false",
        "--auth-logging=false",
        "--show-debug-on-error=false",
        "--silence-ping-logging=true",
        *[f"--trusted-proxy-ip={address}" for address in profile.trusted_proxies],
    ]


def labels(component):
    return {"app.kubernetes.io/name": PREFIX + component}


def mount(name, path, readonly=False):
    return {"name": name, "mountPath": path, "readOnly": readonly}


def deployment(
    component,
    port,
    args,
    env=(),
    volumes=(),
    mounts=(),
    command=None,
    init=None,
    memory="256Mi",
    health="/health",
):
    security = {
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }
    container = {
        "name": component,
        "image": IMAGES[component],
        "imagePullPolicy": "IfNotPresent",
        "args": args,
        "env": list(env),
        "ports": [{"name": "http", "containerPort": port}],
        "securityContext": security,
        "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"cpu": "1", "memory": memory},
        },
        "volumeMounts": list(mounts),
    }
    if command:
        container["command"] = command
    probe = (
        {"tcpSocket": {"port": port}}
        if health is None
        else {"httpGet": {"path": health, "port": port}}
    )
    container["readinessProbe"] = {**probe, "periodSeconds": 10}
    container["livenessProbe"] = {
        **probe,
        "initialDelaySeconds": 60,
        "periodSeconds": 10,
    }
    uid = 101 if component == "nginx" else 1000
    pod = {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": uid,
            "runAsGroup": uid,
            "fsGroup": uid,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [container],
        "volumes": list(volumes),
    }
    if init:
        init["securityContext"] = security.copy()
        pod["initContainers"] = [init]
    return resource(
        "Deployment",
        PREFIX + component,
        spec={
            "replicas": 1,
            **(
                {"strategy": {"type": "Recreate"}}
                if component in ("keycloak", "valkey")
                else {}
            ),
            "selector": {"matchLabels": labels(component)},
            "template": {"metadata": {"labels": labels(component)}, "spec": pod},
        },
    )


def ingress(component, host, paths, port):
    doc = resource(
        "Ingress",
        PREFIX + component,
        spec={
            "ingressClassName": "nginx",
            "tls": [{"hosts": [host], "secretName": PREFIX + component + "-tls"}],
            "rules": [
                {
                    "host": host,
                    "http": {
                        "paths": [
                            {
                                "path": path,
                                "pathType": path_type,
                                "backend": {
                                    "service": {
                                        "name": PREFIX + component,
                                        "port": {"number": port},
                                    }
                                },
                            }
                            for path, path_type in paths
                        ]
                    },
                }
            ],
        },
    )
    doc["metadata"]["annotations"] = dict(preview.ANNOTATIONS)
    return doc


NGINX_CONFIG = """pid /tmp/nginx.pid;
events {}
http {
  access_log off;
  error_log /dev/stderr warn;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  server {
    listen 8080;
    root /html;
    add_header Cache-Control "no-store" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src {{UI_ORIGIN}}; img-src 'self' https:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
    location = / { default_type text/html; try_files /welcome.html =404; }
    location = /account { default_type text/html; try_files /account.html =404; }
    location = /assets/account.js { default_type application/javascript; alias /html/account.js; }
    location = /health { return 200 "ok"; }
    location / { return 404; }
  }
}
"""


def render_public_sso(profile, assets):
    fixture = preview.preview_values(assets.parents[2], profile.ui_host)["config"]
    substitutions = {
        "LOGIN_URL": profile.ui_origin + "/login",
        "STYLE_URL": profile.ui_origin + "/static/login.css",
        "FAVICON_URL": profile.ui_origin + "/favicon.ico",
        "LOGO_URL": fixture["ui"]["branding"]["logo_url"],
    }
    pages = {}
    for filename in ("welcome.html", "account.html", "account.js"):
        text = preview.checked_source_path(assets, assets / filename).read_text()
        for key, value in substitutions.items():
            text = text.replace("{{" + key + "}}", html.escape(value, quote=True))
        if "{{" in text:
            raise ValueError("unresolved browser template placeholder")
        pages[filename] = text
    docs = [
        resource(
            "ConfigMap",
            PREFIX + "realm",
            data={
                profile.realm_filename: json.dumps(
                    realm_config(profile), sort_keys=True
                )
            },
        ),
        resource("ConfigMap", PREFIX + "pages", data=pages),
        resource(
            "ConfigMap",
            PREFIX + "nginx-config",
            data={
                "nginx.conf": NGINX_CONFIG.replace("{{UI_ORIGIN}}", profile.ui_origin)
            },
        ),
    ]
    tmp = {"name": "tmp", "emptyDir": {"sizeLimit": "128Mi"}}
    kc_mounts = [
        mount("work", "/work"),
        mount("tmp", "/tmp"),
        mount("realm", "/work/data/import", True),
    ]
    init = {
        "name": "build-keycloak",
        "image": IMAGES["keycloak"],
        "command": ["bash", "-ec"],
        "args": ["cp -R /opt/keycloak/. /work/; /work/bin/kc.sh build --db=dev-file"],
        "env": [{"name": "JAVA_OPTS_KC_HEAP", "value": "-Xms128m -Xmx512m"}],
        "volumeMounts": [mount("work", "/work"), mount("tmp", "/tmp")],
        "resources": {
            "requests": {"cpu": "100m", "memory": "256Mi"},
            "limits": {"cpu": "1", "memory": "1Gi"},
        },
    }
    docs.append(
        deployment(
            "keycloak",
            8080,
            [
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
            env=[
                secret_env("BROWSER_CLIENT_SECRET", "client-secret"),
                secret_env("DEMO_USER_PASSWORD", "demo-user-password"),
                {"name": "JAVA_OPTS_KC_HEAP", "value": "-Xms128m -Xmx512m"},
            ],
            volumes=[
                tmp,
                {"name": "work", "emptyDir": {"sizeLimit": "2Gi"}},
                {"name": "realm", "configMap": {"name": PREFIX + "realm"}},
            ],
            mounts=kc_mounts,
            command=["/work/bin/kc.sh"],
            init=init,
            memory="1Gi",
            health=None,
        )
    )
    docs.append(
        deployment(
            "oauth2-proxy",
            4180,
            proxy_args(profile),
            env=[
                secret_env("OAUTH2_PROXY_" + env, key)
                for env, key in (
                    ("CLIENT_SECRET", "client-secret"),
                    ("COOKIE_SECRET", "cookie-secret"),
                    ("REDIS_PASSWORD", "valkey-password"),
                )
            ],
            volumes=[tmp],
            mounts=[mount("tmp", "/tmp")],
            health="/ping",
        )
    )
    docs[-1]["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"][
        "path"
    ] = "/ready"
    docs.append(
        deployment(
            "valkey",
            6379,
            [
                'exec valkey-server --save "" --appendonly no --requirepass "$VALKEY_PASSWORD" '
                "--port 6379 --bind 0.0.0.0 --maxmemory 128mb --maxmemory-policy noeviction"
            ],
            command=["sh", "-ec"],
            env=[secret_env("VALKEY_PASSWORD", "valkey-password")],
            volumes=[tmp, {"name": "data", "emptyDir": {"sizeLimit": "128Mi"}}],
            mounts=[mount("tmp", "/tmp"), mount("data", "/data")],
            health=None,
        )
    )
    docs.append(
        deployment(
            "nginx",
            8080,
            ["-g", "daemon off;"],
            command=["nginx"],
            volumes=[
                tmp,
                {"name": "pages", "configMap": {"name": PREFIX + "pages"}},
                {"name": "config", "configMap": {"name": PREFIX + "nginx-config"}},
            ],
            mounts=[
                mount("tmp", "/tmp"),
                mount("pages", "/html", True),
                {
                    **mount("config", "/etc/nginx/nginx.conf", True),
                    "subPath": "nginx.conf",
                },
            ],
        )
    )
    public_config = {
        doc["metadata"]["name"]: doc["data"]
        for doc in docs
        if doc["kind"] == "ConfigMap"
    }
    for component, inputs in (
        ("keycloak", ("realm",)),
        ("nginx", ("pages", "nginx-config")),
    ):
        checksum = hashlib.sha256(
            json.dumps(
                [public_config[PREFIX + name] for name in inputs], sort_keys=True
            ).encode()
        ).hexdigest()
        target = next(
            doc
            for doc in docs
            if doc["kind"] == "Deployment"
            and doc["metadata"]["name"] == PREFIX + component
        )
        target["spec"]["template"]["metadata"]["annotations"] = {
            "checksum/config": checksum
        }
    for component, port in (
        ("keycloak", 8080),
        ("oauth2-proxy", 4180),
        ("valkey", 6379),
        ("nginx", 8080),
    ):
        docs.append(
            resource(
                "Service",
                PREFIX + component,
                spec={
                    "type": "ClusterIP",
                    "selector": labels(component),
                    "ports": [{"name": "http", "port": port, "targetPort": port}],
                },
            )
        )
    docs.extend(
        [
            ingress("keycloak", profile.issuer_host, profile.issuer_paths, 8080),
            ingress("oauth2-proxy", profile.app_host, APP_PATHS, 4180),
        ]
    )
    for component, port in (("valkey", 6379), ("nginx", 8080)):
        policy = {
            "podSelector": {"matchLabels": labels(component)},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [{"podSelector": {"matchLabels": labels("oauth2-proxy")}}],
                    "ports": [{"protocol": "TCP", "port": port}],
                }
            ],
        }
        if component == "valkey":
            policy.update(policyTypes=["Ingress", "Egress"], egress=[])
        docs.append(resource("NetworkPolicy", PREFIX + component, spec=policy))
    docs.append(
        resource(
            "NetworkPolicy",
            PREFIX + "oauth2-proxy",
            spec={
                "podSelector": {"matchLabels": labels("oauth2-proxy")},
                "policyTypes": ["Ingress"],
                "ingress": [
                    {
                        "from": [INGRESS_PEER],
                        "ports": [{"protocol": "TCP", "port": 4180}],
                    }
                ],
            },
        )
    )
    return docs


def validate_secrets(bundle):
    if not isinstance(bundle, dict) or set(bundle) != SECRET_KEYS:
        raise ValueError("invalid secret bundle keys")
    for key, value in bundle.items():
        if (
            not isinstance(value, str)
            or len(value) < 32
            or any(c.isspace() for c in value)
        ):
            raise ValueError("invalid secret bundle value")
        if key != "cookie-secret" and not all(c.isalnum() or c in "-_" for c in value):
            raise ValueError("invalid password encoding")
    try:
        cookie = base64.b64decode(
            bundle["cookie-secret"], altchars=b"-_", validate=True
        )
    except ValueError:
        raise ValueError("invalid cookie secret encoding") from None
    if len(cookie) != 32:
        raise ValueError("cookie secret must encode 32 bytes")


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
    """Roll only consumers of each credential; keep raw values out of Pod metadata.

    Callers validate ``bundle`` first (via ``secret_resource``).
    """
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


def validate_sso(resources, profile, assets):
    """Fail closed against the fixed composition, including every Pod and route field."""
    if NAMESPACE != "authotron-palyground":
        raise ValueError("unexpected target namespace")
    expected = render_public_sso(profile, assets)
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
        validate_secrets(bundle)
        cookie_bytes = base64.b64decode(
            bundle["cookie-secret"], altchars=b"-_", validate=True
        )
        normalized = base64.urlsafe_b64encode(cookie_bytes).decode()
        if bundle["cookie-secret"] != normalized:
            bundle["cookie-secret"] = normalized
            write_file(path, json.dumps(bundle, sort_keys=True) + "\n", private=True)
        return bundle
    bundle = {key: secrets.token_urlsafe(32) for key in SECRET_KEYS}
    bundle["cookie-secret"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    write_file(
        path, json.dumps(bundle, sort_keys=True) + "\n", private=True, exclusive=True
    )
    return bundle


def render_bundles(project, chart, profile, bundle):
    if NAMESPACE != "authotron-palyground":
        raise ValueError("unexpected target namespace")
    assets = project / "authotron/examples/browser-sso"
    ui, archive = preview.render_preview(
        project, chart, profile.ui_host, profile.build_image, profile.sign_in_actions
    )
    ui = preview.checked_resources(ui)
    if any(
        doc["kind"] == "Secret"
        or any(value in yaml.safe_dump(doc) for value in bundle.values())
        for doc in ui
    ):
        raise ValueError("credential in UI bundle")
    sso = render_public_sso(profile, assets) + [secret_resource(bundle)]
    bind_credentials(sso, bundle)
    validate_sso(sso, profile, assets)
    return ui, sso, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("chart", "secret-file", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in (
        "ui-host",
        "issuer-host",
        "app-host",
        "build-image",
        "trusted-proxy-addresses",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        profile = Profile(
            args.ui_host,
            args.issuer_host,
            args.app_host,
            args.build_image,
            trusted_addresses(args.trusted_proxy_addresses),
        )
        if NAMESPACE != "authotron-palyground":
            raise ValueError("unexpected target namespace")
        project = Path(__file__).resolve().parents[3]
        output = checked_private_path(args.output_dir, project)
        secret_path = checked_private_path(args.secret_file, project)
        outputs = [
            output / name
            for name in (
                "ui-resources.yaml",
                "sso-resources.yaml",
                preview.ARCHIVE_KEY,
                "build.sh",
            )
        ]
        if output.is_relative_to(secret_path) or any(
            secret_path.is_relative_to(path) for path in outputs
        ):
            raise ValueError("secret file must be separate from rendered outputs")
        for path in outputs:
            checked_private_path(path, project)
        output.mkdir(parents=True, exist_ok=True)
        bundle = load_or_create_secrets(secret_path, project=project)
        ui, sso, archive = render_bundles(project, args.chart, profile, bundle)
        write_file(outputs[0], yaml.safe_dump_all(ui, sort_keys=False))
        write_file(outputs[1], yaml.safe_dump_all(sso, sort_keys=False), private=True)
        write_file(outputs[2], archive)
        write_file(outputs[3], preview.BUILD_SCRIPT)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Rendering failed: {error}\n")
    print(f"Validated {len(ui)} UI and {len(sso)} SSO resources for {NAMESPACE}.")
    print(f"Sign in: {profile.ui_origin}/login")
    print(f"Browser demo: https://{profile.app_host}/")
    print(f"Issuer: {profile.issuer}")


if __name__ == "__main__":
    main()
