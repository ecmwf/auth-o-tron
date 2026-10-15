#!/usr/bin/env python3
"""Render and validate a disposable, namespace-confined login preview.

This program never invokes kubectl, publishes an image, or applies resources.
"""

import argparse
import base64
import copy
import gzip
import hashlib
import io
import re
import subprocess
import tarfile
from pathlib import Path

import yaml

NAMESPACE = "authotron-playground"
RELEASE = "authotron-login-preview"
ARCHIVE_KEY = "source.tar.gz"
WORK_DIR = "/work"
SOURCE_DIR = "/source"
TARGET_DIR = f"{WORK_DIR}/target"
EXECUTABLE = f"{TARGET_DIR}/debug/authotron"
BUILD_JOBS = 2
# NGINX admission rejects dotted filenames with Exact/Prefix path types.
# Keep API paths unexposed: only the login page and public image/CSS assets route.
# Exact `/login/` reaches the app's 308 redirect to `/login` instead of an NGINX 404.
PATH_RULES = (
    ("/login", "Exact"),
    ("/login/", "Exact"),
    ("/static/", "Prefix"),
    ("/favicon.ico", "ImplementationSpecific"),
)
ANNOTATIONS = {
    "cert-manager.io/cluster-issuer": "letsencrypt-production",
    "dns.operators.ecmwf.int/on-transport-server": "vs-transport-https",
}
# Reviewed public build-input manifest, not an extension filter or Git snapshot.
# Add new modules/assets here explicitly; RESERVED_SOURCE_DIRS only reserves private paths.
SOURCE_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "authotron/Cargo.toml",
    "authotron/README.md",
    "authotron/schema.json",
    "authotron-types/Cargo.toml",
    "authotron-client/Cargo.toml",
    "authotron-client/src/lib.rs",
    "authotron-types/src/lib.rs",
    "authotron/src/augmenters/base.rs",
    "authotron/src/augmenters/ldap_augmenter.rs",
    "authotron/src/augmenters/mod.rs",
    "authotron/src/augmenters/plain_advanced_augmenter.rs",
    "authotron/src/augmenters/plain_augmenter.rs",
    "authotron/src/auth.rs",
    "authotron/src/browser.rs",
    "authotron/src/browser/valkey.lua",
    "authotron/src/browser/valkey.rs",
    "authotron/src/config/logging.rs",
    "authotron/src/config/mod.rs",
    "authotron/src/config/oauth.rs",
    "authotron/src/config/oauth_policy.rs",
    "authotron/src/config/oauth_signing.rs",
    "authotron/src/config/oauth_upstream.rs",
    "authotron/src/config/oidc.rs",
    "authotron/src/config/oidc/tests.rs",
    "authotron/src/config/store.rs",
    "authotron/src/config/types.rs",
    "authotron/src/config/ui.rs",
    "authotron/src/lib.rs",
    "authotron/src/main.rs",
    "authotron/src/metrics/mod.rs",
    "authotron/src/metrics/recorder.rs",
    "authotron/src/middleware/http_metrics.rs",
    "authotron/src/middleware/mod.rs",
    "authotron/src/models/mod.rs",
    "authotron/src/models/token.rs",
    "authotron/src/models/user.rs",
    "authotron/src/oauth/admin.rs",
    "authotron/src/oauth/admin/tests.rs",
    "authotron/src/oauth/audit.rs",
    "authotron/src/oauth/authentication.rs",
    "authotron/src/oauth/authorization.rs",
    "authotron/src/oauth/code_grant.rs",
    "authotron/src/oauth/codes.rs",
    "authotron/src/oauth/consent.rs",
    "authotron/src/oauth/context.rs",
    "authotron/src/oauth/key_rotation_tests.rs",
    "authotron/src/oauth/keys.rs",
    "authotron/src/oauth/logins.rs",
    "authotron/src/oauth/mod.rs",
    "authotron/src/oauth/rate_limit.rs",
    "authotron/src/oauth/records.rs",
    "authotron/src/oauth/refresh.rs",
    "authotron/src/oauth/refresh_durability.rs",
    "authotron/src/oauth/refresh_grant.rs",
    "authotron/src/oauth/refresh_store.rs",
    "authotron/src/oauth/runtime.rs",
    "authotron/src/oauth/store.rs",
    "authotron/src/oauth/tokens.rs",
    "authotron/src/oauth/upstream.rs",
    "authotron/src/oauth/upstream/tests.rs",
    "authotron/src/oauth/upstream_refresh.rs",
    "authotron/src/oauth/upstream_refresh/tests.rs",
    "authotron/src/oauth/valkey_issue_code.lua",
    "authotron/src/oauth/valkey_redeem_code.lua",
    "authotron/src/oauth/valkey_refresh.lua",
    "authotron/src/oauth/valkey_refresh.rs",
    "authotron/src/oauth/valkey_transactions.lua",
    "authotron/src/oauth/valkey_transactions.rs",
    "authotron/src/oidc/claims.rs",
    "authotron/src/oidc/discovery.rs",
    "authotron/src/oidc/flow.rs",
    "authotron/src/oidc/http.rs",
    "authotron/src/oidc/id_token.rs",
    "authotron/src/oidc/jwks.rs",
    "authotron/src/oidc/method.rs",
    "authotron/src/oidc/method/refresh_tests.rs",
    "authotron/src/oidc/mock.rs",
    "authotron/src/oidc/mod.rs",
    "authotron/src/oidc/token_client.rs",
    "authotron/src/oidc/upstream.rs",
    "authotron/src/providers/base.rs",
    "authotron/src/providers/ecmwf_token_generator_provider.rs",
    "authotron/src/providers/ecmwfapi_provider.rs",
    "authotron/src/providers/efasapi_provider.rs",
    "authotron/src/providers/jwt_provider.rs",
    "authotron/src/providers/mod.rs",
    "authotron/src/providers/openid_offline_provider.rs",
    "authotron/src/providers/plain_provider.rs",
    "authotron/src/routes/account.rs",
    "authotron/src/routes/account/tests.rs",
    "authotron/src/routes/augmenters.rs",
    "authotron/src/routes/auth.rs",
    "authotron/src/routes/browser_login.rs",
    "authotron/src/routes/health.rs",
    "authotron/src/routes/homepage.rs",
    "authotron/src/routes/login.rs",
    "authotron/src/routes/metrics.rs",
    "authotron/src/routes/mod.rs",
    "authotron/src/routes/oauth.rs",
    "authotron/src/routes/oidc_login.rs",
    "authotron/src/routes/oidc_login/authorization_tests.rs",
    "authotron/src/routes/oidc_login/keycloak_tests.rs",
    "authotron/src/routes/oidc_login/offline_tests.rs",
    "authotron/src/routes/oidc_login/tests.rs",
    "authotron/src/routes/providers.rs",
    "authotron/src/routes/tokens.rs",
    "authotron/src/routes/whoami.rs",
    "authotron/src/startup.rs",
    "authotron/src/state.rs",
    "authotron/src/static/aviso-logo.base64",
    "authotron/src/static/favicon.ico",
    "authotron/src/static/index.html",
    "authotron/src/static/login.css",
    "authotron/src/static/login.js",
    "authotron/src/static/logo.png",
    "authotron/src/store/base.rs",
    "authotron/src/store/mod.rs",
    "authotron/src/store/mongodb_store.rs",
    "authotron/src/store/no_store.rs",
    "authotron/src/utils/http_helpers.rs",
    "authotron/src/utils/log_throttle.rs",
    "authotron/src/utils/logger.rs",
    "authotron/src/utils/mod.rs",
    "authotron/src/utils/secret_file.rs",
    "authotron/src/utils/valkey.rs",
    "authotron/src/utils/value.rs",
)
RESERVED_SOURCE_DIRS = ("authotron/src", "authotron-types/src", "authotron-client/src")
ALLOWED_API_KIND_PAIRS = {
    ("v1", "ConfigMap"),
    ("v1", "Service"),
    ("apps/v1", "Deployment"),
    ("networking.k8s.io/v1", "Ingress"),
}
BUILD_SCRIPT = f"""mkdir -p {WORK_DIR}/source {WORK_DIR}/cargo {TARGET_DIR} {WORK_DIR}/tmp
tar -xzf {SOURCE_DIR}/{ARCHIVE_KEY} -C {WORK_DIR}/source
cd {WORK_DIR}/source
cargo build --locked -p authotron --jobs {BUILD_JOBS}
test -x {EXECUTABLE}
"""


def checked_source_path(project, path):
    """Reject symlink ancestry before reading any source or fixture."""
    current = project
    for component in path.relative_to(project).parts:
        current = current / component
        if current.is_symlink():
            raise ValueError(f"source symlink is not allowed: {current}")
    if not path.resolve().is_relative_to(project.resolve()):
        raise ValueError("source path escapes the project")
    return path


def source_archive(project):
    """Read current bytes of the explicit public build-input manifest, even in exports."""
    files = [project / name for name in SOURCE_FILES]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for path in sorted(files):
            checked_source_path(project, path)
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"not a regular source file: {path}")
            data = path.read_bytes()
            entry = tarfile.TarInfo(path.relative_to(project).as_posix())
            entry.size = len(data)
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(data))
    compressed = gzip.compress(buffer.getvalue(), mtime=0)
    if len(compressed) > 700 * 1024:
        raise ValueError("source archive exceeds the preview ConfigMap size budget")
    return compressed


def validate_host(host):
    # Valid: preview.example.org. Invalid: a URL, wildcard or whitespace.
    if (
        not isinstance(host, str)
        or len(host) > 253
        or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+",
            host,
        )
        or any(len(label) > 63 for label in host.split("."))
    ):
        raise ValueError("host must be a concrete DNS hostname")


def validate_inputs(host, image):
    validate_host(host)
    if not re.fullmatch(r"docker\.io/library/rust@sha256:[0-9a-f]{64}", image):
        raise ValueError("build image must be the official Rust image pinned by digest")


def preview_values(project, host):
    config = yaml.safe_load(
        checked_source_path(
            project, project / "authotron/examples/login-ui/aviso.yaml"
        ).read_text()
    )
    if config["providers"] or config["store"]["enabled"] or not config["ui"]["enabled"]:
        raise ValueError("the preview fixture must enable only the branding shell")
    config["server"]["host"] = "0.0.0.0"
    config["metrics"]["enabled"] = False
    port = config["server"]["port"]
    return {
        "nameOverride": RELEASE,
        "fullnameOverride": RELEASE,
        "config": config,
        "service": {"type": "ClusterIP", "port": port, "targetPort": port},
        "metrics": {"enabled": False, "serviceMonitor": {"enabled": False}},
        "mongodb": {"enabled": False},
        "pullSecret": {"enabled": False},
        "extraEnv": [],
        "ingress": {
            "enabled": True,
            "className": "nginx",
            "annotations": ANNOTATIONS,
            "hosts": [
                {
                    "host": host,
                    "paths": [
                        {"path": path, "pathType": path_type}
                        for path, path_type in PATH_RULES
                    ],
                }
            ],
            "tls": [{"hosts": [host], "secretName": f"{RELEASE}-tls"}],
        },
    }


def preview_pod(image, source_name, port, probes):
    security = {
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }
    return {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "fsGroup": 1000,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "initContainers": [
            {
                "name": "build-login-ui",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": ["sh", "-ec"],
                "args": [BUILD_SCRIPT],
                "env": [
                    {"name": name, "value": value}
                    for name, value in {
                        "CARGO_HOME": f"{WORK_DIR}/cargo",
                        "CARGO_TARGET_DIR": TARGET_DIR,
                        "TMPDIR": f"{WORK_DIR}/tmp",
                        "HOME": WORK_DIR,
                    }.items()
                ],
                "securityContext": security,
                "resources": {
                    "requests": {"cpu": "500m", "memory": "1Gi"},
                    "limits": {"cpu": str(BUILD_JOBS), "memory": "4Gi"},
                },
                "volumeMounts": [
                    {"name": "preview-work", "mountPath": WORK_DIR},
                    {
                        "name": "preview-source",
                        "mountPath": SOURCE_DIR,
                        "readOnly": True,
                    },
                ],
            }
        ],
        "containers": [
            {
                "name": "authotron",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": [EXECUTABLE],
                "workingDir": WORK_DIR,
                "env": [{"name": "AOT_CONFIG_PATH", "value": "/app/config.yaml"}],
                "ports": [
                    {"name": "http-auth", "containerPort": port, "protocol": "TCP"}
                ],
                "securityContext": security,
                "resources": {
                    "requests": {"cpu": "50m", "memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "512Mi"},
                },
                "volumeMounts": [
                    {
                        "name": "config-volume",
                        "mountPath": "/app/config.yaml",
                        "subPath": "config.yaml",
                        "readOnly": True,
                    },
                    {"name": "preview-work", "mountPath": WORK_DIR, "readOnly": True},
                ],
                **probes,
            }
        ],
        "volumes": [
            {"name": "config-volume", "configMap": {"name": f"{RELEASE}-config"}},
            {"name": "preview-work", "emptyDir": {"sizeLimit": "8Gi"}},
            {"name": "preview-source", "configMap": {"name": source_name}},
        ],
    }


def checked_resources(documents):
    """Accept only known namespaced kinds; never overwrite a foreign namespace.

    A missing namespace is filled in. `namespace: aviso2-dev` is rejected.
    Namespace objects are intentionally excluded and rendered separately.
    """
    resources = []
    seen = set()
    for document in documents:
        if document is None:
            continue
        if (
            not isinstance(document, dict)
            or (document.get("apiVersion"), document.get("kind"))
            not in ALLOWED_API_KIND_PAIRS
        ):
            raise ValueError("unexpected resource kind or API version")
        document = copy.deepcopy(document)
        metadata = document.get("metadata")
        if not isinstance(metadata, dict) or not metadata.get("name"):
            raise ValueError("resource metadata must include a name")
        if metadata.get("namespace", NAMESPACE) != NAMESPACE:
            raise ValueError("foreign namespace is not allowed")
        metadata["namespace"] = NAMESPACE
        identity = (document["apiVersion"], document["kind"], metadata["name"])
        if identity in seen:
            raise ValueError("duplicate resource identity")
        seen.add(identity)
        resources.append(document)
    return resources


def render_preview(project, chart, host, image):
    validate_inputs(host, image)
    archive = source_archive(project)
    source_hash = hashlib.sha256(archive).hexdigest()
    source_name = f"{RELEASE}-source-{source_hash[:12]}"
    values = preview_values(project, host)
    rendered = subprocess.run(
        [
            "helm",
            "template",
            RELEASE,
            str(chart),
            "--namespace",
            NAMESPACE,
            "--kube-version",
            "1.34.0",
            "-f",
            "-",
        ],
        input=yaml.safe_dump(values),
        text=True,
        check=True,
        capture_output=True,
    ).stdout
    resources = checked_resources(yaml.safe_load_all(rendered))
    expected = {
        ("ConfigMap", f"{RELEASE}-config"),
        ("Deployment", RELEASE),
        ("Service", RELEASE),
        ("Ingress", RELEASE),
    }
    if {(doc["kind"], doc["metadata"]["name"]) for doc in resources} != expected:
        raise ValueError(
            "the chart must render exactly the four expected preview resources"
        )
    config = next(doc for doc in resources if doc["kind"] == "ConfigMap")
    # Use only the public fixture, not additional configuration inherited from chart defaults.
    config["data"] = {"config.yaml": yaml.safe_dump(values["config"])}
    deployment = next(doc for doc in resources if doc["kind"] == "Deployment")
    containers = deployment["spec"]["template"]["spec"]["containers"]
    if len(containers) != 1:
        raise ValueError("expected one application container")
    probes = {key: containers[0][key] for key in ("livenessProbe", "readinessProbe")}
    probe_fields = {
        "httpGet",
        "initialDelaySeconds",
        "periodSeconds",
        "timeoutSeconds",
        "failureThreshold",
        "successThreshold",
    }
    if any(
        set(probe) - probe_fields
        or probe.get("httpGet") != {"path": "/health", "port": "http-auth"}
        for probe in probes.values()
    ):
        raise ValueError("expected application-port HTTP health probes")
    pod = preview_pod(image, source_name, values["config"]["server"]["port"], probes)
    expected_pod = copy.deepcopy(pod)
    deployment["spec"]["replicas"] = 1
    deployment["spec"]["template"]["spec"] = pod
    annotations = deployment["spec"]["template"]["metadata"].get("annotations", {})
    if set(annotations) != {"checksum/config"}:
        raise ValueError("expected only the chart's configuration rollout checksum")
    annotations["authotron.ecmwf.int/source-sha256"] = source_hash
    deployment["spec"]["template"]["metadata"]["annotations"] = annotations
    resources.append(
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "immutable": True,
            "metadata": {"name": source_name, "namespace": NAMESPACE},
            "binaryData": {ARCHIVE_KEY: base64.b64encode(archive).decode("ascii")},
        }
    )
    validate_preview(resources, values, expected_pod)
    return resources, archive


def validate_preview(resources, values, expected_pod):
    """Fail closed on unexpected exposure or changed executable/volume/identity."""
    resources = checked_resources(resources)
    config = next(
        doc
        for doc in resources
        if doc["kind"] == "ConfigMap" and doc["metadata"]["name"] == f"{RELEASE}-config"
    )
    if (
        set(config) != {"apiVersion", "kind", "metadata", "data"}
        or set(config.get("data", {})) != {"config.yaml"}
        or yaml.safe_load(config["data"]["config.yaml"]) != values["config"]
    ):
        raise ValueError(
            "rendered application configuration differs from the preview fixture"
        )
    service = next(doc for doc in resources if doc["kind"] == "Service")
    port = values["config"]["server"]["port"]
    if (
        set(service["spec"]) != {"type", "ports", "selector"}
        or service["spec"]["type"] != "ClusterIP"
        or service["metadata"].get("annotations") not in (None, {})
    ):
        raise ValueError("only the internal preview Service is allowed")
    if service["spec"]["ports"] != [
        {"name": "http-auth", "port": port, "targetPort": port, "protocol": "TCP"}
    ]:
        raise ValueError("unexpected Service port")
    ingress = next(doc for doc in resources if doc["kind"] == "Ingress")
    host = values["ingress"]["hosts"][0]["host"]
    expected_ingress = {
        "ingressClassName": "nginx",
        "tls": values["ingress"]["tls"],
        "rules": [
            {
                "host": host,
                "http": {
                    "paths": [
                        {
                            "path": path,
                            "pathType": path_type,
                            "backend": {
                                "service": {"name": RELEASE, "port": {"number": port}}
                            },
                        }
                        for path, path_type in PATH_RULES
                    ]
                },
            }
        ],
    }
    if (
        ingress["spec"] != expected_ingress
        or ingress["metadata"].get("annotations") != ANNOTATIONS
    ):
        raise ValueError("unexpected ingress host, paths, backend, TLS or annotations")
    deployment = next(doc for doc in resources if doc["kind"] == "Deployment")
    if deployment["spec"]["template"]["spec"] != expected_pod:
        raise ValueError("unexpected Pod configuration")
    labels = deployment["spec"]["template"]["metadata"]["labels"]
    expected_selector = {
        "app.kubernetes.io/name": RELEASE,
        "app.kubernetes.io/instance": RELEASE,
    }
    if service["spec"]["selector"] != expected_selector or any(
        labels.get(key) != value for key, value in expected_selector.items()
    ):
        raise ValueError("Service selector does not match the preview Pod")
    sources = [
        doc for doc in resources if doc["kind"] == "ConfigMap" and doc is not config
    ]
    if (
        len(sources) != 1
        or set(sources[0])
        != {"apiVersion", "kind", "metadata", "immutable", "binaryData"}
        or sources[0].get("immutable") is not True
        or set(sources[0].get("binaryData", {})) != {ARCHIVE_KEY}
    ):
        raise ValueError("expected one immutable source archive")
    archive = base64.b64decode(sources[0]["binaryData"][ARCHIVE_KEY], validate=True)
    source_hash = hashlib.sha256(archive).hexdigest()
    annotations = deployment["spec"]["template"]["metadata"].get("annotations", {})
    if (
        sources[0]["metadata"]["name"] != f"{RELEASE}-source-{source_hash[:12]}"
        or annotations.get("authotron.ecmwf.int/source-sha256") != source_hash
        or not annotations.get("checksum/config")
    ):
        raise ValueError(
            "archive identity or configuration rollout checksum is inconsistent"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chart", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--build-image", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[3]
    resources, archive = render_preview(
        project, args.chart, args.host, args.build_image
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "resources.yaml").write_text(
        yaml.safe_dump_all(resources, sort_keys=False)
    )
    (args.output_dir / "namespace.yaml").write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": NAMESPACE},
            }
        )
    )
    (args.output_dir / ARCHIVE_KEY).write_bytes(archive)
    (args.output_dir / "build.sh").write_text(BUILD_SCRIPT)
    config = next(
        doc for doc in resources if doc["kind"] == "ConfigMap" and "data" in doc
    )
    (args.output_dir / "application.yaml").write_text(config["data"]["config.yaml"])
    print(
        f"Validated {len(resources)} resources for {NAMESPACE}; source archive {len(archive)} bytes."
    )
    print(f"Preview URL: https://{args.host}/login")
    print("No Kubernetes resources were applied and no images were published.")


if __name__ == "__main__":
    main()
