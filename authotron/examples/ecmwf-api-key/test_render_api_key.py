"""Offline contracts using explicit public fixtures and mocked Helm."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import render_api_key as renderer
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST = "authotron-playground.lumi.apps.dte.destination-earth.eu"
IMAGE = "docker.io/library/rust@sha256:" + "a" * 64
TOKEN = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
VALKEY_PASSWORD = (
    base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip("=")
)
BASIC = {"username": renderer.BASIC_USERNAME, "password": TOKEN}
# Synthetic disposable keys generated per test run; never read from private files.
OAUTH_KEY = renderer.oauth_pem(
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
)
OTHER_OAUTH_KEY = renderer.oauth_pem(
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
)
# sha256 of yaml.safe_dump_all(..., sort_keys=False) captured before the OAuth profile,
# re-captured when the Ingress moved from per-method Exact paths to one `/login/` Prefix
# (the only difference from the previous digests), and again when provider `browser`
# blocks gained stable ids and the Valkey key_prefix dropped its `v1` segment, and
# again whenever the source manifest gains modules (refresh tokens, rate limits,
# OIDC sign-in), and again when every playground profile enabled the in-cluster
# metrics port.
PRE_OAUTH_DIGESTS = {
    "plain": "d9dbe050a980338c9532051032a7c47a70b81c6c9348c7a747f2267c2892cf2d",
    "basic": "d223c6c4f1621e9562765e452c28a5d83f55a919c74c9afc69e29d10c19a29ce",
    "shared": "ec054b556ae61281144352ea94b7a16a5ea1421e5f0a273a6a1a04ecf2a50916",
}
# One `/login/` Prefix replaces per-method Exact paths, independent of method count.
API_KEY_PATH_RULES = [
    ("/login", "Exact"),
    ("/login/", "Prefix"),
    ("/static/", "Prefix"),
    ("/favicon.ico", "ImplementationSpecific"),
]
AVISO = "https://aviso-mcp-dev.lumi.apps.dte.destination-earth.eu/mcp"
OAUTH_ROUTES = [
    ("/oauth/authorize", "Exact"),
    ("/oauth/continue", "Exact"),
    ("/oauth/consent", "Exact"),
    ("/oauth/token", "Exact"),
    ("/oauth/revoke", "Exact"),
    ("/oauth/jwks", "Exact"),
    ("/.well-known/oauth-authorization-server", "ImplementationSpecific"),
]


def load_mcp_settings():
    """Load mcp-local's settings contract by path; it is not an installed module."""
    path = Path(__file__).resolve().parent.parent / "mcp-local" / "demo_settings.py"
    spec = importlib.util.spec_from_file_location("mcp_local_demo_settings", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find(resources, kind):
    return next(doc for doc in resources if doc["kind"] == kind)


class RendererTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        for name in renderer.preview.SOURCE_FILES:
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("public build input\n")
        for name in renderer.preview.RESERVED_SOURCE_DIRS:
            path = self.project / name / "lib.rs"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// public source\n")
        fixture = self.project / "authotron/examples/login-ui/aviso.yaml"
        fixture.parent.mkdir(parents=True)
        fixture.write_text(
            yaml.safe_dump(
                {
                    "server": {"host": "127.0.0.1", "port": 8080},
                    "providers": [],
                    "store": {"enabled": False},
                    "metrics": {"enabled": False},
                    "services": [],
                    "jwt": {
                        "iss": "public-fixture",
                        "exp": 300,
                        "secret": "public-demo",
                    },
                    "ui": {"enabled": True, "branding": {"application_name": "Aviso"}},
                }
            )
        )

    def helm_documents(self):
        preview = renderer.preview
        values = preview.preview_values(self.project, HOST)
        labels = {
            "app.kubernetes.io/name": preview.RELEASE,
            "app.kubernetes.io/instance": preview.RELEASE,
        }
        metadata = {"name": preview.RELEASE, "namespace": preview.NAMESPACE}
        probe = {"httpGet": {"path": "/health", "port": "http-auth"}}
        return [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": f"{preview.RELEASE}-config"},
                "data": {},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": metadata,
                "spec": {
                    "template": {
                        "metadata": {
                            "labels": labels,
                            "annotations": {"checksum/config": "chart-checksum"},
                        },
                        "spec": {
                            "containers": [
                                {"livenessProbe": probe, "readinessProbe": probe}
                            ]
                        },
                    }
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
                            "name": "http-auth",
                            "port": 8080,
                            "targetPort": 8080,
                            "protocol": "TCP",
                        }
                    ],
                },
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {**metadata, "annotations": preview.ANNOTATIONS},
                "spec": {
                    "ingressClassName": "nginx",
                    "tls": values["ingress"]["tls"],
                    "rules": [
                        {
                            "host": HOST,
                            "http": {
                                "paths": [
                                    {
                                        "path": path,
                                        "pathType": path_type,
                                        "backend": {
                                            "service": {
                                                "name": preview.RELEASE,
                                                "port": {"number": 8080},
                                            }
                                        },
                                    }
                                    for path, path_type in preview.PATH_RULES
                                ]
                            },
                        }
                    ],
                },
            },
        ]

    def baseline(self):
        with patch.object(renderer.preview.subprocess, "run") as command:
            command.return_value.stdout = yaml.safe_dump_all(self.helm_documents())
            resources, archive = renderer.preview.render_preview(
                self.project, self.project, HOST, IMAGE
            )
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][:2], ["helm", "template"])
        return resources, archive

    def test_direct_render_contract_and_stable_repeated_output(self):
        baseline, archive = self.baseline()
        original = copy.deepcopy(baseline)
        resources = renderer.transform(baseline, HOST, TOKEN)
        renderer.validate_resources(resources, baseline, HOST, IMAGE, TOKEN)
        self.assertEqual(baseline, original)
        self.assertEqual(resources, renderer.transform(baseline, HOST, TOKEN))
        self.assertEqual(len(resources), 6)
        self.assertTrue(
            all(d["metadata"]["namespace"] == renderer.NAMESPACE for d in resources)
        )
        config_map = next(
            d for d in resources if d["kind"] == "ConfigMap" and "data" in d
        )
        config = yaml.safe_load(config_map["data"]["config.yaml"])
        self.assertEqual(config["providers"], [renderer.PROVIDER])
        self.assertEqual(
            config["providers"][0]["browser"],
            {"id": "ecmwf-api-key", "label": "ECMWF API key"},
        )
        self.assertNotIn("ecmwf_api_key", config["ui"])
        self.assertEqual(
            config["ui"]["browser_session"],
            {
                "public_origin": f"https://{HOST}",
                "session_ttl_seconds": 300,
                "transaction_ttl_seconds": 300,
                "backend": {"type": "memory"},
            },
        )
        self.assertEqual(config["ui"]["sso"], [])
        self.assertEqual(config["ui"]["branding"]["logo_url"], renderer.LOGO_PATH)
        self.assertFalse(config["store"]["enabled"])
        self.assertEqual(config["services"], [])
        self.assertEqual(config["jwt"]["secret"], "")
        self.assertNotIn(TOKEN, config_map["data"]["config.yaml"])
        deployment = find(resources, "Deployment")
        pod = deployment["spec"]["template"]["spec"]
        self.assertEqual(
            pod["containers"][0]["env"],
            [
                {"name": "AOT_CONFIG_PATH", "value": "/app/config.yaml"},
                {
                    "name": "AOT_JWT__SECRET",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": renderer.SECRET_NAME,
                            "key": "jwt-secret",
                        }
                    },
                },
            ],
        )
        baseline_pod = find(baseline, "Deployment")["spec"]["template"]["spec"]
        actual_pod = copy.deepcopy(pod)
        actual_pod["containers"][0]["env"].pop()
        self.assertEqual(
            actual_pod["containers"][0]["ports"].pop(),
            {"name": "http-metrics", "containerPort": 9090, "protocol": "TCP"},
        )
        self.assertEqual(actual_pod, baseline_pod)
        annotations = deployment["spec"]["template"]["metadata"]["annotations"]
        self.assertEqual(
            annotations["checksum/config"],
            hashlib.sha256(config_map["data"]["config.yaml"].encode()).hexdigest(),
        )
        self.assertEqual(
            annotations["authotron.ecmwf.int/source-sha256"],
            hashlib.sha256(archive).hexdigest(),
        )
        self.assertEqual(
            next(d for d in resources if "binaryData" in d),
            next(d for d in baseline if "binaryData" in d),
        )
        secret = find(resources, "Secret")
        self.assertEqual(secret["type"], "Opaque")
        self.assertEqual(base64.b64decode(secret["data"]["jwt-secret"]).decode(), TOKEN)
        self.assertNotIn("stringData", secret)
        paths = find(resources, "Ingress")["spec"]["rules"][0]["http"]["paths"]
        self.assertEqual(
            [(p["path"], p["pathType"]) for p in paths],
            API_KEY_PATH_RULES,
        )

    def test_metrics_are_served_in_cluster_but_never_routed_by_the_ingress(self):
        baseline, _ = self.baseline()
        for options in ({}, dict(valkey_password=VALKEY_PASSWORD, oauth_key=OAUTH_KEY)):
            resources = renderer.transform(baseline, HOST, TOKEN, BASIC, **options)
            config = yaml.safe_load(find(resources, "ConfigMap")["data"]["config.yaml"])
            self.assertEqual(config["metrics"], {"enabled": True, "port": 9090})
            self.assertNotEqual(config["server"]["port"], 9090)
            service_ports = {
                p["name"]: p["port"]
                for p in find(resources, "Service")["spec"]["ports"]
            }
            self.assertEqual(service_ports["http-metrics"], 9090)
            app = renderer.preview.RELEASE
            backends = [
                p["backend"]["service"]
                for p in find(resources, "Ingress")["spec"]["rules"][0]["http"]["paths"]
            ]
            self.assertTrue(backends)
            for backend in backends:
                self.assertEqual(backend["name"], app)
                self.assertNotEqual(backend["port"].get("number"), 9090)
                self.assertNotEqual(backend["port"].get("name"), "http-metrics")
            self.assertFalse([d for d in resources if d["kind"] == "ServiceMonitor"])

    def test_oauth_allowed_realms_are_deduplicated_in_order(self):
        config = renderer.oauth_config(
            "login.example.test", "kid", ["b", "a", "b", "a"]
        )
        self.assertEqual(config["resources"][0]["allowed_realms"], ["b", "a"])

    def test_public_render_entry_point(self):
        with patch.object(renderer.preview.subprocess, "run") as command:
            command.return_value.stdout = yaml.safe_dump_all(self.helm_documents())
            resources, archive = renderer.render_api_key(
                self.project, self.project, HOST, IMAGE, TOKEN
            )
        self.assertEqual(len(resources), 6)
        self.assertTrue(archive)
        self.assertEqual(command.call_count, 1)

    def test_shared_profile_private_config_and_exact_resources(self):
        baseline, archive = self.baseline()
        for basic in (None, BASIC):
            with self.subTest(basic=basic is not None):
                options = dict(
                    valkey_password=VALKEY_PASSWORD,
                    replicas=2,
                    session_ttl_seconds=86400,
                    transaction_ttl_seconds=30,
                )
                resources = renderer.transform(baseline, HOST, TOKEN, basic, **options)
                renderer.validate_resources(
                    resources, baseline, HOST, IMAGE, TOKEN, basic, **options
                )
                self.assertEqual(
                    set(renderer.resource_map(resources)),
                    set(renderer.resource_map(baseline))
                    | {
                        ("v1", "Secret", renderer.SECRET_NAME),
                        ("v1", "PersistentVolumeClaim", renderer.VALKEY_NAME),
                        ("apps/v1", "Deployment", renderer.VALKEY_NAME),
                        ("v1", "Service", renderer.VALKEY_NAME),
                        ("networking.k8s.io/v1", "NetworkPolicy", renderer.VALKEY_NAME),
                    },
                )
                self.assertEqual(len(resources), 10)
                public_text = find(resources, "ConfigMap")["data"]["config.yaml"]
                public = yaml.safe_load(public_text)
                session = public["ui"]["browser_session"]
                self.assertEqual(session["session_ttl_seconds"], 86400)
                self.assertEqual(session["transaction_ttl_seconds"], 30)
                self.assertEqual(
                    session["backend"],
                    {
                        "type": "valkey",
                        "url": f"redis://{renderer.VALKEY_NAME}:6379/0",
                        "key_prefix": f"authotron:browser:{renderer.preview.RELEASE}",
                        "connect_timeout_ms": 2000,
                        "operation_timeout_ms": 1000,
                    },
                )
                app = find(resources, "Deployment")
                self.assertEqual(app["spec"]["replicas"], 2)
                self.assertEqual(
                    app["spec"]["template"]["spec"]["containers"][0]["env"][-1],
                    renderer.secret_env(
                        renderer.VALKEY_PASSWORD_ENV, "valkey-password"
                    ),
                )
                secret = find(resources, "Secret")["data"]
                self.assertEqual(
                    base64.b64decode(secret["valkey-password"]).decode(),
                    VALKEY_PASSWORD,
                )
                self.assertEqual(
                    base64.b64decode(secret["valkey.conf"]).decode(),
                    renderer.valkey_config(VALKEY_PASSWORD),
                )
                if basic:
                    private = yaml.safe_load(base64.b64decode(secret["config.yaml"]))
                    private["providers"][0]["users"] = []
                    self.assertEqual(private, public)
                else:
                    self.assertNotIn("config.yaml", secret)
                    self.assertIn(
                        "configMap", app["spec"]["template"]["spec"]["volumes"][0]
                    )
                valkey = next(
                    d
                    for d in resources
                    if d["kind"] == "Deployment"
                    and d["metadata"]["name"] == renderer.VALKEY_NAME
                )
                pod = valkey["spec"]["template"]["spec"]
                self.assertEqual(valkey["spec"]["strategy"], {"type": "Recreate"})
                container = pod["containers"][0]
                self.assertEqual(container["image"], renderer.VALKEY_IMAGE)
                self.assertEqual(
                    container["command"], ["valkey-server", "/etc/valkey/valkey.conf"]
                )
                self.assertEqual(
                    container["env"],
                    [renderer.secret_env("VALKEYCLI_AUTH", "valkey-password")],
                )
                for probe in ("livenessProbe", "readinessProbe"):
                    self.assertEqual(
                        container[probe]["exec"]["command"],
                        ["sh", "-ec", 'test "$(valkey-cli -h 127.0.0.1 ping)" = PONG'],
                    )
                self.assertEqual(
                    pod["volumes"][0]["secret"]["items"],
                    [{"key": "valkey.conf", "path": "valkey.conf"}],
                )
                self.assertEqual(pod["volumes"][0]["secret"]["defaultMode"], 0o440)
                self.assertEqual(pod["securityContext"]["fsGroup"], 1000)
                self.assertIn(
                    {
                        "name": "data",
                        "persistentVolumeClaim": {"claimName": renderer.VALKEY_NAME},
                    },
                    pod["volumes"],
                )
                claim = find(resources, "PersistentVolumeClaim")["spec"]
                self.assertEqual(
                    claim,
                    {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "1Gi"}},
                    },
                )
                conf = renderer.valkey_config(VALKEY_PASSWORD).splitlines()
                for line in ("appendonly yes", "appendfsync everysec", "dir /data"):
                    self.assertIn(line, conf)
                policy = find(resources, "NetworkPolicy")["spec"]
                self.assertEqual(
                    policy["ingress"][0]["from"],
                    [
                        {
                            "podSelector": {
                                "matchLabels": app["spec"]["template"]["metadata"][
                                    "labels"
                                ]
                            }
                        }
                    ],
                )
                for doc in resources:
                    if doc["kind"] != "Secret":
                        self.assertNotIn(VALKEY_PASSWORD, yaml.safe_dump(doc))
                self.assertNotIn(VALKEY_PASSWORD.encode(), archive)

    def test_shared_profile_rejects_exposure_password_and_reference_mutations(self):
        baseline, _ = self.baseline()
        options = dict(valkey_password=VALKEY_PASSWORD, replicas=2)
        resources = renderer.transform(baseline, HOST, TOKEN, BASIC, **options)

        def valkey(docs):
            return next(
                d
                for d in docs
                if d["kind"] == "Deployment"
                and d["metadata"]["name"] == renderer.VALKEY_NAME
            )

        def pod(docs):
            return valkey(docs)["spec"]["template"]["spec"]

        mutations = [
            lambda d: valkey(d)["spec"].update(strategy={"type": "RollingUpdate"}),
            lambda d: pod(d)["volumes"].__setitem__(
                1, {"name": "data", "emptyDir": {}}
            ),
            lambda d: find(d, "PersistentVolumeClaim")["spec"].update(
                accessModes=["ReadWriteMany"]
            ),
            lambda d: d.remove(find(d, "PersistentVolumeClaim")),
            lambda d: valkey(d)["metadata"].update(namespace="other"),
            lambda d: pod(d).update(hostNetwork=True),
            lambda d: pod(d).update(automountServiceAccountToken=True),
            lambda d: pod(d)["containers"][0]["securityContext"].update(
                privileged=True
            ),
            lambda d: pod(d)["volumes"][0]["secret"].update(secretName="other"),
            lambda d: pod(d)["volumes"][0]["secret"]["items"].append(
                {"key": "config.yaml", "path": "config.yaml"}
            ),
            lambda d: pod(d)["containers"][0]["env"][0]["valueFrom"][
                "secretKeyRef"
            ].update(key="jwt-secret"),
            lambda d: pod(d)["containers"][0]["command"].extend(
                ["--requirepass", VALKEY_PASSWORD]
            ),
            lambda d: pod(d)["containers"][0]["ports"][0].update(hostPort=6379),
            lambda d: next(
                x
                for x in d
                if x["kind"] == "Service"
                and x["metadata"]["name"] == renderer.VALKEY_NAME
            )["spec"].update(type="LoadBalancer"),
            lambda d: find(d, "NetworkPolicy")["spec"]["ingress"][0]["from"][0].update(
                namespaceSelector={}
            ),
            lambda d: find(d, "NetworkPolicy")["spec"]["ingress"][0].update(
                **{"from": []}
            ),
            lambda d: find(d, "NetworkPolicy")["spec"].update(podSelector={}),
            lambda d: find(d, "ConfigMap")["data"].update(password=VALKEY_PASSWORD),
            lambda d: next(x for x in d if "binaryData" in x)["binaryData"].update(
                leak=base64.b64encode(VALKEY_PASSWORD.encode()).decode()
            ),
            lambda d: find(d, "Secret")["data"].update(**{"valkey-password": "wrong"}),
            lambda d: find(d, "Secret")["data"].update(**{"valkey.conf": "wrong"}),
            lambda d: find(d, "Deployment")["spec"]["template"]["spec"]["containers"][
                0
            ]["env"][-1]["valueFrom"]["secretKeyRef"].update(name="other"),
            lambda d: find(d, "Deployment")["spec"]["template"]["metadata"][
                "annotations"
            ].update(**{"checksum/valkey-password": "wrong"}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                candidate = copy.deepcopy(resources)
                mutate(candidate)
                with self.assertRaises(ValueError):
                    renderer.validate_resources(
                        candidate, baseline, HOST, IMAGE, TOKEN, BASIC, **options
                    )

    def test_valkey_storage_options(self):
        baseline, _ = self.baseline()
        resources = renderer.transform(
            baseline,
            HOST,
            TOKEN,
            valkey_password=VALKEY_PASSWORD,
            valkey_storage_size="512Mi",
            valkey_storage_class="longhorn",
        )
        claim = find(resources, "PersistentVolumeClaim")["spec"]
        self.assertEqual(claim["resources"]["requests"]["storage"], "512Mi")
        self.assertEqual(claim["storageClassName"], "longhorn")
        for size, storage_class in (
            ("1G", None),
            ("0Gi", None),
            ("10000Gi", None),
            (1, None),
            ("1Gi", "Bad_Class"),
            ("1Gi", ""),
            ("1Gi", "a" * 254),
        ):
            with self.subTest(size=size, storage_class=storage_class):
                with self.assertRaises(ValueError):
                    renderer.transform(
                        baseline,
                        HOST,
                        TOKEN,
                        valkey_password=VALKEY_PASSWORD,
                        valkey_storage_size=size,
                        valkey_storage_class=storage_class,
                    )

    def test_valkey_rotation_rolls_both_pods_without_changing_public_config(self):
        baseline, _ = self.baseline()
        original = renderer.transform(
            baseline, HOST, TOKEN, valkey_password=VALKEY_PASSWORD
        )
        rotated = renderer.transform(baseline, HOST, TOKEN, valkey_password=TOKEN)
        self.assertEqual(find(original, "ConfigMap"), find(rotated, "ConfigMap"))
        for name in (renderer.preview.RELEASE, renderer.VALKEY_NAME):

            def annotations(docs):
                return next(
                    d
                    for d in docs
                    if d["kind"] == "Deployment" and d["metadata"]["name"] == name
                )["spec"]["template"]["metadata"]["annotations"]

            for key in ("checksum/valkey-password", "checksum/valkey-config"):
                self.assertNotEqual(
                    annotations(original)[key], annotations(rotated)[key]
                )

    def test_valkey_private_file_reuse_and_strict_schema(self):
        path = self.root / "valkey.json"
        password = renderer.valkey_secret(path)
        self.assertEqual(renderer.valkey_secret(path), password)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(json.loads(path.read_text())), {"valkey-password"})
        for payload in (
            {"valkey-password": "short"},
            {"valkey-password": password, "jwt-secret": TOKEN},
            [],
            {"valkey-password": "_" * 43},
        ):
            path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                renderer.valkey_secret(path)
            self.assertNotIn(password, str(error.exception))

    def test_session_options_fail_before_helm(self):
        for options in (
            {"replicas": 2},
            {"replicas": 0},
            {"replicas": True},
            {"session_ttl_seconds": 59},
            {"session_ttl_seconds": 86401},
            {"transaction_ttl_seconds": 29},
            {"transaction_ttl_seconds": 901},
            {"valkey_password": "invalid"},
        ):
            with patch.object(renderer.preview.subprocess, "run") as command:
                with self.assertRaises(ValueError):
                    renderer.render_api_key(
                        self.project, self.project, HOST, IMAGE, TOKEN, **options
                    )
                command.assert_not_called()
        baseline, _ = self.baseline()
        resources = renderer.transform(baseline, HOST, TOKEN)
        find(resources, "Deployment")["spec"]["replicas"] = 2
        with self.assertRaises(ValueError):
            renderer.validate_resources(resources, baseline, HOST, IMAGE, TOKEN)

    def test_basic_credentials_stay_in_secret_and_roles_come_from_augmenter(self):
        baseline, archive = self.baseline()
        resources = renderer.transform(baseline, HOST, TOKEN, BASIC)
        renderer.validate_resources(resources, baseline, HOST, IMAGE, TOKEN, BASIC)
        self.assertEqual(len(resources), 6)
        config_map = next(
            doc for doc in resources if doc["kind"] == "ConfigMap" and "data" in doc
        )
        public = yaml.safe_load(config_map["data"]["config.yaml"])
        self.assertEqual(public["providers"][0]["users"], [])
        self.assertEqual(public["providers"][0]["name"], renderer.BASIC_PROVIDER_NAME)
        self.assertEqual(
            [p["browser"] for p in public["providers"]],
            [
                {"id": "password", "label": "Username and password"},
                {"id": "ecmwf-api-key", "label": "ECMWF API key"},
            ],
        )
        self.assertNotIn("basic", public["ui"])
        self.assertEqual(
            public["ui"]["browser_session"]["public_origin"], f"https://{HOST}"
        )
        self.assertEqual(
            public["augmenters"][0]["augment"]["roles"], ["demo-user", "augmented"]
        )
        secret = find(resources, "Secret")
        private_text = base64.b64decode(secret["data"]["config.yaml"]).decode()
        private = yaml.safe_load(private_text)
        self.assertEqual(private["providers"][0]["users"], [{**BASIC, "roles": []}])
        private["providers"][0]["users"] = []
        self.assertEqual(private, public)
        for doc in resources:
            if doc["kind"] != "Secret":
                self.assertNotIn(BASIC["password"], yaml.safe_dump(doc))
        self.assertNotIn(BASIC["password"].encode(), archive)
        pod = find(resources, "Deployment")["spec"]["template"]["spec"]
        volume = next(v for v in pod["volumes"] if v["name"] == "config-volume")
        self.assertEqual(volume["secret"]["secretName"], renderer.SECRET_NAME)
        self.assertNotIn("configMap", volume)
        paths = find(resources, "Ingress")["spec"]["rules"][0]["http"]["paths"]
        self.assertEqual(
            [(p["path"], p["pathType"]) for p in paths], API_KEY_PATH_RULES
        )

    def test_basic_profile_guard_rejects_secret_mount_and_credential_mutations(self):
        baseline, _ = self.baseline()
        resources = renderer.transform(baseline, HOST, TOKEN, BASIC)
        for mutate in [
            lambda docs: find(docs, "Secret")["data"].pop("config.yaml"),
            lambda docs: find(docs, "Secret")["data"].update({"config.yaml": "wrong"}),
            lambda docs: find(docs, "Deployment")["spec"]["template"]["spec"][
                "volumes"
            ][0].update(secret={"secretName": "other"}),
        ]:
            candidate = copy.deepcopy(resources)
            mutate(candidate)
            with self.assertRaises(ValueError):
                renderer.validate_resources(
                    candidate, baseline, HOST, IMAGE, TOKEN, BASIC
                )

    def test_basic_private_generation_reuse_and_validation(self):
        path = self.root / "basic.json"
        credentials = renderer.basic_credentials(path)
        self.assertEqual(credentials["username"], renderer.BASIC_USERNAME)
        self.assertEqual(renderer.basic_credentials(path), credentials)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for invalid in [
            {**credentials, "username": "other"},
            {**credentials, "password": "short"},
            {**credentials, "roles": ["admin"]},
        ]:
            with self.assertRaises(ValueError):
                renderer.checked_basic_credentials(invalid)

    def test_private_config_and_signing_changes_trigger_rollout_independently(self):
        baseline, _ = self.baseline()
        original = renderer.transform(baseline, HOST, TOKEN, BASIC)
        annotations = find(original, "Deployment")["spec"]["template"]["metadata"][
            "annotations"
        ]
        private_yaml = base64.b64decode(find(original, "Secret")["data"]["config.yaml"])
        self.assertEqual(
            annotations["checksum/config"], hashlib.sha256(private_yaml).hexdigest()
        )
        self.assertEqual(
            annotations["authotron.ecmwf.int/signing-sha256"],
            hashlib.sha256(TOKEN.encode()).hexdigest(),
        )
        changed = (
            base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip("=")
        )
        signed = renderer.transform(baseline, HOST, changed, BASIC)
        signed_annotations = find(signed, "Deployment")["spec"]["template"]["metadata"][
            "annotations"
        ]
        self.assertNotEqual(
            annotations["authotron.ecmwf.int/signing-sha256"],
            signed_annotations["authotron.ecmwf.int/signing-sha256"],
        )
        self.assertEqual(
            annotations["checksum/config"], signed_annotations["checksum/config"]
        )
        password_changed = renderer.transform(
            baseline, HOST, TOKEN, {**BASIC, "password": changed}
        )
        password_annotations = find(password_changed, "Deployment")["spec"]["template"][
            "metadata"
        ]["annotations"]
        self.assertNotEqual(
            annotations["checksum/config"], password_annotations["checksum/config"]
        )
        self.assertEqual(
            annotations["authotron.ecmwf.int/signing-sha256"],
            password_annotations["authotron.ecmwf.int/signing-sha256"],
        )

    def test_private_locations_cannot_enter_git_or_archived_source(self):
        for source in renderer.preview.SOURCE_FILES:
            with self.assertRaises(ValueError):
                renderer.checked_credential_path(self.project / source, self.project)
        for source in renderer.preview.RESERVED_SOURCE_DIRS:
            with self.assertRaises(ValueError):
                renderer.checked_credential_path(self.project / source, self.project)
            with self.assertRaises(ValueError):
                renderer.checked_output_directory(
                    self.project / source / "output", self.project
                )
        (self.project / ".git").mkdir()
        with self.assertRaises(ValueError):
            renderer.checked_output_directory(self.project / "output", self.project)
        self.assertEqual(
            renderer.checked_output_directory(self.root / "private", self.project),
            self.root / "private",
        )

    def test_duplicate_credential_keys_fail_closed(self):
        path = self.root / "duplicate.json"
        renderer.signing_secret(path)
        path.write_text(
            json.dumps({"jwt-secret": TOKEN})[:-1] + ', "jwt-secret": "' + TOKEN + '"}'
        )
        with self.assertRaises(ValueError):
            renderer.signing_secret(path)

    def test_sso_action_and_direct_key_login_coexist(self):
        actions = [
            {
                "label": "Continue with demo SSO",
                "start_url": "https://browser.example.org/oauth2/start?rd=%2Faccount",
            }
        ]
        with patch.object(renderer.preview.subprocess, "run") as command:
            command.return_value.stdout = yaml.safe_dump_all(self.helm_documents())
            resources, _ = renderer.render_api_key(
                self.project, self.project, HOST, IMAGE, TOKEN, actions
            )
        config_map = next(
            doc for doc in resources if doc["kind"] == "ConfigMap" and "data" in doc
        )
        settings = yaml.safe_load(config_map["data"]["config.yaml"])
        self.assertEqual(settings["ui"]["sso"], actions)
        self.assertEqual(settings["providers"], [renderer.PROVIDER])

    def test_all_three_choices_coexist_without_public_password(self):
        actions = [
            {"label": "Demo SSO", "start_url": "https://browser.example.org/start"}
        ]
        with patch.object(renderer.preview.subprocess, "run") as command:
            command.return_value.stdout = yaml.safe_dump_all(self.helm_documents())
            resources, _ = renderer.render_api_key(
                self.project, self.project, HOST, IMAGE, TOKEN, actions, BASIC
            )
        config_map = next(
            doc for doc in resources if doc["kind"] == "ConfigMap" and "data" in doc
        )
        settings = yaml.safe_load(config_map["data"]["config.yaml"])
        self.assertEqual(settings["ui"]["sso"], actions)
        self.assertEqual(settings["providers"][0]["users"], [])
        self.assertEqual(settings["providers"][1], renderer.PROVIDER)

    def test_basic_cli_does_not_print_credentials(self):
        baseline, _ = self.baseline()
        secret_file = self.root / "signing.json"
        basic_file = self.root / "basic.json"
        output_dir = self.root / "basic-output"
        token = renderer.signing_secret(secret_file)
        basic = renderer.basic_credentials(basic_file)
        resources = renderer.transform(baseline, HOST, token, basic)
        arguments = [
            "render_api_key.py",
            "--chart",
            str(self.project),
            "--host",
            HOST,
            "--build-image",
            IMAGE,
            "--secret-file",
            str(secret_file),
            "--basic-secret-file",
            str(basic_file),
            "--output-dir",
            str(output_dir),
        ]
        with (
            patch("sys.argv", arguments),
            patch.object(
                renderer, "render_api_key", return_value=(resources, b"archive")
            ) as render,
            patch("builtins.print") as printed,
        ):
            renderer.main()
        self.assertEqual(render.call_args.args[-1], basic)
        self.assertNotIn(basic["password"], str(printed.call_args_list))
        output = output_dir / "resources.yaml"
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(yaml.safe_load_all(output.read_text())), resources)

    def cli_arguments(self):
        return [
            "render_api_key.py",
            "--chart",
            str(self.project),
            "--host",
            HOST,
            "--build-image",
            IMAGE,
            "--secret-file",
            str(self.root / "jwt.json"),
            "--output-dir",
            str(self.root / "bundle"),
        ]

    def test_shared_cli_passes_expiry_and_password_without_printing(self):
        baseline, _ = self.baseline()
        options = dict(
            valkey_password=VALKEY_PASSWORD,
            replicas=2,
            session_ttl_seconds=600,
            transaction_ttl_seconds=90,
            valkey_storage_size="2Gi",
            valkey_storage_class="fast-rwo",
        )
        resources = renderer.transform(baseline, HOST, TOKEN, BASIC, **options)
        arguments = self.cli_arguments() + [
            "--valkey-secret-file",
            str(self.root / "valkey.json"),
            "--basic-secret-file",
            str(self.root / "basic.json"),
            "--replicas",
            "2",
            "--session-ttl-seconds",
            "600",
            "--transaction-ttl-seconds",
            "90",
            "--valkey-storage-size",
            "2Gi",
            "--valkey-storage-class",
            "fast-rwo",
            "--browser-start-url",
            "https://browser.example.org/oauth2/start?rd=%2Faccount",
        ]
        with (
            patch("sys.argv", arguments),
            patch.object(renderer, "signing_secret", return_value=TOKEN),
            patch.object(renderer, "basic_credentials", return_value=BASIC),
            patch.object(renderer, "valkey_secret", return_value=VALKEY_PASSWORD),
            patch.object(
                renderer, "render_api_key", return_value=(resources, b"archive")
            ) as render,
            patch("builtins.print") as printed,
        ):
            renderer.main()
        self.assertEqual(render.call_args.kwargs, options)
        self.assertEqual(render.call_args.args[-1], BASIC)
        self.assertEqual(
            render.call_args.args[-2][0]["label"], "Continue with demo SSO"
        )
        self.assertIn("Validated 10 resources", str(printed.call_args_list))
        for password in (TOKEN, VALKEY_PASSWORD):
            self.assertNotIn(password, str(printed.call_args_list))
            self.assertNotIn(
                base64.b64encode(password.encode()).decode(),
                str(printed.call_args_list),
            )

    def test_cli_rejects_options_and_collisions_before_any_credentials(self):
        invalid = [
            ["--replicas", "2"],
            ["--replicas", "0"],
            ["--session-ttl-seconds", "59"],
            ["--transaction-ttl-seconds", "901"],
            ["--valkey-storage-size", "1G"],
            ["--valkey-storage-class", "Bad_Class"],
            ["--basic-secret-file", str(self.root / "jwt.json")],
            ["--valkey-secret-file", str(self.root / "jwt.json")],
            [
                "--basic-secret-file",
                str(self.root / "same.json"),
                "--valkey-secret-file",
                str(self.root / "same.json"),
            ],
            ["--valkey-secret-file", str(self.root / "bundle/resources.yaml")],
            ["--valkey-secret-file", str(self.root / "bundle")],
            ["--valkey-secret-file", str(self.root / "jwt.json/child")],
            [
                "--valkey-secret-file",
                str(
                    self.project
                    / renderer.preview.RESERVED_SOURCE_DIRS[0]
                    / "private.json"
                ),
            ],
            ["--output-dir", str(self.project / renderer.preview.SOURCE_FILES[0])],
        ]
        for extra in invalid:
            with (
                self.subTest(extra=extra),
                patch.object(
                    renderer,
                    "__file__",
                    str(
                        self.project
                        / "authotron/examples/ecmwf-api-key/render_api_key.py"
                    ),
                ),
                patch("sys.argv", self.cli_arguments() + extra),
                patch.object(renderer, "signing_secret") as signing,
                patch.object(renderer, "basic_credentials") as basic,
                patch.object(renderer, "valkey_secret") as valkey,
                patch.object(renderer, "render_api_key") as render,
            ):
                with self.assertRaises(ValueError):
                    renderer.main()
                for mocked in (signing, basic, valkey, render):
                    mocked.assert_not_called()

    def test_final_guard_rejects_mutations_without_masking_foreign_namespace(self):
        baseline, _ = self.baseline()
        resources = renderer.transform(baseline, HOST, TOKEN)
        mutations = [
            lambda d: d[0]["metadata"].update(namespace="aviso2-dev"),
            lambda d: d[0]["metadata"].pop("namespace"),
            lambda d: d[0].update(apiVersion="other/v1"),
            lambda d: d[0].update(kind="Namespace"),
            lambda d: d[0].update(kind="Role"),
            lambda d: d[0]["metadata"].update(name="other"),
            lambda d: d.append(copy.deepcopy(d[0])),
            lambda d: find(d, "Secret")["metadata"].update(namespace="aviso2-dev"),
            lambda d: find(d, "Secret")["metadata"].update(name="other"),
            lambda d: find(d, "Secret").update(stringData={"jwt-secret": TOKEN}),
            lambda d: find(d, "Deployment")["spec"]["template"]["spec"].update(
                hostNetwork=True
            ),
            lambda d: find(d, "Deployment")["spec"]["template"]["spec"][
                "volumes"
            ].append({"name": "host", "hostPath": {"path": "/"}}),
            lambda d: find(d, "Deployment")["spec"]["template"]["spec"]["containers"][
                0
            ]["securityContext"].update(privileged=True),
            lambda d: find(d, "Deployment")["spec"]["template"]["spec"]["containers"][
                0
            ]["env"][-1].update(value=TOKEN),
            lambda d: find(d, "Deployment")["spec"]["template"]["spec"]["containers"][
                0
            ]["env"][-1]["valueFrom"]["secretKeyRef"].update(name="other"),
            lambda d: find(d, "Ingress")["spec"]["rules"][0]["http"]["paths"].append(
                {"path": "/", "pathType": "Prefix"}
            ),
            lambda d: find(d, "Ingress")["spec"]["tls"][0].update(
                secretName="foreign-tls"
            ),
            lambda d: find(d, "Deployment")["spec"]["template"]["metadata"][
                "annotations"
            ].update({"checksum/config": "wrong"}),
            lambda d: next(x for x in d if "binaryData" in x)["metadata"].update(
                name="wrong-source"
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                candidate = copy.deepcopy(resources)
                mutate(candidate)
                snapshot = copy.deepcopy(candidate)
                with self.assertRaises(ValueError):
                    renderer.validate_resources(candidate, baseline, HOST, IMAGE, TOKEN)
                self.assertEqual(candidate, snapshot)

    def test_configuration_guard_rejects_provider_origin_session_and_secret_changes(
        self,
    ):
        baseline, _ = self.baseline()
        for mutate in [
            lambda c: c["providers"].append(renderer.PROVIDER),
            lambda c: c["providers"][0].update(uri="https://other.example.org"),
            lambda c: c["providers"][0]["browser"].update(label="other"),
            lambda c: c["providers"][0]["browser"].update(id="other"),
            lambda c: c["providers"][0].pop("browser"),
            lambda c: c["ui"]["browser_session"].update(
                public_origin="https://other.example.org"
            ),
            lambda c: c["ui"]["browser_session"].update(session_ttl_seconds=301),
            lambda c: c["ui"].update(sso=[{"href": "/sso"}]),
            lambda c: c["store"].update(enabled=True),
            lambda c: c["jwt"].update(secret=TOKEN),
            lambda c: c.update(services=[{"callback": "https://other.example.org"}]),
        ]:
            resources = renderer.transform(baseline, HOST, TOKEN)
            cm = next(d for d in resources if d["kind"] == "ConfigMap" and "data" in d)
            config = yaml.safe_load(cm["data"]["config.yaml"])
            mutate(config)
            cm["data"]["config.yaml"] = yaml.safe_dump(config)
            with self.assertRaises(ValueError):
                renderer.validate_resources(resources, baseline, HOST, IMAGE, TOKEN)

    def test_private_generation_reuse_and_output(self):
        path = self.root / "signing.json"
        token = renderer.signing_secret(path)
        self.assertEqual(len(base64.urlsafe_b64decode(token + "=")), 32)
        self.assertEqual(renderer.signing_secret(path), token)
        self.assertEqual(set(json.loads(path.read_text())), {"jwt-secret"})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        fd = renderer.directory_fd(self.root / "output", create=True)
        try:
            renderer.private_write(fd, "resources.yaml", "private payload")
            renderer.private_write(fd, "resources.yaml", "short")
        finally:
            os.close(fd)
        output = self.root / "output/resources.yaml"
        self.assertEqual(output.read_text(), "short")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_private_file_guards(self):
        path = self.root / "signing.json"
        renderer.signing_secret(path)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            renderer.signing_secret(path)
        path.chmod(0o600)
        link = self.root / "hardlink"
        os.link(path, link)
        with self.assertRaises(ValueError):
            renderer.signing_secret(path)
        link.unlink()
        symlink = self.root / "symlink"
        symlink.symlink_to(path)
        with self.assertRaises(OSError):
            renderer.signing_secret(symlink)
        ancestry = self.root / "linked-dir"
        ancestry.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            renderer.signing_secret(ancestry / "signing.json")
        with self.assertRaises(ValueError):
            renderer.signing_secret(ancestry / ".." / "signing.json")
        (self.project / ".git").mkdir()
        with self.assertRaises(ValueError):
            renderer.signing_secret(self.project / "signing.json")
        for payload in [
            {"jwt-secret": TOKEN, "api-key": "synthetic"},
            {"jwt-secret": "bad"},
            [],
        ]:
            path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError):
                renderer.signing_secret(path)

    def test_output_rejects_symlink_hardlink_and_public_mode(self):
        target = self.root / "target"
        target.write_text("untouched")
        output = self.root / "resources.yaml"
        fd = renderer.directory_fd(self.root)
        try:
            for kind in ("symlink", "hardlink", "mode"):
                if kind == "symlink":
                    output.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, output)
                else:
                    output.write_text("public")
                    output.chmod(0o644)
                with self.assertRaises((OSError, ValueError)):
                    renderer.private_write(fd, output.name, "overwrite")
                output.unlink()
            self.assertEqual(target.read_text(), "untouched")
        finally:
            os.close(fd)

    def test_control_inputs_fail_before_helm(self):
        for host, image in [
            ("https://example.org", IMAGE),
            ("example.org/path", IMAGE),
            (HOST + "\n", IMAGE),
            (HOST, "rust:latest"),
        ]:
            with patch.object(renderer.preview.subprocess, "run") as command:
                with self.assertRaises(ValueError):
                    renderer.render_api_key(
                        self.project, self.project, host, image, TOKEN
                    )
                command.assert_not_called()

    def test_cli_outputs_only_private_bundle_without_printing_secret(self):
        baseline, _ = self.baseline()
        secret_file = self.root / "signing.json"
        output_dir = self.root / "output"
        token = renderer.signing_secret(secret_file)
        resources = renderer.transform(baseline, HOST, token)
        arguments = [
            "render_api_key.py",
            "--chart",
            str(self.project),
            "--host",
            HOST,
            "--build-image",
            IMAGE,
            "--secret-file",
            str(secret_file),
            "--output-dir",
            str(output_dir),
        ]
        with (
            patch("sys.argv", arguments),
            patch.object(
                renderer, "render_api_key", return_value=(resources, b"archive")
            ),
            patch("builtins.print") as printed,
        ):
            renderer.main()
        self.assertEqual([p.name for p in output_dir.iterdir()], ["resources.yaml"])
        output = output_dir / "resources.yaml"
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(yaml.safe_load_all(output.read_text())), resources)
        self.assertNotIn(token, str(printed.call_args_list))
        self.assertNotIn(
            base64.b64encode(token.encode()).decode(), str(printed.call_args_list)
        )

    def oauth_resources(self, baseline, basic=BASIC, key=OAUTH_KEY):
        return renderer.transform(
            baseline,
            HOST,
            TOKEN,
            basic,
            valkey_password=VALKEY_PASSWORD,
            oauth_key=key,
        )

    def test_oauth_off_output_is_unchanged_from_previous_profiles(self):
        baseline, _ = self.baseline()
        for name, args, options in (
            ("plain", (), {}),
            ("basic", (BASIC,), {}),
            ("shared", (BASIC,), dict(valkey_password=VALKEY_PASSWORD, replicas=2)),
        ):
            with self.subTest(profile=name):
                text = yaml.safe_dump_all(
                    renderer.transform(baseline, HOST, TOKEN, *args, **options),
                    sort_keys=False,
                )
                self.assertEqual(
                    hashlib.sha256(text.encode()).hexdigest(), PRE_OAUTH_DIGESTS[name]
                )
                self.assertNotIn("oauth", text)
                explicit = yaml.safe_dump_all(
                    renderer.transform(
                        baseline, HOST, TOKEN, *args, oauth_key=None, **options
                    ),
                    sort_keys=False,
                )
                self.assertEqual(explicit.encode(), text.encode())

    def test_oauth_registration_matches_mcp_local_remote_settings(self):
        demo = load_mcp_settings()
        remote = demo.make_settings("https://issuer.example.org/")
        client = renderer.OAUTH_CLIENT
        self.assertEqual(client["client_id"], remote["client_id"])
        self.assertEqual(client["redirect_uris"], [remote["callback"]])
        self.assertEqual(renderer.OAUTH_RESOURCE, remote["resource"])
        self.assertEqual(renderer.OAUTH_SCOPE, remote["scope"])
        self.assertEqual(
            client["resources"],
            [{"resource": remote["resource"], "scopes": [remote["scope"]]}],
        )
        # The issuer's scope role is exactly the role the remote resource requires.
        self.assertEqual(renderer.OAUTH_REQUIRED_ROLES, (remote["required_role"],))
        self.assertEqual(remote["required_role"], "mcp-demo")
        roles = renderer.oauth_config(HOST, "kid", ["ecmwf"])["resources"][0]["scopes"]
        self.assertEqual(
            roles, [{"name": remote["scope"], "required_roles": ["mcp-demo"]}]
        )

    def test_mcp_client_table_entries_render_and_validate(self):
        expected = {
            "claude-code": (
                "native",
                ["http://localhost/callback", "http://127.0.0.1/callback"],
            ),
            "claude-ai": ("web", ["https://claude.ai/api/mcp/auth_callback"]),
            "codex": ("native", ["http://127.0.0.1/callback"]),
            "chatgpt": (
                "web",
                ["https://chatgpt.com/connector_platform_oauth_redirect"],
            ),
            "gemini-cli": ("native", ["http://localhost/oauth/callback"]),
            "vscode": (
                "native",
                [
                    "http://127.0.0.1:33418",
                    "http://127.0.0.1:33418/",
                    "https://vscode.dev/redirect",
                    "https://insiders.vscode.dev/redirect",
                ],
            ),
            "cursor": (
                "native",
                [
                    "http://localhost/callback",
                    "https://www.cursor.com/agents/mcp/oauth/callback",
                ],
            ),
            "mcp-inspector": (
                "native",
                [
                    "http://127.0.0.1/oauth/callback",
                    "http://localhost/oauth/callback",
                    "http://localhost/oauth/callback/debug",
                ],
            ),
        }
        table = {
            c["client_id"]: (c["application_type"], c["redirect_uris"])
            for c in renderer.MCP_CLIENTS
        }
        self.assertEqual(table, expected)
        clients = renderer.oauth_config(HOST, "kid", ["ecmwf"])["clients"]
        self.assertEqual([c["client_id"] for c in clients], ["mcp-local", *expected])
        for client in clients:
            with self.subTest(client=client["client_id"]):
                renderer.checked_mcp_client(client)
                self.assertEqual(
                    client["refresh_tokens"],
                    {
                        "enabled": True,
                        "idle_ttl_seconds": 2592000,
                        "absolute_ttl_seconds": 7776000,
                    },
                )
                # Hosted-only callbacks need no native type; loopback HTTP does.
                loopback = any(u.startswith("http://") for u in client["redirect_uris"])
                self.assertEqual(client["application_type"] == "native", loopback)

    def test_refresh_token_policy_validation_mirrors_server_rules(self):
        good = renderer.OAUTH_REFRESH_TOKENS
        renderer.checked_refresh_tokens(dict(good))
        for change in (
            {"idle_ttl_seconds": 299},
            {"absolute_ttl_seconds": 34560001},
            {"idle_ttl_seconds": 7776001},
            {"idle_ttl_seconds": 600.0},
            {"enabled": "yes"},
            {"extra": True},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    renderer.checked_refresh_tokens({**good, **change})
        with self.assertRaises(ValueError):
            renderer.checked_refresh_tokens({"enabled": True})

    def test_oauth_capacity_reserves_a_share_for_every_client(self):
        clients = renderer.oauth_clients()
        cap = renderer.OAUTH_MAX_AUTHORIZATION_TRANSACTIONS
        # Server partitioning: floor(cap / n) each, remainder in configuration order.
        shares = [
            cap // len(clients) + (i < cap % len(clients)) for i in range(len(clients))
        ]
        self.assertEqual(sum(shares), cap)
        self.assertGreaterEqual(min(shares), 100)
        with patch.object(renderer, "OAUTH_MAX_AUTHORIZATION_TRANSACTIONS", 8):
            with self.assertRaises(ValueError):
                renderer.oauth_clients()

    def test_mcp_client_redirect_validation_mirrors_server_rules(self):
        for uri, kind in (
            ("https://claude.ai/api/mcp/auth_callback", "web"),
            ("https://claude.ai/api/mcp/auth_callback", "native"),
            ("http://localhost/callback", "native"),
            ("http://127.0.0.1:33418", "native"),
            ("http://[::1]:8080/cb", "native"),
            ("https://a.example/cb?x=1", "web"),
        ):
            with self.subTest(valid=uri, kind=kind):
                self.assertEqual(renderer.checked_callback(uri, kind), uri)
        for uri, kind in (
            ("http://127.0.0.1/callback", "web"),
            ("http://localhost/callback", "web"),
            ("http://127.0.0.2/callback", "native"),
            ("http://example.org/callback", "native"),
            ("http://localhost:0/callback", "native"),
            ("http://localhost:/callback", "native"),
            ("https://u@a.example/cb", "web"),
            ("https://a.example/cb#x", "web"),
            ("https://a.example/cb?state=1", "web"),
            ("https://a.example/c b", "web"),
            ("https://a.example/c\\b", "web"),
            ("https://a.example/%zz", "web"),
            ("HTTPS://a.example/cb", "web"),
            ("ftp://a.example/cb", "web"),
            ("", "native"),
        ):
            with self.subTest(invalid=uri, kind=kind):
                with self.assertRaises(ValueError):
                    renderer.checked_callback(uri, kind)
        good = copy.deepcopy(renderer.MCP_CLIENTS[0])
        for mutate in (
            lambda c: c.update(client_id="bad id"),
            lambda c: c.update(display_name=" "),
            lambda c: c.update(display_name="x\x00"),
            lambda c: c.update(application_type="spa"),
            lambda c: c.update(redirect_uris=[]),
            lambda c: c.update(redirect_uris=["https://a.example/cb"] * 2),
            lambda c: c.update(
                redirect_uris=[f"https://a.example/{i}" for i in range(9)]
            ),
            lambda c: c.update(extra=1),
        ):
            client = copy.deepcopy(good)
            mutate(client)
            with self.assertRaises(ValueError):
                renderer.checked_mcp_client(client)
        with self.assertRaises(ValueError):
            renderer.checked_mcp_clients([good, copy.deepcopy(good)])

    def test_oauth_aviso_resource_is_opt_in_and_bound_to_table_clients(self):
        baseline, _ = self.baseline()
        options = dict(
            valkey_password=VALKEY_PASSWORD,
            oauth_key=OAUTH_KEY,
            oauth_aviso_resource=AVISO,
        )
        for basic, realms in ((None, ["ecmwf"]), (BASIC, ["browser-demo", "ecmwf"])):
            with self.subTest(basic=basic is not None):
                resources = renderer.transform(baseline, HOST, TOKEN, basic, **options)
                renderer.validate_resources(
                    resources, baseline, HOST, IMAGE, TOKEN, basic, **options
                )
                oauth = yaml.safe_load(
                    find(resources, "ConfigMap")["data"]["config.yaml"]
                )["oauth"]
                self.assertEqual(oauth["access_token_ttl_seconds"], 3600)
                self.assertEqual(
                    oauth["resources"][1],
                    {
                        "resource": AVISO,
                        "allowed_realms": realms,
                        "scopes": [{"name": "aviso:read", "required_roles": []}],
                    },
                )
                self.assertEqual(
                    oauth["resources"][0]["scopes"],
                    [{"name": "mcp:read", "required_roles": ["mcp-demo"]}],
                )
                local, *table = oauth["clients"]
                self.assertEqual(local, renderer.OAUTH_CLIENT)
                self.assertEqual(len(table), len(renderer.MCP_CLIENTS))
                for client in table:
                    self.assertEqual(
                        client["resources"],
                        [
                            {
                                "resource": renderer.OAUTH_RESOURCE,
                                "scopes": ["mcp:read"],
                            },
                            {"resource": AVISO, "scopes": ["aviso:read"]},
                        ],
                    )
                # Dropping or changing the flag is a guard mismatch.
                for other in (None, AVISO + "2"):
                    with self.assertRaises(ValueError):
                        renderer.validate_resources(
                            resources,
                            baseline,
                            HOST,
                            IMAGE,
                            TOKEN,
                            basic,
                            **{**options, "oauth_aviso_resource": other},
                        )
        without = renderer.oauth_config(HOST, "kid", ["ecmwf"])
        self.assertEqual(
            [r["resource"] for r in without["resources"]], [renderer.OAUTH_RESOURCE]
        )
        for client in without["clients"]:
            self.assertEqual(
                client["resources"],
                [{"resource": renderer.OAUTH_RESOURCE, "scopes": ["mcp:read"]}],
            )

    def test_oauth_aviso_resource_validation(self):
        for value in (AVISO, "https://a.example:8443/mcp", "https://a.example/"):
            self.assertEqual(renderer.checked_aviso_resource(value, True), value)
        self.assertIsNone(renderer.checked_aviso_resource(None, False))
        for value in (
            "http://a.example/mcp",
            "https://A.example/mcp",
            "https://a.example",
            "https://a.example:443/mcp",
            "https://a.example:0/mcp",
            "https://a.example:08443/mcp",
            "https://a.example:70000/mcp",
            "https://a.example/mcp?x=1",
            "https://a.example/mcp#x",
            "https://u@a.example/mcp",
            "https://a.example//mcp",
            "https://a.example/m cp",
            "https://a..example/mcp",
            renderer.OAUTH_RESOURCE,
            "",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    renderer.checked_aviso_resource(value, True)
        with self.assertRaises(ValueError):
            renderer.checked_aviso_resource(AVISO, False)
        baseline, _ = self.baseline()
        with self.assertRaises(ValueError):
            renderer.transform(
                baseline,
                HOST,
                TOKEN,
                BASIC,
                valkey_password=VALKEY_PASSWORD,
                oauth_aviso_resource=AVISO,
            )

    def test_oauth_trusted_proxies_are_opt_in_and_guarded(self):
        baseline, _ = self.baseline()
        proxies = ("10.70.13.40/32", "10.26.28.0/24")
        options = dict(
            valkey_password=VALKEY_PASSWORD,
            oauth_key=OAUTH_KEY,
            oauth_trusted_proxies=proxies,
        )
        resources = renderer.transform(baseline, HOST, TOKEN, BASIC, **options)
        renderer.validate_resources(
            resources, baseline, HOST, IMAGE, TOKEN, BASIC, **options
        )
        oauth = yaml.safe_load(find(resources, "ConfigMap")["data"]["config.yaml"])[
            "oauth"
        ]
        self.assertEqual(
            oauth["endpoint_rate_limit"], {"trusted_proxies": list(proxies)}
        )
        for other in ((), proxies[:1]):
            with self.assertRaises(ValueError):
                renderer.validate_resources(
                    resources,
                    baseline,
                    HOST,
                    IMAGE,
                    TOKEN,
                    BASIC,
                    **{**options, "oauth_trusted_proxies": other},
                )
        self.assertNotIn(
            "endpoint_rate_limit", renderer.oauth_config(HOST, "kid", ["ecmwf"])
        )
        self.assertEqual(renderer.checked_trusted_proxies([], False), ())
        for bad in (
            ["0.0.0.0/0"],
            ["::/0"],
            ["10.26.28.1/24"],
            ["10.70.13.40"],
            ["010.70.13.40/32"],
            ["not-a-cidr"],
            ["10.70.13.40/32", "10.70.13.40/32"],
            [f"10.0.0.{i}/32" for i in range(65)],
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    renderer.checked_trusted_proxies(bad, True)
        with self.assertRaises(ValueError):
            renderer.checked_trusted_proxies(proxies, False)

    def test_oauth_aviso_policy_admits_any_browser_realm_user(self):
        config = renderer.oauth_config(HOST, "kid", ["browser-demo", "ecmwf"], AVISO)
        aviso = config["resources"][1]
        (scope,) = aviso["scopes"]
        for realm in ("browser-demo", "ecmwf"):
            self.assertIn(realm, aviso["allowed_realms"])
        self.assertEqual(scope["required_roles"], [])
        self.assertNotIn("other", aviso["allowed_realms"])

    def test_oauth_ecmwf_allowlist_grants_role_only_to_listed_uids(self):
        baseline, _ = self.baseline()
        options = dict(
            valkey_password=VALKEY_PASSWORD,
            oauth_key=OAUTH_KEY,
            oauth_allow_ecmwf_uids=("user_a", "user_b"),
        )
        for basic in (None, BASIC):
            with self.subTest(basic=basic is not None):
                resources = renderer.transform(baseline, HOST, TOKEN, basic, **options)
                renderer.validate_resources(
                    resources, baseline, HOST, IMAGE, TOKEN, basic, **options
                )
                config = yaml.safe_load(
                    find(resources, "ConfigMap")["data"]["config.yaml"]
                )
                self.assertEqual(
                    config["augmenters"][-1],
                    {
                        "type": "plain_advanced",
                        "name": "Playground ECMWF OAuth allowlist",
                        "realm": "ecmwf",
                        "match": {"username": ["user_a", "user_b"]},
                        "augment": {"roles": ["mcp-demo"]},
                    },
                )
                self.assertEqual(len(config["augmenters"]), 2 if basic else 1)
                # The allowlist is policy, not a widening of the allowed realms.
                self.assertEqual(
                    config["oauth"]["resources"][0]["allowed_realms"],
                    ["browser-demo", "ecmwf"] if basic else ["ecmwf"],
                )
                # A rendering without the uid is rejected by the guard.
                with self.assertRaises(ValueError):
                    renderer.validate_resources(
                        resources,
                        baseline,
                        HOST,
                        IMAGE,
                        TOKEN,
                        basic,
                        **{**options, "oauth_allow_ecmwf_uids": ("user_a",)},
                    )
        for uids, oauth_key in (
            (("user_a",), None),
            (("",), OAUTH_KEY),
            ((" user_a",), OAUTH_KEY),
            (("user a",), OAUTH_KEY),
            (("user\x00",), OAUTH_KEY),
            (("u" * 129,), OAUTH_KEY),
            (("user_a", "user_a"), OAUTH_KEY),
            (tuple(f"u{i}" for i in range(33)), OAUTH_KEY),
            ("user_a", OAUTH_KEY),
            (b"user_a", OAUTH_KEY),
        ):
            with self.subTest(uids=uids[:2], oauth=oauth_key is not None):
                with self.assertRaises(ValueError):
                    renderer.transform(
                        baseline,
                        HOST,
                        TOKEN,
                        BASIC,
                        valkey_password=VALKEY_PASSWORD,
                        oauth_key=oauth_key,
                        oauth_allow_ecmwf_uids=uids,
                    )

    def test_oauth_policy_denies_users_without_the_role(self):
        """Mirror of the server's scope check: required_roles must all be held."""
        baseline, _ = self.baseline()
        resources = renderer.transform(
            baseline,
            HOST,
            TOKEN,
            BASIC,
            valkey_password=VALKEY_PASSWORD,
            oauth_key=OAUTH_KEY,
            oauth_allow_ecmwf_uids=("listed",),
        )
        config = yaml.safe_load(find(resources, "ConfigMap")["data"]["config.yaml"])
        resource = config["oauth"]["resources"][0]
        (scope,) = resource["scopes"]

        def roles(realm, username):
            granted = []
            for augmenter in config["augmenters"]:
                if (
                    realm == augmenter["realm"]
                    and username in augmenter["match"]["username"]
                ):
                    granted += augmenter["augment"]["roles"]
            return granted

        def allowed(realm, username):
            return realm in resource["allowed_realms"] and set(
                scope["required_roles"]
            ) <= set(roles(realm, username))

        self.assertTrue(allowed("browser-demo", "browser-demo"))
        self.assertTrue(allowed("ecmwf", "listed"))
        self.assertFalse(allowed("ecmwf", "unlisted"))
        self.assertFalse(allowed("browser-demo", "someone-else"))
        self.assertFalse(allowed("ecmwf", "browser-demo"))

    def test_oauth_caps_api_key_refresh_lifetime_only(self):
        baseline, _ = self.baseline()

        def browser_blocks(**options):
            resources = renderer.transform(baseline, HOST, TOKEN, BASIC, **options)
            config = yaml.safe_load(find(resources, "ConfigMap")["data"]["config.yaml"])
            return {p["type"]: p["browser"] for p in config["providers"]}

        self.assertEqual(
            browser_blocks(valkey_password=VALKEY_PASSWORD, oauth_key=OAUTH_KEY),
            {
                "plain": {"id": "password", "label": renderer.BASIC_LABEL},
                "ecmwf-api": {
                    "id": "ecmwf-api-key",
                    "label": "ECMWF API key",
                    "refresh_max_lifetime_seconds": 30 * 86400,
                },
            },
        )
        self.assertLessEqual(
            renderer.OAUTH_API_KEY_REFRESH_MAX_LIFETIME_SECONDS,
            renderer.OAUTH_REFRESH_TOKENS["absolute_ttl_seconds"],
        )
        self.assertNotIn(
            "refresh_max_lifetime_seconds",
            browser_blocks(valkey_password=VALKEY_PASSWORD)["ecmwf-api"],
        )
        self.assertNotIn("refresh_max_lifetime_seconds", renderer.PROVIDER["browser"])

    def test_oauth_key_generation_reuse_permissions_and_schema(self):
        path = self.root / "oauth.json"
        pem = renderer.oauth_signing_key(path)
        self.assertEqual(renderer.oauth_signing_key(path), pem)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(json.loads(path.read_text())), {"private-key-pem"})
        self.assertTrue(pem.startswith("-----BEGIN PRIVATE KEY-----\n"))
        key = serialization.load_pem_private_key(pem.encode(), None)
        self.assertEqual(key.key_size, 2048)
        kid = renderer.oauth_kid(pem)
        self.assertRegex(kid, r"^playground-[0-9a-f]{16}$")
        self.assertEqual(renderer.oauth_kid(pem), kid)
        self.assertNotEqual(renderer.oauth_kid(OTHER_OAUTH_KEY), kid)
        pkcs1 = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
        small = renderer.oauth_pem(
            rsa.generate_private_key(public_exponent=65537, key_size=1024)
        )
        for payload in (
            {"private-key-pem": pkcs1},
            {"private-key-pem": small},
            {"private-key-pem": "not a key"},
            {"private-key-pem": pem + "\n"},
            {"private-key-pem": pem, "jwt-secret": TOKEN},
            {"private-key-pem": 1},
            [],
        ):
            path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError):
                renderer.oauth_signing_key(path)
        path.write_text(json.dumps({"private-key-pem": pem}))
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            renderer.oauth_signing_key(path)
        path.chmod(0o600)
        link = self.root / "oauth-link.json"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            renderer.oauth_signing_key(link)
        hard = self.root / "oauth-hard.json"
        os.link(path, hard)
        with self.assertRaises(ValueError):
            renderer.oauth_signing_key(path)
        hard.unlink()
        (self.project / ".git").mkdir()
        with self.assertRaises(ValueError):
            renderer.oauth_signing_key(self.project / "oauth.json")

    def test_oauth_config_shape_secret_mount_and_ingress(self):
        baseline, archive = self.baseline()
        kid = renderer.oauth_kid(OAUTH_KEY)
        for basic, realms in ((None, ["ecmwf"]), (BASIC, ["browser-demo", "ecmwf"])):
            with self.subTest(basic=basic is not None):
                resources = self.oauth_resources(baseline, basic)
                renderer.validate_resources(
                    resources,
                    baseline,
                    HOST,
                    IMAGE,
                    TOKEN,
                    basic,
                    valkey_password=VALKEY_PASSWORD,
                    oauth_key=OAUTH_KEY,
                )
                self.assertEqual(len(resources), 10)
                public_text = find(resources, "ConfigMap")["data"]["config.yaml"]
                config = yaml.safe_load(public_text)
                oauth = config["oauth"]
                self.assertEqual(oauth["issuer"], f"https://{HOST}/")
                self.assertEqual(oauth["access_token_ttl_seconds"], 3600)
                # Only the Basic demo user holds the OAuth role by default.
                self.assertEqual(
                    [
                        (a["realm"], a["match"], a["augment"]["roles"])
                        for a in config.get("augmenters", [])
                    ],
                    [
                        (
                            "browser-demo",
                            {"username": ["browser-demo"]},
                            ["demo-user", "augmented", "mcp-demo"],
                        )
                    ]
                    if basic
                    else [],
                )
                self.assertEqual(
                    oauth["issuer"].rstrip("/"),
                    config["ui"]["browser_session"]["public_origin"],
                )
                self.assertEqual(
                    config["ui"]["browser_session"]["backend"]["type"], "valkey"
                )
                self.assertEqual(
                    oauth["signing"],
                    {
                        "active_kid": kid,
                        "keys": [
                            {
                                "kid": kid,
                                "private_key_file": "/run/secrets/oauth/signing.pem",
                            }
                        ],
                    },
                )
                self.assertEqual(oauth["clients"], renderer.oauth_clients())
                self.assertEqual(oauth["clients"][0], renderer.OAUTH_CLIENT)
                self.assertEqual(oauth["max_authorization_transactions"], 1024)
                self.assertEqual(
                    oauth["resources"],
                    [
                        {
                            "resource": renderer.OAUTH_RESOURCE,
                            "allowed_realms": realms,
                            "scopes": [
                                {
                                    "name": renderer.OAUTH_SCOPE,
                                    "required_roles": ["mcp-demo"],
                                }
                            ],
                        }
                    ],
                )
                self.assertEqual(
                    sorted(p["realm"] for p in config["providers"]), sorted(realms)
                )
                secret = find(resources, "Secret")["data"]
                self.assertEqual(
                    base64.b64decode(secret["oauth-signing.pem"]).decode(), OAUTH_KEY
                )
                if basic:
                    private = yaml.safe_load(base64.b64decode(secret["config.yaml"]))
                    self.assertEqual(private["oauth"], oauth)
                app = find(resources, "Deployment")["spec"]["template"]
                pod = app["spec"]
                self.assertEqual(
                    pod["volumes"][-1],
                    {
                        "name": "oauth-signing",
                        "secret": {
                            "secretName": renderer.SECRET_NAME,
                            "defaultMode": 0o440,
                            "items": [
                                {"key": "oauth-signing.pem", "path": "signing.pem"}
                            ],
                        },
                    },
                )
                self.assertEqual(
                    pod["containers"][0]["volumeMounts"][-1],
                    {
                        "name": "oauth-signing",
                        "mountPath": "/run/secrets/oauth",
                        "readOnly": True,
                    },
                )
                self.assertEqual(
                    app["metadata"]["annotations"]["checksum/oauth-signing-key"],
                    hashlib.sha256(OAUTH_KEY.encode()).hexdigest(),
                )
                paths = find(resources, "Ingress")["spec"]["rules"][0]["http"]["paths"]
                self.assertEqual(
                    [(p["path"], p["pathType"]) for p in paths],
                    API_KEY_PATH_RULES + OAUTH_ROUTES,
                )
                self.assertEqual(len({str(p["backend"]) for p in paths}), 1)
                self.assert_no_key_leak(resources, archive)

    def assert_no_key_leak(self, resources, archive):
        body = "".join(OAUTH_KEY.splitlines()[1:-1])
        encoded = base64.b64encode(OAUTH_KEY.encode()).decode()
        for doc in resources:
            text = yaml.safe_dump(doc)
            if doc["kind"] == "Secret":
                text = yaml.safe_dump(
                    {k: v for k, v in doc["data"].items() if k != "oauth-signing.pem"}
                )
            for needle in ("PRIVATE KEY", body[:64], encoded[:64]):
                self.assertNotIn(needle, text)
        self.assertNotIn(b"PRIVATE KEY", archive)

    def test_oauth_key_rotation_rolls_out_with_digest_only(self):
        baseline, _ = self.baseline()
        first = self.oauth_resources(baseline)
        second = self.oauth_resources(baseline, key=OTHER_OAUTH_KEY)
        annotations = [
            find(d, "Deployment")["spec"]["template"]["metadata"]["annotations"]
            for d in (first, second)
        ]
        for key in ("checksum/oauth-signing-key", "checksum/config"):
            self.assertNotEqual(annotations[0][key], annotations[1][key])
        self.assertEqual(len(annotations[0]["checksum/oauth-signing-key"]), 64)

    def test_oauth_requires_shared_valkey_profile(self):
        baseline, _ = self.baseline()
        for basic in (None, BASIC):
            with self.assertRaisesRegex(ValueError, "Valkey"):
                renderer.transform(baseline, HOST, TOKEN, basic, oauth_key=OAUTH_KEY)
        with patch.object(renderer.preview.subprocess, "run") as command:
            with self.assertRaisesRegex(ValueError, "Valkey"):
                renderer.render_api_key(
                    self.project, self.project, HOST, IMAGE, TOKEN, oauth_key=OAUTH_KEY
                )
            command.assert_not_called()
        with (
            patch(
                "sys.argv",
                self.cli_arguments()
                + ["--oauth-secret-file", str(self.root / "oauth.json")],
            ),
            patch.object(renderer, "signing_secret") as signing,
            patch.object(renderer, "oauth_signing_key") as oauth,
            patch.object(renderer, "render_api_key") as render,
        ):
            with self.assertRaisesRegex(ValueError, "Valkey"):
                renderer.main()
            for mocked in (signing, oauth, render):
                mocked.assert_not_called()
        self.assertFalse((self.root / "oauth.json").exists())

    def test_oauth_guard_rejects_exposure_and_reference_mutations(self):
        baseline, _ = self.baseline()
        resources = self.oauth_resources(baseline)
        options = dict(valkey_password=VALKEY_PASSWORD, oauth_key=OAUTH_KEY)

        def pod(docs):
            return find(docs, "Deployment")["spec"]["template"]["spec"]

        def paths(docs):
            return find(docs, "Ingress")["spec"]["rules"][0]["http"]["paths"]

        mutations = [
            lambda d: paths(d).append(
                {
                    "path": "/authenticate",
                    "pathType": "Exact",
                    "backend": paths(d)[0]["backend"],
                }
            ),
            lambda d: paths(d)[-2].update(pathType="Prefix"),
            lambda d: paths(d)[1].update(pathType="Exact"),
            lambda d: paths(d)[1].update(path="/login/method/"),
            lambda d: paths(d).pop(),
            lambda d: pod(d)["volumes"][-1]["secret"].update(defaultMode=0o444),
            lambda d: pod(d)["volumes"][-1]["secret"]["items"][0].update(
                key="jwt-secret"
            ),
            lambda d: pod(d)["containers"][0]["volumeMounts"][-1].update(
                readOnly=False
            ),
            lambda d: find(d, "Secret")["data"].update(
                **{
                    "oauth-signing.pem": base64.b64encode(
                        OTHER_OAUTH_KEY.encode()
                    ).decode()
                }
            ),
            lambda d: find(d, "ConfigMap")["data"].update(key=OAUTH_KEY),
            lambda d: find(d, "Deployment")["spec"]["template"]["metadata"][
                "annotations"
            ].update(**{"checksum/oauth-signing-key": "wrong"}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                candidate = copy.deepcopy(resources)
                mutate(candidate)
                with self.assertRaises(ValueError):
                    renderer.validate_resources(
                        candidate, baseline, HOST, IMAGE, TOKEN, BASIC, **options
                    )
        for mutate in (
            lambda c: c["oauth"].update(issuer="https://other.example.org/"),
            lambda c: c["oauth"]["resources"][0]["scopes"][0].update(
                required_roles=["x"]
            ),
            lambda c: c["oauth"]["clients"][0]["redirect_uris"].append(
                "http://127.0.0.1:1/cb"
            ),
            lambda c: c["oauth"]["signing"]["keys"][0].update(
                private_key_file="/tmp/k.pem"
            ),
            lambda c: c.pop("oauth"),
        ):
            candidate = copy.deepcopy(resources)
            secret = find(candidate, "Secret")["data"]
            config = yaml.safe_load(base64.b64decode(secret["config.yaml"]))
            mutate(config)
            secret["config.yaml"] = base64.b64encode(
                yaml.safe_dump(config).encode()
            ).decode()
            with self.assertRaises(ValueError):
                renderer.validate_resources(
                    candidate, baseline, HOST, IMAGE, TOKEN, BASIC, **options
                )

    def test_oauth_cli_passes_key_without_printing_it(self):
        baseline, _ = self.baseline()
        resources = self.oauth_resources(baseline)
        oauth_file = self.root / "oauth.json"
        output_dir = self.root / "bundle"
        arguments = self.cli_arguments() + [
            "--valkey-secret-file",
            str(self.root / "valkey.json"),
            "--basic-secret-file",
            str(self.root / "basic.json"),
            "--oauth-secret-file",
            str(oauth_file),
        ]
        with (
            patch("sys.argv", arguments),
            patch.object(renderer, "signing_secret", return_value=TOKEN),
            patch.object(renderer, "basic_credentials", return_value=BASIC),
            patch.object(renderer, "valkey_secret", return_value=VALKEY_PASSWORD),
            patch.object(
                renderer, "render_api_key", return_value=(resources, b"archive")
            ) as render,
            patch("builtins.print") as printed,
        ):
            renderer.main()
        pem = json.loads(oauth_file.read_text())["private-key-pem"]
        self.assertEqual(render.call_args.kwargs["oauth_key"], pem)
        self.assertNotIn("oauth_allow_ecmwf_uids", render.call_args.kwargs)
        with (
            patch(
                "sys.argv",
                arguments
                + ["--oauth-allow-ecmwf-uid", "user_a"]
                + ["--oauth-allow-ecmwf-uid", "user_b"],
            ),
            patch.object(renderer, "signing_secret", return_value=TOKEN),
            patch.object(renderer, "basic_credentials", return_value=BASIC),
            patch.object(renderer, "valkey_secret", return_value=VALKEY_PASSWORD),
            patch.object(
                renderer, "render_api_key", return_value=(resources, b"archive")
            ) as render,
            patch("builtins.print"),
        ):
            renderer.main()
        self.assertEqual(
            render.call_args.kwargs["oauth_allow_ecmwf_uids"], ("user_a", "user_b")
        )
        self.assertNotIn("oauth_aviso_resource", render.call_args.kwargs)
        with (
            patch("sys.argv", arguments + ["--oauth-aviso-resource", AVISO]),
            patch.object(renderer, "signing_secret", return_value=TOKEN),
            patch.object(renderer, "basic_credentials", return_value=BASIC),
            patch.object(renderer, "valkey_secret", return_value=VALKEY_PASSWORD),
            patch.object(
                renderer, "render_api_key", return_value=(resources, b"archive")
            ) as render,
            patch("builtins.print"),
        ):
            renderer.main()
        self.assertEqual(render.call_args.kwargs["oauth_aviso_resource"], AVISO)
        for bad in (
            arguments[: arguments.index("--oauth-secret-file")]
            + ["--oauth-aviso-resource", AVISO],
            arguments + ["--oauth-aviso-resource", "http://a.example/mcp"],
        ):
            with (
                patch("sys.argv", bad),
                patch.object(renderer, "signing_secret") as signing,
                patch.object(renderer, "render_api_key"),
            ):
                with self.assertRaises(ValueError):
                    renderer.main()
                signing.assert_not_called()
        self.assertEqual(oauth_file.stat().st_mode & 0o777, 0o600)
        printed_text = str(printed.call_args_list)
        self.assertIn(f"OAuth issuer: https://{HOST}/", printed_text)
        for needle in ("PRIVATE KEY", pem.splitlines()[1], TOKEN, VALKEY_PASSWORD):
            self.assertNotIn(needle, printed_text)
        self.assertEqual((output_dir / "resources.yaml").stat().st_mode & 0o777, 0o600)
        without_oauth = arguments[: arguments.index("--oauth-secret-file")]
        with (
            patch("sys.argv", without_oauth + ["--oauth-allow-ecmwf-uid", "user_a"]),
            patch.object(renderer, "signing_secret") as signing,
            patch.object(renderer, "render_api_key") as render,
        ):
            with self.assertRaises(ValueError):
                renderer.main()
            signing.assert_not_called()
            render.assert_not_called()
        for extra in (
            ["--oauth-secret-file", str(self.root / "jwt.json")],
            ["--oauth-secret-file", str(self.root / "valkey.json")],
            ["--oauth-secret-file", str(output_dir / "resources.yaml")],
        ):
            with (
                self.subTest(extra=extra),
                patch("sys.argv", arguments + extra),
                patch.object(renderer, "oauth_signing_key") as oauth,
                patch.object(renderer, "render_api_key") as render,
            ):
                with self.assertRaises((ValueError, SystemExit)):
                    renderer.main()
                oauth.assert_not_called()
                render.assert_not_called()


if __name__ == "__main__":
    unittest.main()
