"""Offline contracts using explicit public fixtures and mocked Helm."""

import base64
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import render_api_key as renderer
import yaml

HOST = "authotron-palyground.lumi.apps.dte.destination-earth.eu"
IMAGE = "docker.io/library/rust@sha256:" + "a" * 64
TOKEN = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
VALKEY_PASSWORD = (
    base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip("=")
)
BASIC = {"username": renderer.BASIC_USERNAME, "password": TOKEN}


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
        for name in renderer.preview.SOURCE_DIRS:
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
            config["ui"]["ecmwf_api_key"],
            {
                "provider_name": "ECMWF API Provider",
            },
        )
        self.assertEqual(
            config["ui"]["browser_session"],
            {
                "public_origin": f"https://{HOST}",
                "session_ttl_seconds": 300,
                "transaction_ttl_seconds": 300,
                "backend": {"type": "memory"},
            },
        )
        self.assertEqual(config["ui"]["sign_in_actions"], [])
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
            list(renderer.preview.PATH_RULES)
            + [(p, "Exact") for p in renderer.LOGIN_PATHS],
        )

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
                        ("apps/v1", "Deployment", renderer.VALKEY_NAME),
                        ("v1", "Service", renderer.VALKEY_NAME),
                        ("networking.k8s.io/v1", "NetworkPolicy", renderer.VALKEY_NAME),
                    },
                )
                self.assertEqual(len(resources), 9)
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
                        "key_prefix": f"authotron:browser:v1:{renderer.preview.RELEASE}",
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
                    private["providers"][-1]["users"] = []
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
        self.assertEqual(public["providers"][-1]["users"], [])
        self.assertEqual(
            public["ui"]["basic"]["provider_name"], renderer.BASIC_PROVIDER_NAME
        )
        self.assertEqual(
            public["ui"]["browser_session"]["public_origin"], f"https://{HOST}"
        )
        self.assertEqual(
            public["augmenters"][0]["augment"]["roles"], ["demo-user", "augmented"]
        )
        secret = find(resources, "Secret")
        private_text = base64.b64decode(secret["data"]["config.yaml"]).decode()
        private = yaml.safe_load(private_text)
        self.assertEqual(private["providers"][-1]["users"], [{**BASIC, "roles": []}])
        private["providers"][-1]["users"] = []
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
        self.assertIn(
            ("/login/basic", "Exact"), [(p["path"], p["pathType"]) for p in paths]
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
        for source in renderer.preview.SOURCE_DIRS:
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
        self.assertEqual(settings["ui"]["sign_in_actions"], actions)
        self.assertEqual(
            settings["ui"]["ecmwf_api_key"]["provider_name"], renderer.PROVIDER["name"]
        )
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
        self.assertEqual(settings["ui"]["sign_in_actions"], actions)
        self.assertIn("ecmwf_api_key", settings["ui"])
        self.assertIn("basic", settings["ui"])
        self.assertEqual(settings["providers"][0], renderer.PROVIDER)
        self.assertEqual(settings["providers"][1]["users"], [])

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
        self.assertIn("Validated 9 resources", str(printed.call_args_list))
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
                str(self.project / renderer.preview.SOURCE_DIRS[0] / "private.json"),
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
            lambda c: c["ui"]["ecmwf_api_key"].update(provider_name="other"),
            lambda c: c["ui"]["browser_session"].update(
                public_origin="https://other.example.org"
            ),
            lambda c: c["ui"]["browser_session"].update(session_ttl_seconds=301),
            lambda c: c["ui"].update(sign_in_actions=[{"href": "/sso"}]),
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


if __name__ == "__main__":
    unittest.main()
