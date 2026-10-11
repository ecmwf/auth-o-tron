"""Offline renderer checks using disposable sources, credentials and Helm output."""

import base64
import copy
from dataclasses import FrozenInstanceError
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

import render_sso as renderer


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.assets = self.project / "authotron/examples/browser-sso"
        self.assets.mkdir(parents=True)
        for name in ("welcome.html", "account.html"):
            (self.assets / name).write_text(
                '<a href="{{LOGIN_URL}}">login</a><link href="{{STYLE_URL}}">'
                '<img src="{{FAVICON_URL}}">'
            )
        (self.assets / "account.js").write_text('fetch("/oauth2/userinfo");')
        fixture = self.project / "authotron/examples/login-ui/aviso.yaml"
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(
            yaml.safe_dump(
                {
                    "server": {"host": "127.0.0.1", "port": 8080},
                    "metrics": {"enabled": False},
                    "providers": [],
                    "store": {"enabled": False},
                    "ui": {
                        "enabled": True,
                        "branding": {"logo_url": "https://logo.example.org/aviso.png"},
                    },
                }
            )
        )
        self.profile = renderer.Profile(
            "ui.example.org",
            "issuer.example.org",
            "app.example.org",
            "docker.io/library/rust@sha256:" + "a" * 64,
            renderer.trusted_addresses("10.26.28.1/32,10.26.28.2,2001:db8::1/128"),
        )
        self.bundle = {
            key: "fake-demo-only-" + "x" * 32 for key in renderer.SECRET_KEYS
        }
        self.bundle["cookie-secret"] = base64.b64encode(b"f" * 32).decode()
        self.docs = renderer.render_public_sso(self.profile, self.assets)
        self.docs.append(renderer.secret_resource(self.bundle))

    def doc(self, kind, name, docs=None):
        return next(
            doc
            for doc in (self.docs if docs is None else docs)
            if doc["kind"] == kind and doc["metadata"]["name"] == name
        )

    def pod(self, component, docs=None):
        return self.doc("Deployment", renderer.PREFIX + component, docs)["spec"][
            "template"
        ]["spec"]

    def assert_invalid(self, change):
        docs = copy.deepcopy(self.docs)
        change(docs)
        with self.assertRaises(ValueError):
            renderer.validate_sso(docs, self.profile, self.assets)

    def test_profile_is_immutable_and_derives_all_callback_uses(self):
        with self.assertRaises(FrozenInstanceError):
            self.profile.app_host = "other.example.org"
        realm = renderer.realm_config(self.profile)
        client = realm["clients"][0]
        self.assertEqual(client["redirectUris"], [self.profile.callback])
        self.assertEqual(
            self.profile.callback, "https://app.example.org/oauth2/callback"
        )
        args = renderer.proxy_args(self.profile)
        self.assertIn("--redirect-url=" + client["redirectUris"][0], args)
        self.assertIn("--client-id=" + client["clientId"], args)
        self.assertIn("--oidc-issuer-url=" + self.profile.issuer, args)
        self.assertEqual(
            self.profile.sign_in_actions,
            [
                {
                    "label": "Continue with demo SSO",
                    "start_url": "https://app.example.org/oauth2/start?rd=%2Faccount",
                }
            ],
        )

    def test_input_validation(self):
        for addresses in (
            "",
            "0.0.0.0/0",
            "10.26.28.0/24",
            "::/0",
            "no-ip",
            "10.0.0.1,10.0.0.1",
        ):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                renderer.trusted_addresses(addresses)
        for hosts in (
            ("ui.example.org", "ui.example.org", "app.example.org"),
            ("https://ui.example.org", "issuer.example.org", "app.example.org"),
            ("*.example.org", "issuer.example.org", "app.example.org"),
        ):
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                renderer.Profile(
                    *hosts, self.profile.build_image, self.profile.trusted_proxies
                )
        with self.assertRaises(ValueError):
            renderer.Profile(
                "ui.example.org",
                "issuer.example.org",
                "app.example.org",
                self.profile.build_image,
                (),
            )

    def test_namespace_kind_names_duplicates_and_pod_safety_fail_closed(self):
        renderer.validate_sso(self.docs, self.profile, self.assets)
        mutations = [
            lambda ds: ds[0]["metadata"].update(namespace="aviso2-dev"),
            lambda ds: ds[0].update(kind="Namespace"),
            lambda ds: ds[0].update(apiVersion="v2"),
            lambda ds: ds[0]["metadata"].update(name="foreign-config"),
            lambda ds: ds.append(copy.deepcopy(ds[0])),
            lambda ds: self.pod("nginx", ds).update(hostNetwork=True),
            lambda ds: self.pod("nginx", ds).update(automountServiceAccountToken=True),
            lambda ds: self.pod("nginx", ds)["volumes"].append(
                {"name": "host", "hostPath": {"path": "/"}}
            ),
            lambda ds: self.pod("nginx", ds)["containers"][0]["securityContext"].update(
                privileged=True
            ),
            lambda ds: self.pod("nginx", ds)["containers"][0].update(
                image="nginx:latest"
            ),
            lambda ds: ds.append(renderer.resource("ServiceAccount", "foreign")),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_invalid(mutation)
        with patch.object(renderer, "NAMESPACE", "other"):
            with self.assertRaises(ValueError):
                renderer.validate_sso(self.docs, self.profile, self.assets)

    def test_callback_wildcard_and_proxy_mismatch_rejected(self):
        def change_callback(ds):
            cm = self.doc("ConfigMap", renderer.PREFIX + "realm", ds)
            realm = json.loads(cm["data"][self.profile.realm_filename])
            realm["clients"][0]["redirectUris"] = ["https://app.example.org/*"]
            cm["data"][self.profile.realm_filename] = json.dumps(realm)

        self.assert_invalid(change_callback)
        self.assert_invalid(
            lambda ds: self.pod("oauth2-proxy", ds)["containers"][0]["args"].append(
                "--redirect-url=https://other.example.org/oauth2/callback"
            )
        )

    def test_realm_and_html_contain_only_secret_placeholders(self):
        public = yaml.safe_dump_all(
            [doc for doc in self.docs if doc["kind"] != "Secret"]
        )
        for credential in self.bundle.values():
            self.assertNotIn(credential, public)
        realm = renderer.realm_config(self.profile)
        self.assertEqual(realm["clients"][0]["secret"], "${BROWSER_CLIENT_SECRET}")
        self.assertEqual(
            realm["users"][0]["credentials"][0]["value"], "${DEMO_USER_PASSWORD}"
        )
        self.assertEqual(realm["accessTokenLifespan"], 60)
        for key in (
            "ssoSessionIdleTimeout",
            "ssoSessionMaxLifespan",
            "clientSessionIdleTimeout",
            "clientSessionMaxLifespan",
        ):
            self.assertEqual(realm[key], 900)
        client = realm["clients"][0]
        for key in (
            "publicClient",
            "directAccessGrantsEnabled",
            "implicitFlowEnabled",
            "serviceAccountsEnabled",
        ):
            self.assertFalse(client[key])
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertEqual(
            client["protocolMappers"][0]["config"],
            {
                "included.client.audience": self.profile.client_id,
                "id.token.claim": "true",
                "access.token.claim": "true",
            },
        )
        pages = self.doc("ConfigMap", renderer.PREFIX + "pages")["data"]
        self.assertIn('href="https://ui.example.org/login"', pages["welcome.html"])
        self.assertIn("https://ui.example.org/static/login.css", pages["account.html"])
        self.assertNotIn("{{", str(pages))

    def test_exact_scoped_ingresses_and_private_services(self):
        expected = {
            "keycloak": ("issuer.example.org", self.profile.issuer_paths),
            "oauth2-proxy": ("app.example.org", renderer.APP_PATHS),
        }
        self.assertEqual(sum(doc["kind"] == "Ingress" for doc in self.docs), 2)
        for component, (host, paths) in expected.items():
            spec = self.doc("Ingress", renderer.PREFIX + component)["spec"]
            self.assertEqual(spec["rules"][0]["host"], host)
            self.assertEqual(
                [(p["path"], p["pathType"]) for p in spec["rules"][0]["http"]["paths"]],
                list(paths),
            )
            self.assertEqual(spec["tls"][0]["hosts"], [host])
        for doc in self.docs:
            if doc["kind"] == "Service":
                self.assertEqual(doc["spec"]["type"], "ClusterIP")
        self.assert_invalid(
            lambda ds: self.doc("Ingress", renderer.PREFIX + "oauth2-proxy", ds)[
                "spec"
            ]["rules"][0]["http"]["paths"][0].update(pathType="Prefix")
        )
        self.assert_invalid(
            lambda ds: self.doc("Service", renderer.PREFIX + "nginx", ds)[
                "spec"
            ].update(type="LoadBalancer")
        )

    def test_proxy_pkce_nonce_cookie_and_token_controls(self):
        args = renderer.proxy_args(self.profile)
        for flag in (
            "--code-challenge-method=S256",
            "--insecure-oidc-skip-nonce=false",
            "--insecure-oidc-skip-issuer-verification=false",
            "--pass-access-token=false",
            "--pass-authorization-header=false",
            "--set-authorization-header=false",
            "--pass-basic-auth=false",
            "--pass-user-headers=false",
            "--cookie-name=__Host-aviso_demo",
            "--cookie-secure=true",
            "--cookie-httponly=true",
            "--cookie-refresh=30s",
            "--cookie-expire=900s",
            "--skip-auth-route=GET=^/$",
            "--request-logging=false",
        ):
            self.assertIn(flag, args)
        self.assertFalse(
            any(
                arg.startswith(
                    ("--cookie-domain", "--trusted-ip=", "--skip-jwt-bearer-tokens")
                )
                for arg in args
            )
        )
        for address in self.profile.trusted_proxies:
            self.assertIn("--trusted-proxy-ip=" + address, args)
        self.assertIn(
            "--proxy-trusted-addresses=" + ",".join(self.profile.trusted_proxies),
            self.pod("keycloak")["containers"][0]["args"],
        )
        self.assert_invalid(
            lambda ds: self.pod("oauth2-proxy", ds)["containers"][0]["args"].append(
                "--trusted-ip=10.26.28.1"
            )
        )

    def test_public_issuer_excludes_logout_admin_and_generic_realm_prefix(self):
        paths = self.profile.issuer_paths
        base = f"/realms/{self.profile.realm}"
        self.assertIn((base + "/protocol/openid-connect/auth", "Exact"), paths)
        self.assertIn((base + "/login-actions/", "Prefix"), paths)
        self.assertNotIn((base, "Prefix"), paths)
        self.assertFalse(any("logout" in path or "admin" in path for path, _ in paths))
        realm_map = self.doc("ConfigMap", renderer.PREFIX + "realm")["data"]
        self.assertEqual(set(realm_map), {self.profile.realm_filename})

    def test_proxy_network_policy_accepts_only_configured_ingress_peers(self):
        policy = self.doc("NetworkPolicy", renderer.PREFIX + "oauth2-proxy")["spec"]
        self.assertEqual(
            policy["podSelector"], {"matchLabels": renderer.labels("oauth2-proxy")}
        )
        peers = policy["ingress"][0]["from"]
        self.assertEqual(peers, [renderer.INGRESS_PEER])
        self.assertEqual(set(peers[0]), {"namespaceSelector", "podSelector"})
        self.assertEqual(
            peers[0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "kube-system",
        )
        self.assertEqual(
            policy["ingress"][0]["ports"], [{"protocol": "TCP", "port": 4180}]
        )

    def test_valkey_backend_network_and_secret_references(self):
        args = renderer.proxy_args(self.profile)
        self.assertIn("--session-store-type=redis", args)
        self.assertIn(
            "--redis-connection-url=redis://authotron-sso-valkey:6379/0", args
        )
        valkey = self.pod("valkey")["containers"][0]
        self.assertEqual(valkey["image"], renderer.IMAGES["valkey"])
        self.assertIn('--requirepass "$VALKEY_PASSWORD"', valkey["args"][0])
        self.assertIn("--maxmemory-policy noeviction", valkey["args"][0])
        policy = self.doc("NetworkPolicy", renderer.PREFIX + "valkey")["spec"]
        self.assertEqual(policy["egress"], [])
        self.assertEqual(
            policy["ingress"][0]["from"],
            [{"podSelector": {"matchLabels": renderer.labels("oauth2-proxy")}}],
        )
        for component in ("keycloak", "oauth2-proxy", "valkey"):
            for env in self.pod(component)["containers"][0]["env"]:
                if "valueFrom" in env:
                    self.assertEqual(
                        env["valueFrom"]["secretKeyRef"]["name"], renderer.SECRET_NAME
                    )
        self.assert_invalid(
            lambda ds: self.doc("NetworkPolicy", renderer.PREFIX + "valkey", ds)[
                "spec"
            ].update(ingress=[{}])
        )

    def test_secret_file_generation_permissions_reuse_and_invalid_file(self):
        path = self.root / "secrets.json"
        first = renderer.load_or_create_secrets(path)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(len(base64.urlsafe_b64decode(first["cookie-secret"])), 32)
        original = path.read_bytes()
        self.assertEqual(renderer.load_or_create_secrets(path), first)
        self.assertEqual(path.read_bytes(), original)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            renderer.load_or_create_secrets(path)
        path.chmod(0o600)
        path.write_text('{"unexpected":"fake"}')
        with self.assertRaises(ValueError):
            renderer.load_or_create_secrets(path)
        for invalid in ("not-base64", base64.b64encode(b"short").decode()):
            bundle = dict(self.bundle, **{"cookie-secret": invalid})
            with self.assertRaises(ValueError):
                renderer.secret_resource(bundle)

    def test_cookie_secret_migrates_encoding_without_rotating_key_bytes(self):
        path = self.root / "cookie-secrets.json"
        bundle = dict(
            self.bundle, **{"cookie-secret": base64.b64encode(b"\xff" * 32).decode()}
        )
        renderer.write_file(path, json.dumps(bundle), private=True)
        loaded = renderer.load_or_create_secrets(path)
        self.assertEqual(
            base64.urlsafe_b64decode(loaded["cookie-secret"]), b"\xff" * 32
        )
        self.assertNotIn("/", loaded["cookie-secret"])
        self.assertEqual(loaded["client-secret"], bundle["client-secret"])
        self.assertEqual(renderer.load_or_create_secrets(path), loaded)

    def test_symlink_and_hardlink_outputs_rejected(self):
        target = self.root / "target"
        target.write_text("unchanged")
        link = self.root / "link"
        link.symlink_to(target)
        for operation in (
            lambda: renderer.load_or_create_secrets(link),
            lambda: renderer.write_file(link, "overwrite", private=True),
        ):
            with self.assertRaises(ValueError):
                operation()
        directory_link = self.root / "directory-link"
        directory_link.symlink_to(self.assets, target_is_directory=True)
        with self.assertRaises(ValueError):
            renderer.write_file(directory_link / "new-file", "overwrite")
        hardlink = self.root / "hardlink"
        hardlink.hardlink_to(target)
        with self.assertRaises(ValueError):
            renderer.write_file(hardlink, "overwrite")
        self.assertEqual(target.read_text(), "unchanged")

    def make_preview_fixture(self):
        preview = renderer.preview
        for name in preview.SOURCE_FILES:
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("public build fixture\n")
        for name in preview.SOURCE_DIRS:
            directory = self.project / name
            directory.mkdir(parents=True)
            (directory / "lib.rs").write_text("// public fixture\n")
        fixture = self.project / "authotron/examples/login-ui/aviso.yaml"
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(
            yaml.safe_dump(
                {
                    "providers": {},
                    "store": {"enabled": False},
                    "ui": {
                        "enabled": True,
                        "branding": {"logo_url": "https://logo.example.org/aviso.png"},
                    },
                    "server": {"port": 8080},
                    "metrics": {"enabled": True},
                }
            )
        )
        for private in (
            "configuration/config.yaml",
            "tooling/private",
            ".git/config",
            ".kube/config",
        ):
            path = self.project / private
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("private-must-not-be-archived")
        release = preview.RELEASE
        selector = {
            "app.kubernetes.io/name": release,
            "app.kubernetes.io/instance": release,
        }
        values = preview.preview_values(
            self.project, self.profile.ui_host, self.profile.sign_in_actions
        )
        docs = [
            renderer.resource("ConfigMap", release + "-config", data={}),
            renderer.resource(
                "Deployment",
                release,
                spec={
                    "template": {
                        "metadata": {
                            "labels": selector,
                            "annotations": {"checksum/config": "fixture-checksum"},
                        },
                        "spec": {
                            "containers": [
                                {
                                    "livenessProbe": {
                                        "httpGet": {
                                            "path": "/health",
                                            "port": "http-auth",
                                        }
                                    },
                                    "readinessProbe": {
                                        "httpGet": {
                                            "path": "/health",
                                            "port": "http-auth",
                                        }
                                    },
                                }
                            ]
                        },
                    }
                },
            ),
            renderer.resource(
                "Service",
                release,
                spec={
                    "type": "ClusterIP",
                    "selector": selector,
                    "ports": [
                        {
                            "name": "http-auth",
                            "port": 8080,
                            "targetPort": 8080,
                            "protocol": "TCP",
                        }
                    ],
                },
            ),
            renderer.resource(
                "Ingress",
                release,
                spec={
                    "ingressClassName": "nginx",
                    "tls": values["ingress"]["tls"],
                    "rules": [
                        {
                            "host": self.profile.ui_host,
                            "http": {
                                "paths": [
                                    {
                                        "path": path,
                                        "pathType": path_type,
                                        "backend": {
                                            "service": {
                                                "name": release,
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
            ),
        ]
        docs[-1]["metadata"]["annotations"] = preview.ANNOTATIONS
        return yaml.safe_dump_all(docs)

    def test_full_preview_composition_determinism_and_archive_exclusions(self):
        helm_output = self.make_preview_fixture()
        with patch.object(
            renderer.preview.subprocess,
            "run",
            return_value=SimpleNamespace(stdout=helm_output),
        ) as run:
            first = renderer.render_bundles(
                self.project, self.root / "chart", self.profile, self.bundle
            )
            second = renderer.render_bundles(
                self.project, self.root / "chart", self.profile, self.bundle
            )
        self.assertEqual(first, second)
        self.assertEqual(run.call_args.args[0][:2], ["helm", "template"])
        ui, sso, archive = first
        self.assertEqual(len(ui), 5)
        self.assertEqual(len(sso), 17)
        ui_text = yaml.safe_dump_all(ui)
        for value in self.bundle.values():
            self.assertNotIn(value, ui_text)
        config = next(doc for doc in ui if doc["kind"] == "ConfigMap" and "data" in doc)
        self.assertEqual(
            yaml.safe_load(config["data"]["config.yaml"])["ui"]["sign_in_actions"],
            self.profile.sign_in_actions,
        )
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            names = source.getnames()
            self.assertIn("Cargo.lock", names)
            self.assertFalse(
                any(
                    name.startswith((".git", ".kube", "tooling", "configuration"))
                    for name in names
                )
            )
        path = self.root / "sso-resources.yaml"
        renderer.write_file(path, yaml.safe_dump_all(sso), private=True)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def cli_args(self):
        return [
            "render_sso.py",
            "--chart",
            str(self.root / "chart"),
            "--ui-host",
            self.profile.ui_host,
            "--issuer-host",
            self.profile.issuer_host,
            "--app-host",
            self.profile.app_host,
            "--build-image",
            self.profile.build_image,
            "--trusted-proxy-addresses",
            ",".join(self.profile.trusted_proxies),
            "--secret-file",
            str(self.root / "secret.json"),
            "--output-dir",
            str(self.root / "output"),
        ]

    def test_cli_rerender_writes_only_review_bundles_and_preserves_credentials(self):
        helm_output = self.make_preview_fixture()
        stdout = io.StringIO()
        with (
            patch("sys.argv", self.cli_args()),
            patch("sys.stdout", stdout),
            patch.object(renderer, "__file__", str(self.assets / "render_sso.py")),
            patch.object(
                renderer.preview.subprocess,
                "run",
                return_value=SimpleNamespace(stdout=helm_output),
            ),
        ):
            renderer.main()
            output = self.root / "output"
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            secret_before = (self.root / "secret.json").read_bytes()
            renderer.main()
        self.assertEqual(
            before, {path.name: path.read_bytes() for path in output.iterdir()}
        )
        self.assertEqual(secret_before, (self.root / "secret.json").read_bytes())
        self.assertEqual(
            set(before),
            {"ui-resources.yaml", "sso-resources.yaml", "source.tar.gz", "build.sh"},
        )
        self.assertEqual(
            stat.S_IMODE((output / "sso-resources.yaml").stat().st_mode), 0o600
        )
        for value in json.loads(secret_before).values():
            self.assertNotIn(value, stdout.getvalue())
            self.assertNotIn(value.encode(), before["ui-resources.yaml"])
        for name in ("ui-resources.yaml", "sso-resources.yaml"):
            docs = list(yaml.safe_load_all(before[name]))
            self.assertTrue(
                all(
                    doc["metadata"]["namespace"] == "authotron-palyground"
                    for doc in docs
                )
            )
            self.assertFalse(any(doc["kind"] == "Namespace" for doc in docs))

    def test_cli_disallows_namespace_override(self):
        stderr = io.StringIO()
        with (
            patch("sys.argv", self.cli_args() + ["--namespace", "other"]),
            patch("sys.stderr", stderr),
        ):
            with self.assertRaises(SystemExit) as error:
                renderer.main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("unrecognized arguments: --namespace other", stderr.getvalue())
        self.assertFalse((self.root / "secret.json").exists())

    def test_secret_generation_rejects_archive_paths_without_git(self):
        for name in (*renderer.preview.SOURCE_FILES, *renderer.preview.SOURCE_DIRS):
            path = self.project / name
            if name in renderer.preview.SOURCE_DIRS:
                path /= "private.json"
            with self.subTest(path=path), self.assertRaises(ValueError):
                renderer.load_or_create_secrets(path, project=self.project)
            self.assertFalse(path.exists())
        marker = self.project / ".git"
        marker.write_text("gitdir: synthetic-worktree")
        with self.assertRaises(ValueError):
            renderer.load_or_create_secrets(
                self.project / "private.json", project=self.project
            )
        with patch.object(renderer, "__file__", str(self.assets / "render_sso.py")):
            with self.assertRaises(ValueError):
                renderer.load_or_create_secrets(self.project / "private.json")
        path = self.root / "valid-private.json"
        generated = renderer.load_or_create_secrets(path, project=self.project)
        self.assertEqual(
            renderer.load_or_create_secrets(path, project=self.project), generated
        )

    def assert_cli_paths_rejected(self, secret, output):
        args = self.cli_args()
        args[args.index("--secret-file") + 1] = str(secret)
        args[args.index("--output-dir") + 1] = str(output)
        with (
            patch("sys.argv", args),
            patch("sys.stderr", io.StringIO()),
            patch.object(renderer, "__file__", str(self.assets / "render_sso.py")),
            patch.object(renderer, "load_or_create_secrets") as generate,
            patch.object(renderer, "render_bundles") as render,
            patch.object(renderer.preview.subprocess, "run") as helm,
        ):
            with self.assertRaises(SystemExit) as error:
                renderer.main()
        self.assertEqual(error.exception.code, 1)
        generate.assert_not_called()
        render.assert_not_called()
        helm.assert_not_called()

    def test_cli_rejects_git_and_archive_locations_before_side_effects(self):
        secret = self.root / "secret.json"
        output = self.root / "output"
        paths = [self.project / name for name in renderer.preview.SOURCE_FILES]
        paths += [
            self.project / name / "private" for name in renderer.preview.SOURCE_DIRS
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assert_cli_paths_rejected(path, output)
                self.assert_cli_paths_rejected(secret, path)
                self.assertFalse(path.exists())
        (self.project / ".git").write_text("gitdir: synthetic-worktree")
        self.assert_cli_paths_rejected(self.project / "private.json", output)
        self.assert_cli_paths_rejected(secret, self.project / "output")
        self.assert_cli_paths_rejected(secret, self.project / ".git/output")
        self.assertFalse(secret.exists())
        self.assertFalse(output.exists())

    def test_cli_rejects_output_file_locations_and_credential_overlaps(self):
        output = self.root / "output"
        secret = self.root / "secret.json"
        for name in (
            "ui-resources.yaml",
            "sso-resources.yaml",
            renderer.preview.ARCHIVE_KEY,
            "build.sh",
        ):
            path = output / name
            self.assert_cli_paths_rejected(path, output)
            self.assert_cli_paths_rejected(path / "secret.json", output)
        self.assert_cli_paths_rejected(output, output)
        self.assert_cli_paths_rejected(secret, secret / "output")
        # A permitted directory must still reject a secret-bearing output that
        # collides with an exact archive filename before any directory is made.
        with patch.object(renderer.preview, "SOURCE_FILES", ("sso-resources.yaml",)):
            self.assert_cli_paths_rejected(secret, self.project)
        self.assertFalse(output.exists())
        self.assertFalse(secret.exists())

    def test_rejected_secret_never_enters_decompressed_source_archive(self):
        self.make_preview_fixture()
        (self.project / ".git/config").unlink()
        (self.project / ".git").rmdir()
        sentinel = "synthetic-sentinel-secret-must-not-be-packaged"
        secret_path = self.project / renderer.preview.SOURCE_DIRS[0] / "private.json"
        with patch.object(renderer.secrets, "token_urlsafe", return_value=sentinel):
            with self.assertRaises(ValueError):
                renderer.load_or_create_secrets(secret_path, project=self.project)
        self.assertFalse(secret_path.exists())
        existing = self.project / renderer.preview.SOURCE_FILES[0]
        before = existing.read_bytes()
        with self.assertRaises(ValueError):
            renderer.load_or_create_secrets(existing, project=self.project)
        self.assertEqual(existing.read_bytes(), before)
        archive = renderer.preview.source_archive(self.project)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            for member in source.getmembers():
                if member.isfile():
                    self.assertNotIn(
                        sentinel.encode(), source.extractfile(member).read()
                    )


if __name__ == "__main__":
    unittest.main()
