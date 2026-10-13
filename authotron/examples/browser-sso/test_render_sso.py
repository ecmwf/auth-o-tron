"""Offline renderer checks using disposable credentials."""

import base64
import copy
from dataclasses import FrozenInstanceError
import io
import json
from pathlib import Path
import stat
import tempfile
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
        self.assets = self.project / "authotron/examples/browser-sso"
        self.assets.mkdir(parents=True)
        self.profile = renderer.Profile(
            "ui.example.org",
            "issuer.example.org",
            renderer.trusted_addresses("10.70.0.0/16,10.26.28.2/32,2001:db8::1"),
        )
        self.bundle = {
            key: "fake-demo-only-" + "x" * 32 for key in renderer.SECRET_KEYS
        }
        self.docs = renderer.render_bundle(self.profile, self.bundle)

    def doc(self, kind, name, docs=None):
        return next(
            doc
            for doc in (self.docs if docs is None else docs)
            if doc["kind"] == kind and doc["metadata"]["name"] == name
        )

    def pod(self, docs=None):
        return self.doc("Deployment", renderer.PREFIX + "keycloak", docs)["spec"][
            "template"
        ]["spec"]

    def assert_invalid(self, change):
        docs = copy.deepcopy(self.docs)
        change(docs)
        with self.assertRaises(ValueError):
            renderer.validate_sso(docs, self.profile)

    def test_bundle_holds_only_keycloak_and_its_secret(self):
        self.assertEqual(
            sorted((doc["kind"], doc["metadata"]["name"]) for doc in self.docs),
            [
                ("ConfigMap", "authotron-sso-realm"),
                ("Deployment", "authotron-sso-keycloak"),
                ("Ingress", "authotron-sso-keycloak"),
                ("Secret", "authotron-browser-sso"),
                ("Service", "authotron-sso-keycloak"),
            ],
        )
        self.assertEqual(
            self.doc("Deployment", renderer.PREFIX + "keycloak")["spec"]["strategy"],
            {"type": "Recreate"},
        )

    def test_credential_rotation_rolls_keycloak_by_digest_only(self):
        original = self.doc("Deployment", renderer.PREFIX + "keycloak")
        for key in renderer.SECRET_KEYS:
            with self.subTest(key=key):
                bundle = dict(self.bundle, **{key: "rotated-" + "r" * 32})
                docs = renderer.render_bundle(self.profile, bundle)
                changed = self.doc("Deployment", renderer.PREFIX + "keycloak", docs)
                self.assertNotEqual(original, changed)
                self.assertRegex(
                    changed["spec"]["template"]["metadata"]["annotations"][
                        "checksum/credentials"
                    ],
                    r"^[0-9a-f]{64}$",
                )
                public = yaml.safe_dump_all(d for d in docs if d["kind"] != "Secret")
                for value in bundle.values():
                    self.assertNotIn(value, public)
                    self.assertNotIn(base64.b64encode(value.encode()).decode(), public)
        self.assert_invalid(
            lambda docs: self.doc("Deployment", renderer.PREFIX + "keycloak", docs)[
                "spec"
            ]["template"]["metadata"]["annotations"].pop("checksum/credentials")
        )

    def test_keycloak_pin_matches_the_server_interoperability_fixture(self):
        fixture = (
            Path(renderer.__file__).parents[2]
            / "src/routes/oidc_login/keycloak_tests.rs"
        )
        self.assertIn(
            f'const KEYCLOAK_IMAGE: &str = "{renderer.KEYCLOAK_IMAGE}";',
            fixture.read_text(),
        )

    def test_profile_is_immutable_and_derives_the_callback(self):
        with self.assertRaises(FrozenInstanceError):
            self.profile.ui_host = "other.example.org"
        self.assertEqual(
            self.profile.authotron_callback,
            "https://ui.example.org/login/method/demo-sso/callback",
        )
        self.assertEqual(
            self.profile.issuer, "https://issuer.example.org/realms/aviso-demo"
        )

    def test_input_validation(self):
        self.assertEqual(
            self.profile.trusted_proxies, ("10.70.0.0/16", "10.26.28.2", "2001:db8::1")
        )
        self.assertEqual(
            renderer.trusted_addresses(" 10.26.28.0/24 ,2001:db8::/64"),
            ("10.26.28.0/24", "2001:db8::/64"),
        )
        for addresses in (
            "",
            "0.0.0.0/0",
            "::/0",
            "10.70.1.0/16",
            "no-ip",
            "10.0.0.1,10.0.0.1",
            "10.0.0.1/32,10.0.0.1",
        ):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                renderer.trusted_addresses(addresses)
        for hosts in (
            ("ui.example.org", "ui.example.org"),
            ("https://ui.example.org", "issuer.example.org"),
            ("*.example.org", "issuer.example.org"),
        ):
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                renderer.Profile(*hosts, self.profile.trusted_proxies)
        with self.assertRaises(ValueError):
            renderer.Profile("ui.example.org", "issuer.example.org", ())

    def test_namespace_kind_names_duplicates_and_pod_safety_fail_closed(self):
        renderer.validate_sso(self.docs, self.profile)
        mutations = [
            lambda ds: ds[0]["metadata"].update(namespace="aviso2-dev"),
            lambda ds: ds[0].update(kind="Namespace"),
            lambda ds: ds[0].update(apiVersion="v2"),
            lambda ds: ds[0]["metadata"].update(name="foreign-config"),
            lambda ds: ds.append(copy.deepcopy(ds[0])),
            lambda ds: self.pod(ds).update(hostNetwork=True),
            lambda ds: self.pod(ds).update(automountServiceAccountToken=True),
            lambda ds: self.pod(ds)["volumes"].append(
                {"name": "host", "hostPath": {"path": "/"}}
            ),
            lambda ds: self.pod(ds)["containers"][0]["securityContext"].update(
                privileged=True
            ),
            lambda ds: self.pod(ds)["containers"][0].update(image="keycloak:latest"),
            lambda ds: ds.append(renderer.resource("ServiceAccount", "foreign")),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_invalid(mutation)
        with patch.object(renderer, "NAMESPACE", "other"):
            with self.assertRaises(ValueError):
                renderer.validate_sso(self.docs, self.profile)

    def test_callback_wildcard_rejected(self):
        def change_callback(ds):
            cm = self.doc("ConfigMap", renderer.PREFIX + "realm", ds)
            realm = json.loads(cm["data"][self.profile.realm_filename])
            realm["clients"][0]["redirectUris"] = ["https://ui.example.org/*"]
            cm["data"][self.profile.realm_filename] = json.dumps(realm)

        self.assert_invalid(change_callback)

    def test_realm_holds_only_secret_placeholders(self):
        public = yaml.safe_dump_all(
            [doc for doc in self.docs if doc["kind"] != "Secret"]
        )
        for credential in self.bundle.values():
            self.assertNotIn(credential, public)
        realm = renderer.realm_config(self.profile)
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

    def test_authotron_client_offline_sessions_and_e2e_admin(self):
        realm = renderer.realm_config(self.profile)
        for key, value in {
            "revokeRefreshToken": True,
            "refreshTokenMaxReuse": 0,
            "offlineSessionIdleTimeout": 30 * 86400,
            "offlineSessionMaxLifespanEnabled": True,
            "offlineSessionMaxLifespan": 90 * 86400,
        }.items():
            self.assertEqual(realm[key], value, key)
        clients = {client["clientId"]: client for client in realm["clients"]}
        self.assertEqual(set(clients), {"authotron-playground", "authotron-e2e-admin"})
        authotron = clients["authotron-playground"]
        self.assertEqual(authotron["id"], renderer.AUTHOTRON_CLIENT_UUID)
        self.assertEqual(authotron["secret"], "${AUTHOTRON_CLIENT_SECRET}")
        self.assertEqual(
            authotron["redirectUris"],
            ["https://ui.example.org/login/method/demo-sso/callback"],
        )
        self.assertEqual(
            authotron["defaultClientScopes"], ["basic", "profile", "email"]
        )
        self.assertEqual(authotron["optionalClientScopes"], ["offline_access"])
        self.assertEqual(authotron["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertTrue(authotron["standardFlowEnabled"])
        for key in (
            "publicClient",
            "directAccessGrantsEnabled",
            "implicitFlowEnabled",
            "serviceAccountsEnabled",
        ):
            self.assertFalse(authotron[key], key)
        admin = clients["authotron-e2e-admin"]
        self.assertEqual(admin["secret"], "${E2E_ADMIN_SECRET}")
        self.assertTrue(admin["serviceAccountsEnabled"])
        self.assertFalse(admin["standardFlowEnabled"] or admin["redirectUris"])
        users = {user["username"]: user for user in realm["users"]}
        self.assertEqual(users["alice"]["id"], renderer.DEMO_USER_ID)
        self.assertEqual(
            users["alice"]["realmRoles"], ["default-roles-aviso-demo", "offline_access"]
        )
        account = users["service-account-authotron-e2e-admin"]
        self.assertEqual(account["serviceAccountClientId"], "authotron-e2e-admin")
        self.assertEqual(
            account["clientRoles"], {"realm-management": ["manage-users", "view-users"]}
        )
        self.assertNotIn("credentials", account)
        env = {
            item["name"]: item["valueFrom"]["secretKeyRef"]["key"]
            for item in self.pod()["containers"][0]["env"]
            if "valueFrom" in item
        }
        self.assertEqual(
            env,
            {
                "AUTHOTRON_CLIENT_SECRET": "authotron-client-secret",
                "E2E_ADMIN_SECRET": "e2e-admin-secret",
                "DEMO_USER_PASSWORD": "demo-user-password",
            },
        )

    def test_exact_scoped_issuer_ingress_and_private_service(self):
        spec = self.doc("Ingress", renderer.PREFIX + "keycloak")["spec"]
        self.assertEqual(spec["rules"][0]["host"], "issuer.example.org")
        self.assertEqual(spec["tls"][0]["hosts"], ["issuer.example.org"])
        paths = [(p["path"], p["pathType"]) for p in spec["rules"][0]["http"]["paths"]]
        self.assertEqual(paths, list(self.profile.issuer_paths))
        base = f"/realms/{self.profile.realm}"
        self.assertIn((base + "/protocol/openid-connect/revoke", "Exact"), paths)
        self.assertNotIn((base, "Prefix"), paths)
        self.assertFalse(any("logout" in path or "admin" in path for path, _ in paths))
        self.assertEqual(
            self.doc("Service", renderer.PREFIX + "keycloak")["spec"]["type"],
            "ClusterIP",
        )
        args = self.pod()["containers"][0]["args"]
        # Forwarded scheme and client address are trusted only from the ingress peers.
        self.assertIn("--proxy-headers=xforwarded", args)
        self.assertIn(
            "--proxy-trusted-addresses=10.70.0.0/16,10.26.28.2,2001:db8::1", args
        )
        self.assert_invalid(
            lambda ds: self.doc("Ingress", renderer.PREFIX + "keycloak", ds)["spec"][
                "rules"
            ][0]["http"]["paths"][0].update(pathType="Prefix")
        )
        self.assert_invalid(
            lambda ds: self.doc("Service", renderer.PREFIX + "keycloak", ds)[
                "spec"
            ].update(type="LoadBalancer")
        )

    def test_secret_file_generation_permissions_reuse_and_invalid_file(self):
        path = self.root / "secrets.json"
        first = renderer.load_or_create_secrets(path)
        self.assertEqual(set(first), renderer.SECRET_KEYS)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
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
        for invalid in ("short", "not url safe " + "x" * 32):
            with self.assertRaises(ValueError):
                renderer.secret_resource(
                    dict(self.bundle, **{"e2e-admin-secret": invalid})
                )

    def test_older_bundles_gain_only_the_missing_keys(self):
        path = self.root / "older-secrets.json"
        older = {"demo-user-password": self.bundle["demo-user-password"]}
        renderer.write_file(path, json.dumps(older), private=True)
        loaded = renderer.load_or_create_secrets(path)
        self.assertEqual(set(loaded), renderer.SECRET_KEYS)
        self.assertEqual(loaded["demo-user-password"], older["demo-user-password"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text()), loaded)
        self.assertEqual(renderer.load_or_create_secrets(path), loaded)
        # Keys of the retired OAuth2-proxy demo are not accepted.
        path.write_text(json.dumps(dict(loaded, **{"cookie-secret": "x" * 43})))
        with self.assertRaises(ValueError):
            renderer.load_or_create_secrets(path)

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

    def cli_args(self):
        return [
            "render_sso.py",
            "--ui-host",
            self.profile.ui_host,
            "--issuer-host",
            self.profile.issuer_host,
            "--trusted-proxy-addresses",
            ",".join(self.profile.trusted_proxies),
            "--secret-file",
            str(self.root / "secret.json"),
            "--output-dir",
            str(self.root / "output"),
        ]

    def test_cli_rerender_writes_only_the_private_bundle_and_keeps_credentials(self):
        stdout = io.StringIO()
        with (
            patch("sys.argv", self.cli_args()),
            patch("sys.stdout", stdout),
            patch.object(renderer, "__file__", str(self.assets / "render_sso.py")),
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
        self.assertEqual(set(before), {"sso-resources.yaml"})
        self.assertEqual(
            stat.S_IMODE((output / "sso-resources.yaml").stat().st_mode), 0o600
        )
        for value in json.loads(secret_before).values():
            self.assertNotIn(value, stdout.getvalue())
        docs = list(yaml.safe_load_all(before["sso-resources.yaml"]))
        self.assertTrue(
            all(doc["metadata"]["namespace"] == "authotron-playground" for doc in docs)
        )
        self.assertFalse(any(doc["kind"] == "Namespace" for doc in docs))
        self.assertIn(self.profile.authotron_callback, stdout.getvalue())

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
        for name in (
            *renderer.preview.SOURCE_FILES,
            *renderer.preview.RESERVED_SOURCE_DIRS,
        ):
            path = self.project / name
            if name in renderer.preview.RESERVED_SOURCE_DIRS:
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
            patch.object(renderer, "render_bundle") as render,
        ):
            with self.assertRaises(SystemExit) as error:
                renderer.main()
        self.assertEqual(error.exception.code, 1)
        generate.assert_not_called()
        render.assert_not_called()

    def test_cli_rejects_git_archive_and_overlapping_locations(self):
        secret = self.root / "secret.json"
        output = self.root / "output"
        paths = [self.project / name for name in renderer.preview.SOURCE_FILES]
        paths += [
            self.project / name / "private"
            for name in renderer.preview.RESERVED_SOURCE_DIRS
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assert_cli_paths_rejected(path, output)
                self.assert_cli_paths_rejected(secret, path)
                self.assertFalse(path.exists())
        bundle = output / "sso-resources.yaml"
        self.assert_cli_paths_rejected(bundle, output)
        self.assert_cli_paths_rejected(bundle / "secret.json", output)
        self.assert_cli_paths_rejected(output, output)
        self.assert_cli_paths_rejected(secret, secret / "output")
        (self.project / ".git").write_text("gitdir: synthetic-worktree")
        self.assert_cli_paths_rejected(self.project / "private.json", output)
        self.assert_cli_paths_rejected(secret, self.project / "output")
        self.assertFalse(secret.exists())
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
