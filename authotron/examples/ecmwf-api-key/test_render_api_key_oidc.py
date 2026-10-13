"""Offline contracts of the demo SSO (Keycloak) method."""

import base64
import copy
import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import render_api_key as renderer
import test_render_api_key as base
import yaml

ISSUER = "https://sso.example.org/realms/aviso-demo"
CLIENT_SECRET = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
OIDC = {"issuer": ISSUER, "client_secret": CLIENT_SECRET}


def config_of(resources):
    config_map = next(
        doc for doc in resources if doc["kind"] == "ConfigMap" and "data" in doc
    )
    return yaml.safe_load(config_map["data"]["config.yaml"])


def private_config_of(resources):
    secret = base.find(resources, "Secret")
    return yaml.safe_load(base64.b64decode(secret["data"]["config.yaml"]))


class OidcRendererTests(unittest.TestCase):
    setUp = base.RendererTests.setUp
    helm_documents = base.RendererTests.helm_documents
    baseline = base.RendererTests.baseline

    def options(self, **changes):
        return {
            "valkey_password": base.VALKEY_PASSWORD,
            "oauth_key": base.OAUTH_KEY,
            "oauth_aviso_resource": base.AVISO,
            "oidc": copy.deepcopy(OIDC),
            **changes,
        }

    def render(self, baseline, **changes):
        options = self.options(**changes)
        resources = renderer.transform(
            baseline, base.HOST, base.TOKEN, base.BASIC, **options
        )
        renderer.validate_resources(
            resources,
            baseline,
            base.HOST,
            base.IMAGE,
            base.TOKEN,
            base.BASIC,
            **options,
        )
        return resources

    def test_demo_sso_method_and_secret_mount(self):
        baseline, archive = self.baseline()
        resources = self.render(baseline)
        for config in (config_of(resources), private_config_of(resources)):
            self.assertEqual(
                config["ui"]["oidc"],
                [
                    {
                        "id": "demo-sso",
                        "label": "Demo SSO (Keycloak)",
                        "realm": "demo-sso",
                        "issuer": ISSUER,
                        "client_id": "authotron-playground",
                        "client_secret_file": "/run/secrets/oidc/client-secret",
                        "scopes": ["profile", "email"],
                        "offline_access": True,
                    }
                ],
            )
            for resource in config["oauth"]["resources"]:
                self.assertEqual(
                    resource["allowed_realms"], ["browser-demo", "ecmwf", "demo-sso"]
                )
        secret = base.find(resources, "Secret")
        self.assertEqual(
            base64.b64decode(secret["data"]["oidc-client-secret"]).decode(),
            CLIENT_SECRET,
        )
        template = base.find(resources, "Deployment")["spec"]["template"]
        volume = next(v for v in template["spec"]["volumes"] if v["name"] == "oidc")
        self.assertEqual(volume["secret"]["secretName"], renderer.SECRET_NAME)
        self.assertEqual(volume["secret"]["defaultMode"], 0o440)
        self.assertIn(
            {"key": "oidc-client-secret", "path": "client-secret"},
            volume["secret"]["items"],
        )
        self.assertIn(
            {"name": "oidc", "mountPath": "/run/secrets/oidc", "readOnly": True},
            template["spec"]["containers"][0]["volumeMounts"],
        )
        self.assertRegex(
            template["metadata"]["annotations"]["checksum/oidc-credentials"],
            r"^[0-9a-f]{64}$",
        )
        public = yaml.safe_dump_all(d for d in resources if d["kind"] != "Secret")
        for value in OIDC.values():
            if value != ISSUER:
                self.assertNotIn(value, public)
                self.assertNotIn(value, archive.decode("latin-1"))

    def test_credential_changes_roll_out_by_digest_only(self):
        baseline, _ = self.baseline()

        def annotation(**oidc):
            resources = self.render(baseline, oidc={**OIDC, **oidc})
            template = base.find(resources, "Deployment")["spec"]["template"]
            return template["metadata"]["annotations"]["checksum/oidc-credentials"]

        original = annotation()
        self.assertNotEqual(annotation(client_secret=base.TOKEN), original)

    def test_demo_sso_requires_oauth_and_valid_settings(self):
        baseline, _ = self.baseline()
        with self.assertRaises(ValueError):
            renderer.transform(
                baseline,
                base.HOST,
                base.TOKEN,
                base.BASIC,
                valkey_password=base.VALKEY_PASSWORD,
                oidc=copy.deepcopy(OIDC),
            )
        for change in (
            {"issuer": "http://sso.example.org/realms/aviso-demo"},
            {"issuer": ISSUER + "/"},
            {"issuer": ISSUER + "?x=1"},
            {"issuer": "https://sso/realms/aviso-demo"},
            {"issuer": "https://sso.example.org/realms/../admin"},
            {"client_secret": "short"},
            {"extra": "value"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                renderer.transform(
                    baseline,
                    base.HOST,
                    base.TOKEN,
                    base.BASIC,
                    **self.options(oidc={**OIDC, **change}),
                )

    def test_guard_rejects_demo_sso_mutations(self):
        baseline, _ = self.baseline()
        options = self.options()
        resources = self.render(baseline)

        def edit_config(change):
            def mutate(docs):
                secret = base.find(docs, "Secret")
                config = private_config_of(docs)
                change(config)
                secret["data"]["config.yaml"] = base64.b64encode(
                    yaml.safe_dump(config).encode()
                ).decode()

            return mutate

        def pod(docs):
            return base.find(docs, "Deployment")["spec"]["template"]["spec"]

        mutations = [
            edit_config(lambda c: c["ui"]["oidc"][0].update(issuer=ISSUER + "x")),
            edit_config(lambda c: c["ui"]["oidc"][0].update(offline_access=False)),
            edit_config(
                lambda c: c["ui"]["oidc"][0].update(client_secret_file="/tmp/s")
            ),
            lambda d: base.find(d, "Secret")["data"].update(
                {"oidc-client-secret": base64.b64encode(b"other").decode()}
            ),
            lambda d: pod(d)["containers"][0]["volumeMounts"][-1].update(
                readOnly=False
            ),
            lambda d: next(v for v in pod(d)["volumes"] if v["name"] == "oidc")[
                "secret"
            ].update(defaultMode=0o444),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                candidate = copy.deepcopy(resources)
                mutate(candidate)
                with self.assertRaises(ValueError):
                    renderer.validate_resources(
                        candidate,
                        baseline,
                        base.HOST,
                        base.IMAGE,
                        base.TOKEN,
                        base.BASIC,
                        **options,
                    )

    def test_sso_bundle_is_read_but_never_created_or_changed(self):
        bundle = self.root / "sso.json"
        missing = self.root / "absent.json"
        with self.assertRaises(OSError):
            renderer.sso_client_secret(missing)
        self.assertFalse(missing.exists())
        fd = renderer.directory_fd(self.root)
        try:
            renderer.private_write(
                fd,
                bundle.name,
                json.dumps({"authotron-client-secret": CLIENT_SECRET, "other": "x"}),
            )
        finally:
            os.close(fd)
        before = bundle.read_bytes()
        self.assertEqual(renderer.sso_client_secret(bundle), CLIENT_SECRET)
        self.assertEqual(bundle.read_bytes(), before)
        bundle.write_text(json.dumps({"client-secret": CLIENT_SECRET}))
        with self.assertRaises(ValueError):
            renderer.sso_client_secret(bundle)
        bundle.chmod(0o644)
        with self.assertRaises(ValueError):
            renderer.sso_client_secret(bundle)

    def sso_arguments(self):
        return base.RendererTests.cli_arguments(self) + [
            "--valkey-secret-file",
            str(self.root / "valkey.json"),
            "--oauth-secret-file",
            str(self.root / "oauth.json"),
            "--sso-issuer",
            ISSUER,
            "--sso-secret-file",
            str(self.root / "sso.json"),
        ]

    def test_cli_passes_demo_sso_without_printing_secrets(self):
        baseline, _ = self.baseline()
        resources = renderer.transform(
            baseline, base.HOST, base.TOKEN, None, **self.options()
        )
        with (
            patch("sys.argv", self.sso_arguments()),
            patch.object(renderer, "signing_secret", return_value=base.TOKEN),
            patch.object(renderer, "valkey_secret", return_value=base.VALKEY_PASSWORD),
            patch.object(renderer, "oauth_signing_key", return_value=base.OAUTH_KEY),
            patch.object(renderer, "sso_client_secret", return_value=CLIENT_SECRET),
            patch.object(
                renderer, "render_api_key", return_value=(resources, b"archive")
            ) as render,
            patch("builtins.print") as printed,
        ):
            renderer.main()
        self.assertEqual(render.call_args.kwargs["oidc"], OIDC)
        self.assertIn(ISSUER, str(printed.call_args_list))
        self.assertNotIn(CLIENT_SECRET, str(printed.call_args_list))

    def test_cli_rejects_partial_or_unsupported_sso_before_credentials(self):
        full = self.sso_arguments()
        oauth_less = list(full)
        index = oauth_less.index("--oauth-secret-file")
        del oauth_less[index : index + 2]
        invalid = [
            full[: full.index("--sso-secret-file")],
            oauth_less,
            [a if a != ISSUER else ISSUER + "/" for a in full],
            full[:-1] + [str(self.root / "valkey.json")],
        ]
        for arguments in invalid:
            with (
                self.subTest(arguments=arguments[-6:]),
                patch("sys.argv", arguments),
                patch.object(renderer, "signing_secret") as signing,
                patch.object(renderer, "sso_client_secret") as sso,
                patch.object(renderer, "render_api_key") as render,
            ):
                with self.assertRaises(ValueError):
                    renderer.main()
                for mocked in (signing, sso, render):
                    mocked.assert_not_called()

    def test_method_and_client_ids_match_the_sso_realm(self):
        path = Path(renderer.__file__).parents[1] / "browser-sso/render_sso.py"
        spec = importlib.util.spec_from_file_location("sso_renderer", path)
        sso = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sso)
        self.assertEqual(sso.AUTHOTRON_METHOD_ID, renderer.OIDC_METHOD_ID)
        self.assertEqual(sso.AUTHOTRON_CLIENT_ID, renderer.OIDC_CLIENT_ID)
        self.assertIn(renderer.OIDC_BUNDLE_KEY, sso.SECRET_KEYS)


if __name__ == "__main__":
    unittest.main()
