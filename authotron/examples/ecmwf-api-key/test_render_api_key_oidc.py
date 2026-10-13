"""Offline contracts of the demo SSO (Keycloak) method."""

import base64
import copy
import importlib.util
import unittest
from pathlib import Path

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
