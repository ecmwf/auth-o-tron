"""Offline tests: no kubeconfig, cluster access or real Helm invocation."""

import copy
import io
import tempfile
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

import render
import yaml

HOST = "preview.example.org"
IMAGE = "docker.io/library/rust@sha256:" + "a" * 64


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        for name in render.SOURCE_FILES:
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("public build input\n")
        for name in render.RESERVED_SOURCE_DIRS:
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
                    "ui": {"enabled": True},
                }
            )
        )

    def helm_documents(self):
        values = render.preview_values(self.project, HOST)
        labels = {
            "app.kubernetes.io/name": render.RELEASE,
            "app.kubernetes.io/instance": render.RELEASE,
        }
        metadata = {"name": render.RELEASE, "namespace": render.NAMESPACE}
        probe = {"httpGet": {"path": "/health", "port": "http-auth"}}
        return [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": f"{render.RELEASE}-config"},
                "data": {"config.yaml": yaml.safe_dump(values["config"])},
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
                "metadata": {**metadata, "annotations": render.ANNOTATIONS},
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
                                                "name": render.RELEASE,
                                                "port": {"number": 8080},
                                            }
                                        },
                                    }
                                    for path, path_type in render.PATH_RULES
                                ]
                            },
                        }
                    ],
                },
            },
        ]

    def plan(self):
        with patch("render.subprocess.run") as command:
            command.return_value.stdout = yaml.safe_dump_all(self.helm_documents())
            resources, archive = render.render_preview(
                self.project, self.project, HOST, IMAGE
            )
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0][0:2], ["helm", "template"])
            self.assertIn(render.NAMESPACE, command.call_args.args[0])
        return resources, archive

    def test_render_is_namespace_confined_and_never_invokes_kubectl(self):
        resources, archive = self.plan()
        self.assertTrue(archive)
        self.assertEqual(len(resources), 5)
        self.assertTrue(
            all(doc["metadata"]["namespace"] == render.NAMESPACE for doc in resources)
        )
        deployment = next(doc for doc in resources if doc["kind"] == "Deployment")
        pod = deployment["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["securityContext"]["runAsUser"], 1000)
        self.assertEqual(
            pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault"
        )
        for container in pod["containers"] + pod["initContainers"]:
            self.assertEqual(container["image"], IMAGE)
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
            self.assertEqual(
                container["securityContext"]["capabilities"], {"drop": ["ALL"]}
            )
        self.assertEqual(pod["initContainers"][0]["args"], [render.BUILD_SCRIPT])
        self.assertEqual(pod["containers"][0]["command"], [render.EXECUTABLE])

    def test_manifest_guard_rejects_foreign_namespace_and_unknown_resources(self):
        valid = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "example"}}
        self.assertEqual(
            render.checked_resources([valid])[0]["metadata"]["namespace"],
            render.NAMESPACE,
        )
        for invalid in [
            {**valid, "metadata": {"name": "example", "namespace": "aviso2-dev"}},
            {**valid, "apiVersion": "unexpected/v1"},
            {**valid, "kind": "Namespace"},
            {**valid, "kind": "ClusterRole"},
            {**valid, "kind": "List"},
            {**valid, "metadata": {}},
            "not an object",
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                render.checked_resources([invalid])
        with self.assertRaises(ValueError):
            render.checked_resources([valid, valid])

    def test_invalid_helm_output_has_no_additional_side_effects(self):
        for extra in [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "other"}},
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "extra", "namespace": "aviso2-dev"},
            },
        ]:
            with patch("render.subprocess.run") as command:
                command.return_value.stdout = yaml.safe_dump_all(
                    self.helm_documents() + [extra]
                )
                with self.assertRaises(ValueError):
                    render.render_preview(self.project, self.project, HOST, IMAGE)
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[0][0], "helm")

    def test_final_guard_rejects_unsafe_pods_and_unintended_exposure(self):
        resources, _ = self.plan()
        values = render.preview_values(self.project, HOST)
        pod = next(doc for doc in resources if doc["kind"] == "Deployment")["spec"][
            "template"
        ]["spec"]
        for mutate in [
            lambda docs: next(doc for doc in docs if doc["kind"] == "Deployment")[
                "spec"
            ]["template"]["spec"].update(hostNetwork=True),
            lambda docs: next(doc for doc in docs if doc["kind"] == "Deployment")[
                "spec"
            ]["template"]["spec"]["volumes"].append(
                {"name": "host", "hostPath": {"path": "/"}}
            ),
            lambda docs: next(doc for doc in docs if doc["kind"] == "Deployment")[
                "spec"
            ]["template"]["spec"]["containers"][0]["securityContext"].update(
                privileged=True
            ),
            lambda docs: next(doc for doc in docs if doc["kind"] == "Service")[
                "spec"
            ].update(type="LoadBalancer"),
            lambda docs: next(doc for doc in docs if doc["kind"] == "Ingress")["spec"][
                "rules"
            ][0]["http"]["paths"][0].update(path="/", pathType="Prefix"),
            lambda docs: next(
                doc for doc in docs if doc["kind"] == "ConfigMap" and "data" in doc
            )["data"].update(other="unexpected"),
        ]:
            candidate = copy.deepcopy(resources)
            mutate(candidate)
            with self.assertRaises(ValueError):
                render.validate_preview(candidate, values, pod)

    def test_archive_is_deterministic_and_excludes_local_configuration(self):
        (self.project / "config.yaml").write_text("private credential")
        (self.project / ".kube").mkdir()
        (self.project / ".kube/config").write_text("private kubeconfig")
        first = render.source_archive(self.project)
        self.assertEqual(first, render.source_archive(self.project))
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            expected = set(render.SOURCE_FILES) | {
                f"{directory}/lib.rs" for directory in render.RESERVED_SOURCE_DIRS
            }
            self.assertEqual(set(archive.getnames()), expected)

    def test_archive_rejects_symlinks(self):
        private = self.project / "private.txt"
        private.write_text("private credential")
        source = self.project / "authotron/src/lib.rs"
        source.unlink()
        source.symlink_to(private)
        with self.assertRaises(ValueError):
            render.source_archive(self.project)

    def test_archive_never_enumerates_or_reads_virtual_untracked_secrets(self):
        read_bytes = Path.read_bytes
        reads = set()
        secrets = [
            self.project / directory / filename
            for directory in render.RESERVED_SOURCE_DIRS
            for filename in (
                ".env",
                "credentials.json",
                "credentials.rs",
                "private.lua",
            )
        ]

        def read_public(path):
            self.assertNotIn(path, secrets)
            reads.add(path.relative_to(self.project).as_posix())
            return read_bytes(path)

        with (
            patch.object(Path, "rglob", return_value=iter(secrets)) as enumerate_files,
            patch.object(Path, "read_bytes", read_public),
        ):
            data = render.source_archive(self.project)
        enumerate_files.assert_not_called()
        self.assertEqual(reads, set(render.SOURCE_FILES))
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            self.assertEqual(set(archive.getnames()), set(render.SOURCE_FILES))

    def test_exported_tree_includes_current_source_and_runtime_assets(self):
        self.assertFalse((self.project / ".git").exists())
        name = "authotron/src/lib.rs"
        (self.project / name).write_text("// current local modification\n")
        with patch.object(render.subprocess, "run", side_effect=AssertionError("git")):
            data = render.source_archive(self.project)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            self.assertEqual(
                archive.extractfile(name).read(), b"// current local modification\n"
            )
            for asset in (
                "browser/valkey.lua",
                "oauth/valkey_transactions.lua",
                "static/aviso-logo.base64",
                "static/login.css",
                "static/login.js",
                "static/favicon.ico",
                "static/logo.png",
                "static/index.html",
            ):
                self.assertIn("authotron/src/" + asset, archive.getnames())

    def test_missing_manifest_input_fails_closed(self):
        (self.project / "authotron/src/static/login.js").unlink()
        with self.assertRaises(ValueError):
            render.source_archive(self.project)

    def test_archive_and_fixture_reject_symlinked_ancestors(self):
        actual = self.project / "renamed-authotron"
        (self.project / "authotron").rename(actual)
        (self.project / "authotron").symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            render.source_archive(self.project)
        with self.assertRaises(ValueError):
            render.preview_values(self.project, HOST)

    def test_final_guard_rejects_weakened_selectors_and_service_annotations(self):
        resources, _ = self.plan()
        values = render.preview_values(self.project, HOST)
        pod = next(doc for doc in resources if doc["kind"] == "Deployment")["spec"][
            "template"
        ]["spec"]
        for selector in [{}, {"app.kubernetes.io/instance": render.RELEASE}]:
            candidate = copy.deepcopy(resources)
            service = next(doc for doc in candidate if doc["kind"] == "Service")
            service["spec"]["selector"] = selector
            with self.assertRaises(ValueError):
                render.validate_preview(candidate, values, pod)
        candidate = copy.deepcopy(resources)
        service = next(doc for doc in candidate if doc["kind"] == "Service")
        service["metadata"]["annotations"] = {"unreviewed.example/expose": "true"}
        with self.assertRaises(ValueError):
            render.validate_preview(candidate, values, pod)

    def test_final_guard_rejects_changed_configuration_and_source_identity(self):
        resources, _ = self.plan()
        values = render.preview_values(self.project, HOST)
        pod = next(doc for doc in resources if doc["kind"] == "Deployment")["spec"][
            "template"
        ]["spec"]
        candidate = copy.deepcopy(resources)
        config = next(
            doc for doc in candidate if doc["kind"] == "ConfigMap" and "data" in doc
        )
        config["data"]["config.yaml"] = "providers: [unexpected]"
        with self.assertRaises(ValueError):
            render.validate_preview(candidate, values, pod)
        candidate = copy.deepcopy(resources)
        source = next(
            doc
            for doc in candidate
            if doc["kind"] == "ConfigMap" and "binaryData" in doc
        )
        source["metadata"]["name"] = "incorrect-source-identity"
        with self.assertRaises(ValueError):
            render.validate_preview(candidate, values, pod)

    def test_host_and_image_validation(self):
        render.validate_inputs(HOST, IMAGE)
        for host in [
            "https://example.org",
            "*.example.org",
            "example.org/path",
            "bad host.example",
        ]:
            with self.assertRaises(ValueError):
                render.validate_inputs(host, IMAGE)
        for image in [
            "rust:latest",
            "rust:1.90",
            "untrusted.example/image@sha256:" + "a" * 64,
        ]:
            with self.assertRaises(ValueError):
                render.validate_inputs(HOST, image)

    def test_ingress_profile_routes_only_login_and_public_assets(self):
        values = render.preview_values(self.project, HOST)
        paths = values["ingress"]["hosts"][0]["paths"]
        self.assertEqual(
            paths,
            [
                {"path": "/login", "pathType": "Exact"},
                {"path": "/login/", "pathType": "Exact"},
                {"path": "/static/", "pathType": "Prefix"},
                {"path": "/favicon.ico", "pathType": "ImplementationSpecific"},
            ],
        )
        self.assertFalse(any(path["path"] == "/" for path in paths))


if __name__ == "__main__":
    unittest.main()
