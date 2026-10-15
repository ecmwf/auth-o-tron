"""Self-contained setup tests: all secrets are generated in disposable temp dirs."""

import asyncio
import contextlib
import io
import ipaddress
import json
import os
import selectors
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import aiohttp
import demo_settings
import jsonschema
import prepare_demo as setup
import run_demo
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from yarl import URL


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="authotron-setup-")
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name) / "runtime"

    def test_new_private_runtime_and_complete_config(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            setup.prepare(self.runtime)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o700)
        for file in self.runtime.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600, file.name)
        config = json.loads((self.runtime / "authotron.json").read_text())
        schema = json.loads((setup.REPOSITORY / "authotron" / "schema.json").read_text())
        jsonschema.validate(config, schema)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(dict(config, version="invalid"), schema)
        credentials = json.loads((self.runtime / "credentials.json").read_text())
        settings = json.loads((self.runtime / "settings.json").read_text())
        self.assertEqual(settings, demo_settings.LOCAL_SETTINGS)
        self.assertEqual(config["version"], "2.0.0")
        self.assertEqual(config["server"], {"host": "127.0.0.1", "port": 8000})
        self.assertFalse(config["metrics"]["enabled"])
        self.assertFalse(config["store"]["enabled"])
        self.assertEqual(config["services"], [])
        self.assertEqual(config["augmenters"], [])
        self.assertEqual(config["providers"][0]["users"], [dict(credentials, roles=["reader"])])
        self.assertEqual(credentials["username"], "alice")
        self.assertGreaterEqual(len(credentials["password"]), 32)
        self.assertGreaterEqual(len(config["jwt"]["secret"]), 32)
        self.assertEqual(
            config["providers"][0]["browser"], {"id": "password", "label": "Username and password"}
        )
        self.assertNotIn("basic", config["ui"])
        self.assertEqual(
            config["ui"]["browser_session"]["public_origin"], demo_settings.LOCAL_ISSUER.rstrip("/")
        )
        self.assertEqual(config["ui"]["browser_session"]["backend"], {"type": "memory"})
        oauth = config["oauth"]
        self.assertTrue(oauth["enabled"])
        self.assertEqual(oauth["issuer"], demo_settings.LOCAL_ISSUER)
        self.assertEqual(oauth["clients"][0]["client_id"], setup.CLIENT_ID)
        self.assertEqual(oauth["clients"][0]["application_type"], "native")
        self.assertEqual(oauth["clients"][0]["redirect_uris"], [setup.CALLBACK])
        self.assertEqual(
            oauth["clients"][0]["resources"],
            [{"resource": setup.RESOURCE, "scopes": [setup.SCOPE]}],
        )
        self.assertEqual(
            oauth["clients"][0]["refresh_tokens"],
            {"enabled": True, "idle_ttl_seconds": 86400, "absolute_ttl_seconds": 604800},
        )
        self.assertEqual(
            oauth["resources"],
            [
                {
                    "resource": setup.RESOURCE,
                    "allowed_realms": ["local"],
                    "scopes": [{"name": setup.SCOPE, "required_roles": ["reader"]}],
                }
            ],
        )
        self.assertEqual(
            oauth["signing"]["keys"][0]["private_key_file"], str(self.runtime / "oauth-private.pem")
        )
        key = serialization.load_pem_private_key(
            (self.runtime / "oauth-private.pem").read_bytes(), password=None
        )
        self.assertIsInstance(key, rsa.RSAPrivateKey)
        self.assertGreaterEqual(key.key_size, 2048)
        another = setup.prepare(Path(self.temp.name) / "another")
        self.assertNotEqual(credentials, json.loads((another / "credentials.json").read_text()))

    def test_existing_directory_file_and_symlink_are_refused(self):
        self.runtime.mkdir()
        sentinel = self.runtime / "sentinel"
        sentinel.write_text("preserve")
        with self.assertRaises(FileExistsError):
            setup.prepare(self.runtime)
        self.assertEqual(sentinel.read_text(), "preserve")
        link = Path(self.temp.name) / "alias"
        link.symlink_to(self.runtime, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            setup.prepare(link)
        dangling = Path(self.temp.name) / "dangling"
        dangling.symlink_to(Path(self.temp.name) / "missing")
        with self.assertRaises(FileExistsError):
            setup.prepare(dangling)
        file = Path(self.temp.name) / "file"
        file.write_text("preserve")
        with self.assertRaises(FileExistsError):
            setup.prepare(file)

    def test_repository_and_symlink_alias_are_refused(self):
        with self.assertRaises(ValueError):
            setup.prepare(setup.REPOSITORY / "runtime-test-must-not-exist")
        link = Path(self.temp.name) / "repo-alias"
        link.symlink_to(setup.REPOSITORY, target_is_directory=True)
        with self.assertRaises(ValueError):
            setup.prepare(link / "runtime-test-must-not-exist")

    def test_failed_generation_removes_partial_runtime(self):
        with (
            patch.object(setup, "generate_tls", side_effect=RuntimeError("fixture failure")),
            self.assertRaises(RuntimeError),
        ):
            setup.prepare(self.runtime)
        self.assertFalse(self.runtime.exists())

    def test_source_archive_excludes_generated_secrets(self):
        # Archive explicit example sources, never private runtime material.
        setup.prepare(self.runtime)
        files = [
            Path(__file__).with_name(name)
            for name in (
                "demo_settings.py",
                "prepare_demo.py",
                "run_demo.py",
                "server.py",
                "client.py",
                "test_setup.py",
                "test_auth.py",
                "test_e2e.py",
                "test_remote.py",
                "README.md",
                "pyproject.toml",
                ".gitignore",
            )
        ]
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as bundle:
            for file in files:
                bundle.add(file, arcname=file.name)
        data = archive.getvalue()
        password = json.loads((self.runtime / "credentials.json").read_text())["password"].encode()
        self.assertNotIn(password, data)
        for name in ("oauth-private.pem", "tls-key.pem", "credentials.json"):
            self.assertFalse((self.runtime / name).read_bytes() in data, name)
        with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
            self.assertEqual(set(bundle.getnames()), {file.name for file in files})

    def test_environment_removes_config_overrides_and_proxies(self):
        with patch.dict(
            os.environ,
            {
                "AOT_SERVER__HOST": "0.0.0.0",
                "aot_jwt__secret": "fixture",
                "HTTPS_PROXY": "http://invalid",
                "all_proxy": "http://invalid",
                "NO_PROXY": "",
                "PATH": "/fixture",
            },
            clear=True,
        ):
            self.assertEqual(run_demo.clean_environment(), {"PATH": "/fixture"})


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_verifies_loopback_ip_and_rejects_other_host(self):
        with tempfile.TemporaryDirectory(prefix="authotron-tls-") as temp:
            runtime = setup.prepare(Path(temp) / "runtime")
            ca = x509.load_pem_x509_certificate((runtime / "tls-ca.pem").read_bytes())
            leaf = x509.load_pem_x509_certificate((runtime / "tls-cert.pem").read_bytes())
            self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(
                leaf.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.IPAddress),
                [ipaddress.ip_address("127.0.0.1")],
            )
            ca.public_key().verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf.signature_hash_algorithm,
            )
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(runtime / "tls-cert.pem", runtime / "tls-key.pem")
            verify = ssl.create_default_context(cafile=str(runtime / "tls-ca.pem"))

            async def handle(reader, writer):
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=tls)
            loop = asyncio.get_running_loop()
            previous_handler = loop.get_exception_handler()

            def expected_tls_reset(loop, context):
                if not isinstance(context.get("exception"), ConnectionResetError):
                    if previous_handler:
                        previous_handler(loop, context)
                    else:
                        loop.default_exception_handler(context)

            loop.set_exception_handler(expected_tls_reset)
            self.addCleanup(loop.set_exception_handler, previous_handler)
            async with server:
                port = server.sockets[0].getsockname()[1]
                _, writer = await asyncio.open_connection(
                    "127.0.0.1", port, ssl=verify, server_hostname="127.0.0.1"
                )
                writer.close()
                await writer.wait_closed()
                with self.assertRaises(ssl.SSLCertVerificationError):
                    await asyncio.open_connection(
                        "127.0.0.1", port, ssl=verify, server_hostname="localhost"
                    )
                await asyncio.sleep(0.01)

    async def test_proxy_preserves_origin_redirect_cookies_path_and_body(self):
        received = {}

        async def backend(request):
            received.update(
                origin=request.headers.get("Origin"),
                path=request.raw_path,
                body=await request.read(),
                forwarded=request.headers.get("X-Forwarded-Host"),
            )
            response = web.Response(status=303, body=b"fixture-body")
            response.headers["Location"] = setup.CALLBACK + "?code=synthetic"
            response.headers.add("Set-Cookie", "first=fixture; Secure; HttpOnly; Path=/")
            response.headers.add("Set-Cookie", "second=fixture; Secure; HttpOnly; Path=/")
            return response

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", backend)
        async with (
            TestServer(app) as backend_server,
            aiohttp.ClientSession(trust_env=False, auto_decompress=False) as upstream,
            TestServer(run_demo.proxy_app(upstream, backend_server.port)) as proxy,
            aiohttp.ClientSession(trust_env=False) as client,
        ):
            url = URL(str(proxy.make_url("/")) + "oauth/consent?q=a%2Fb", encoded=True)
            async with client.post(
                url,
                data=b"synthetic-form",
                headers={
                    "Origin": demo_settings.LOCAL_ISSUER.rstrip("/"),
                    "X-Forwarded-Host": "invalid",
                },
                allow_redirects=False,
            ) as response:
                self.assertEqual(response.status, 303)
                self.assertEqual(response.headers["Location"], setup.CALLBACK + "?code=synthetic")
                self.assertEqual(len(response.headers.getall("Set-Cookie")), 2)
                self.assertEqual(await response.read(), b"fixture-body")
        self.assertEqual(
            received,
            {
                "origin": demo_settings.LOCAL_ISSUER.rstrip("/"),
                "path": "/oauth/consent?q=a%2Fb",
                "body": b"synthetic-form",
                "forwarded": None,
            },
        )


class PortCheckTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "TIME_WAIT reuse is POSIX behaviour")
    def test_port_check_ignores_time_wait_but_not_listeners(self):
        with socket.create_server(("127.0.0.1", 0)) as listener:
            port = listener.getsockname()[1]
            with self.assertRaises(OSError):
                run_demo.check_ports((port,))
            client = socket.create_connection(("127.0.0.1", port))
            accepted, _ = listener.accept()
            # The server side closes first, so its end waits in TIME_WAIT.
            accepted.close()
            client.recv(1)
            client.close()
        run_demo.check_ports((port,))


@unittest.skipUnless(
    os.environ.get("AUTHOTRON_DEMO_BIN"), "set AUTHOTRON_DEMO_BIN for process smoke test"
)
class ProcessTests(unittest.TestCase):
    def test_startup_timeout_stops_children(self):
        with tempfile.TemporaryDirectory(prefix="authotron-timeout-") as temp:
            runtime = setup.prepare(Path(temp) / "runtime")
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).with_name("run_demo.py")),
                    "--runtime-dir",
                    str(runtime),
                    "--authotron-bin",
                    os.environ["AUTHOTRON_DEMO_BIN"],
                    "--startup-timeout",
                    "0.000000001",
                ],
                capture_output=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"children stopped", result.stderr)
            for port in (8000, 8001, 8443, 8444):
                with socket.socket() as probe:
                    self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0, port)

    def test_ready_shutdown_and_no_default_credential_output(self):
        with tempfile.TemporaryDirectory(prefix="authotron-runner-") as temp:
            runtime = setup.prepare(Path(temp) / "runtime")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).with_name("run_demo.py")),
                    "--runtime-dir",
                    str(runtime),
                    "--authotron-bin",
                    os.environ["AUTHOTRON_DEMO_BIN"],
                    "--startup-timeout",
                    "20",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output = bytearray()
            try:
                deadline = time.monotonic() + 25
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while b"Local demo ready:" not in output:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            self.fail("local runner did not become ready")
                        for key, _ in selector.select(timeout=0.1):
                            output.extend(os.read(key.fileobj.fileno(), 65536))
            finally:
                process.terminate()
                try:
                    remaining, errors = process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    self.fail("runner did not clean up on SIGTERM")
                output.extend(remaining)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(errors, b"")
            credentials = json.loads((runtime / "credentials.json").read_text())
            self.assertFalse(credentials["password"].encode() in output)
            for port in (8000, 8001, 8443, 8444):
                with socket.socket() as probe:
                    self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0, port)


if __name__ == "__main__":
    unittest.main()
