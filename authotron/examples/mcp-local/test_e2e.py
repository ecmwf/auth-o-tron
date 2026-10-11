"""Opt-in real-process OAuth-to-MCP regression using disposable local credentials."""

import asyncio
import base64
import hashlib
from datetime import timedelta
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx
import jwt
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


class HiddenFields(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.fields = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("type") == "hidden":
            self.fields[values["name"]] = values.get("value", "")


@unittest.skipUnless(os.environ.get("AUTHOTRON_DEMO_BIN"), "set AUTHOTRON_DEMO_BIN")
class EndToEnd(unittest.TestCase):
    def test_real_https_oauth_and_sdk_tool(self):
        here = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix="authotron-mcp-e2e-") as parent:
            runtime = Path(parent) / "runtime"
            subprocess.run(
                [sys.executable, str(here / "prepare_demo.py"), "--runtime-dir", str(runtime)],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            runner = subprocess.Popen(
                [
                    sys.executable,
                    str(here / "run_demo.py"),
                    "--runtime-dir",
                    str(runtime),
                    "--authotron-bin",
                    os.environ["AUTHOTRON_DEMO_BIN"],
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                self.exercise(runtime, runner)
            finally:
                try:
                    os.killpg(runner.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    runner.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(runner.pid, signal.SIGKILL)
                    runner.wait(timeout=5)
                finally:
                    # A supervisor can exit before all of its children finish.
                    try:
                        os.killpg(runner.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def exercise(self, runtime, runner):
        issuer = "https://127.0.0.1:8443/"
        resource = "https://127.0.0.1:8444/mcp"
        callback = "http://127.0.0.1:49152/callback"
        tls = ssl.create_default_context(cafile=str(runtime / "tls-ca.pem"))
        with httpx.Client(verify=tls, trust_env=False, timeout=10) as http:
            deadline = time.monotonic() + 30
            while True:
                try:
                    response = http.get(issuer + ".well-known/oauth-authorization-server")
                    response.raise_for_status()
                    break
                except httpx.HTTPError:
                    if runner.poll() is not None or time.monotonic() > deadline:
                        self.fail("demo failed to start HTTPS endpoints")
                    time.sleep(0.2)
            self.assertEqual(response.json()["issuer"], issuer)
            for _ in range(100):
                try:
                    unauthorized = http.post(resource, json={})
                    if unauthorized.status_code == 502:
                        time.sleep(0.1)
                        continue
                    break
                except httpx.HTTPError:
                    time.sleep(0.1)
            else:
                self.fail("MCP endpoint did not become ready")
            self.assertEqual(unauthorized.status_code, 401)
            challenge = unauthorized.headers["www-authenticate"]
            self.assertIn("resource_metadata=", challenge)
            metadata_url = challenge.split('resource_metadata="', 1)[1].split('"', 1)[0]
            metadata = http.get(metadata_url)
            metadata.raise_for_status()
            self.assertEqual(metadata.json()["resource"], resource)
            self.assertIn(issuer, metadata.json()["authorization_servers"])
            verifier = secrets.token_urlsafe(48)
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            state = secrets.token_urlsafe(24)
            response = http.get(
                issuer
                + "oauth/authorize?"
                + urlencode(
                    {
                        "client_id": "mcp-local",
                        "redirect_uri": callback,
                        "response_type": "code",
                        "resource": resource,
                        "scope": "mcp:read",
                        "state": state,
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                    }
                )
            )
            self.assertEqual(response.status_code, 303)
            form = http.get(issuer + "login/basic")
            form.raise_for_status()
            fields = HiddenFields(form.text).fields
            credentials = json.loads((runtime / "credentials.json").read_text())
            fields.update(username=credentials["username"], password=credentials["password"])
            response = http.post(
                issuer + "login/basic", data=fields, headers={"Origin": issuer.rstrip("/")}
            )
            self.assertEqual(response.status_code, 303)
            consent = http.get(issuer + "oauth/continue")
            consent.raise_for_status()
            fields = HiddenFields(consent.text).fields
            fields["decision"] = "approve"
            response = http.post(
                issuer + "oauth/consent", data=fields, headers={"Origin": issuer.rstrip("/")}
            )
            self.assertEqual(response.status_code, 303)
            location = urlsplit(response.headers["location"])
            self.assertEqual(location.scheme + "://" + location.netloc + location.path, callback)
            query = parse_qs(location.query)
            self.assertEqual(query["state"], [state])
            self.assertEqual(query["iss"], [issuer])
            exchange = {
                "grant_type": "authorization_code",
                "client_id": "mcp-local",
                "redirect_uri": callback,
                "resource": resource,
                "code": query["code"][0],
                "code_verifier": verifier,
            }
            response = http.post(issuer + "oauth/token", data=exchange)
            self.assertEqual(response.status_code, 200)
            token = response.json()["access_token"]
            self.assertEqual(http.post(issuer + "oauth/token", data=exchange).status_code, 400)
            self.assertEqual(
                http.post(
                    resource, json={}, headers={"Authorization": "Bearer invalid"}
                ).status_code,
                401,
            )
            claims = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            private_key = (runtime / "oauth-private.pem").read_bytes()
            positive_control = jwt.encode(claims, private_key, algorithm="RS256", headers=header)
            asyncio.run(asyncio.wait_for(self.call_tool(resource, tls, positive_control), 30))
            segments = token.split(".")
            segments[2] = ("A" if segments[2][0] != "A" else "B") + segments[2][1:]
            corrupted = ".".join(segments)
            self.assertEqual(
                http.post(
                    resource, json={}, headers={"Authorization": "Bearer " + corrupted}
                ).status_code,
                401,
            )
            for field, value in (
                ("aud", "https://wrong.example/mcp"),
                ("iss", "https://wrong.example/"),
                ("exp", 1),
            ):
                altered = jwt.encode(
                    {**claims, field: value}, private_key, algorithm="RS256", headers=header
                )
                self.assertEqual(
                    http.post(
                        resource, json={}, headers={"Authorization": "Bearer " + altered}
                    ).status_code,
                    401,
                )
            wrong_type = jwt.encode(
                claims, private_key, algorithm="RS256", headers={**header, "typ": "JWT"}
            )
            self.assertEqual(
                http.post(
                    resource, json={}, headers={"Authorization": "Bearer " + wrong_type}
                ).status_code,
                401,
            )
            unscoped = jwt.encode(
                {**claims, "scope": "other"}, private_key, algorithm="RS256", headers=header
            )
            self.assertEqual(
                http.post(
                    resource, json={}, headers={"Authorization": "Bearer " + unscoped}
                ).status_code,
                403,
            )
            asyncio.run(asyncio.wait_for(self.call_tool(resource, tls, token), 30))
            self.exercise_client(http, runtime, issuer, credentials)
            self.exercise_client(http, runtime, issuer, credentials, failed_exchange=True)

    def exercise_client(self, http, runtime, issuer, credentials, failed_exchange=False):
        client = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).parent / "client.py"),
                "--runtime-dir",
                str(runtime),
                "--no-browser",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        lines = queue.Queue()

        def read_url():
            for line in client.stdout:
                if "oauth/authorize?" in line:
                    lines.put(line)
                    return

        reader = threading.Thread(target=read_url, daemon=True)
        reader.start()
        try:
            try:
                line = lines.get(timeout=15)
            except queue.Empty:
                self.fail("native client did not provide an authorization URL")
            match = re.search(r"https://127\.0\.0\.1:8443/oauth/authorize\?\S+", line)
            self.assertIsNotNone(match, "native client URL must use the configured issuer")
            response = http.get(match.group(0))
            self.assertEqual(response.status_code, 303)
            fields = HiddenFields(http.get(issuer + "login/basic").text).fields
            fields.update(username=credentials["username"], password=credentials["password"])
            response = http.post(
                issuer + "login/basic", data=fields, headers={"Origin": issuer.rstrip("/")}
            )
            self.assertEqual(response.status_code, 303)
            fields = HiddenFields(http.get(issuer + "oauth/continue").text).fields
            fields["decision"] = "approve"
            response = http.post(
                issuer + "oauth/consent", data=fields, headers={"Origin": issuer.rstrip("/")}
            )
            self.assertEqual(response.status_code, 303)
            callback_url = response.headers["location"]
            callback_parts = urlsplit(callback_url)
            params = parse_qs(callback_parts.query)
            original_code = params["code"][0]
            if failed_exchange:
                params["code"] = [secrets.token_urlsafe(32)]
                callback_url = urlunsplit(
                    callback_parts._replace(query=urlencode(params, doseq=True))
                )
            callback_response = http.get(callback_url)
            self.assertEqual(callback_response.status_code, 200)
            output, errors = client.communicate(timeout=30)
            if failed_exchange:
                self.assertNotEqual(client.returncode, 0, "native client accepted an invalid code")
            else:
                self.assertEqual(client.returncode, 0, "native client failed OAuth-to-MCP flow")
            diagnostics = output + errors
            for secret in (credentials["password"], original_code, params["code"][0]):
                self.assertFalse(secret in diagnostics, "client diagnostic leaked a runtime secret")
            self.assertFalse("access_token" in diagnostics, "client diagnostic included token data")
            self.assertFalse(
                bool(re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", diagnostics)),
                "client diagnostic leaked JWT-shaped output",
            )
        finally:
            if client.poll() is None:
                client.terminate()
                try:
                    client.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.communicate(timeout=5)
            reader.join(timeout=2)

    async def call_tool(self, resource, tls, token):
        async with httpx.AsyncClient(
            verify=tls, trust_env=False, headers={"Authorization": "Bearer " + token}
        ) as http:
            async with streamable_http_client(resource, http_client=http) as (read, write, _):
                async with ClientSession(
                    read, write, read_timeout_seconds=timedelta(seconds=10)
                ) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual(len(tools.tools), 1)
                    result = await session.call_tool(tools.tools[0].name, {})
                    self.assertFalse(result.isError)
                    self.assertTrue(result.content)


if __name__ == "__main__":
    unittest.main()
