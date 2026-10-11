"""Public-client S256 OAuth flow followed by an official SDK MCP tool call."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import logging
import re
import secrets
import socket
import threading
import time
import webbrowser
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from server import (
    CALLBACK,
    CLIENT_ID,
    ISSUER,
    MAX_TOKEN_BYTES,
    RESOURCE,
    SCOPE,
    bounded_json,
    load_settings,
    local_tls_context,
)

CALLBACK_TIMEOUT = 180
AUTHORIZATION_ENDPOINT = "https://127.0.0.1:8443/oauth/authorize"
TOKEN_ENDPOINT = "https://127.0.0.1:8443/oauth/token"


class CallbackError(ValueError):
    pass


def parse_callback(target: str, expected_state: str) -> str | None:
    """Valid: /callback?code=x&state=s&iss=…; invalid: duplicate state or %ZZ."""
    if len(target) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in target):
        raise CallbackError("Invalid callback")
    if "#" in target or re.search(r"%(?![0-9A-Fa-f]{2})", target):
        raise CallbackError("Invalid encoding")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.path != "/callback" or parsed.fragment:
        raise CallbackError("Invalid callback path")
    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=4,
        )
    except (ValueError, UnicodeError) as exc:
        raise CallbackError("Invalid callback query") from exc
    values = {}
    for name, value in pairs:
        if name in values or name not in {"code", "error", "state", "iss"}:
            raise CallbackError("Unexpected or duplicate callback field")
        if not value or len(value) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise CallbackError("Invalid callback value")
        values[name] = value
    if set(values) not in ({"code", "state", "iss"}, {"error", "state", "iss"}):
        raise CallbackError("Incomplete callback")
    if not hmac.compare_digest(values["state"].encode(), expected_state.encode()):
        raise CallbackError("State mismatch")
    if values["iss"] != ISSUER:
        raise CallbackError("Issuer mismatch")
    if "error" in values:
        if values["error"] != "access_denied":
            raise CallbackError("Unexpected OAuth error")
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", values["code"]):
        raise CallbackError("Invalid authorization code")
    return values["code"]


class CallbackListener:
    """Bind before authorization; invalid requests cannot consume the callback."""

    def __init__(self, state: str):
        self.state = state
        self.completed = False
        self.code: str | None = None
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def handle(self):
                # Bound the entire request, including clients slowly feeding HTTP headers.
                def interrupt():
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

                self.connection.settimeout(2)
                timer = threading.Timer(2, interrupt)
                timer.daemon = True
                timer.start()
                try:
                    super().handle()
                finally:
                    timer.cancel()

            def do_GET(self):
                try:
                    if self.headers.get_all("Host") != ["127.0.0.1:49152"]:
                        raise CallbackError("Invalid callback host")
                    if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length"):
                        raise CallbackError("Unexpected request body")
                    if listener.completed:
                        raise CallbackError("Callback already consumed")
                    code = parse_callback(self.path, listener.state)
                except (ValueError, UnicodeError):
                    self.reply(400, b"Invalid OAuth callback.")
                    return
                listener.code = code
                listener.completed = True
                self.reply(200, b"Authorization response received. Return to the terminal.")

            def reply(self, status: int, body: bytes):
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
                )
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                # Request targets carry the one-use code and must never be logged.
                pass

        class Server(HTTPServer):
            # Allow a fresh flow after our closed connection enters TIME_WAIT.
            # SO_REUSEPORT is never enabled; an active listener still prevents binding.
            allow_reuse_address = True

            def handle_error(self, request, client_address):
                pass

        self.server = Server(("127.0.0.1", 49152), Handler)
        self.server.timeout = 0.25

    def wait_for_code(self, timeout: float = CALLBACK_TIMEOUT) -> str:
        deadline = time.monotonic() + timeout
        while not self.completed and time.monotonic() < deadline:
            self.server.handle_request()
        if not self.completed:
            raise CallbackError("Authorization callback timed out")
        if self.code is None:
            raise CallbackError("Authorization was denied")
        return self.code

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.server.server_close()


def authorization_url(state: str, verifier: str) -> str:
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return (
        AUTHORIZATION_ENDPOINT
        + "?"
        + urlencode(
            {
                "client_id": CLIENT_ID,
                "redirect_uri": CALLBACK,
                "response_type": "code",
                "resource": RESOURCE,
                "scope": SCOPE,
                "state": state,
                "code_challenge": challenge.rstrip(b"=").decode("ascii"),
                "code_challenge_method": "S256",
            }
        )
    )


async def exchange_code(client: httpx.AsyncClient, code: str, verifier: str) -> str:
    response = await bounded_json(
        client,
        "POST",
        TOKEN_ENDPOINT,
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": CALLBACK,
            "resource": RESOURCE,
            "code_verifier": verifier,
        },
    )
    token = response.get("access_token")
    if (
        response.get("token_type") != "Bearer"
        or response.get("scope") != SCOPE
        or type(response.get("expires_in")) is not int
        or not 1 <= response["expires_in"] <= 3600
        or not isinstance(token, str)
        or len(token) > MAX_TOKEN_BYTES
        or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)
    ):
        raise ValueError("Invalid token response")
    return token


async def call_demo(client: httpx.AsyncClient) -> None:
    async with asyncio.timeout(30):
        async with (
            streamable_http_client(RESOURCE, http_client=client) as (read, write, _),
            ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
            if not any(tool.name == "demo_status" for tool in tools.tools):
                raise ValueError("Expected synthetic demo tool")
            result = await session.call_tool("demo_status", {})
            if result.isError:
                raise ValueError("Synthetic tool failed")
            # Only fixed messages are printed; server output could contain unexpected data.
            print(
                "MCP initialized; listed demo_status; synthetic tool call succeeded.",
                flush=True,
            )


async def run(runtime_dir: Path, no_browser: bool) -> None:
    load_settings(runtime_dir)
    tls = local_tls_context(runtime_dir)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with CallbackListener(state) as listener:
        url = authorization_url(state, verifier)
        print(
            "Open this URL, sign in with the synthetic demo account, and approve consent:",
            flush=True,
        )
        print(url, flush=True)
        if not no_browser:
            webbrowser.open(url)
        code = await asyncio.to_thread(listener.wait_for_code)
    async with httpx.AsyncClient(
        verify=tls,
        trust_env=False,
        follow_redirects=False,
        timeout=10,
    ) as client:
        token = await exchange_code(client, code, verifier)
        client.headers["Authorization"] = "Bearer " + token
        await call_demo(client)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument(
        "--no-browser", action="store_true", help="Print the URL without launching a browser"
    )
    args = parser.parse_args()
    # SDK HTTP errors can contain URL details. CLI failures emit only a fixed diagnostic.
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(run(args.runtime_dir, args.no_browser))
    except KeyboardInterrupt:
        parser.exit(130, "Demo cancelled.\n")
    except Exception:  # noqa: BLE001 -- SDK task groups can wrap errors; never print sensitive details.
        parser.exit(
            1,
            "Demo failed: check services, local CA, callback port, and consent; retry with a fresh flow.\n",
        )


if __name__ == "__main__":
    main()
