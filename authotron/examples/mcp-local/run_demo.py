"""Run the local Authotron/MCP backends and loopback-only HTTPS proxies.

With a remote-issuer runtime (prepared with --issuer), only the MCP backend and its
8444 HTTPS proxy are started; the issuer is reached with system TLS trust.
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import ssl
import sys
from pathlib import Path

import aiohttp
from aiohttp import web
from multidict import CIMultiDict
from demo_settings import endpoints, is_remote, load_settings, system_tls_context
from prepare_demo import outside_repository
from yarl import URL

HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def clean_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("AOT_") and not key.lower().endswith("_proxy")
    }


def forwarded_headers(headers) -> CIMultiDict:
    excluded = HOP_HEADERS | {
        part.strip().lower()
        for value in headers.getall("Connection", [])
        for part in value.split(",")
    }
    return CIMultiDict(
        (key, value) for key, value in headers.items() if key.lower() not in excluded
    )


def proxy_app(session: aiohttp.ClientSession, backend_port: int) -> web.Application:
    async def proxy(request: web.Request) -> web.StreamResponse:
        headers = forwarded_headers(request.headers)
        # Do not let caller-controlled forwarding headers affect backend policy.
        for key in list(headers):
            if key.lower() == "forwarded" or key.lower().startswith("x-forwarded-"):
                headers.popall(key, None)
        target = URL(f"http://127.0.0.1:{backend_port}{request.raw_path}", encoded=True)
        try:
            async with session.request(
                request.method,
                target,
                headers=headers,
                data=request.content.iter_chunked(65536),
                allow_redirects=False,
            ) as upstream:
                response = web.StreamResponse(
                    status=upstream.status, headers=forwarded_headers(upstream.headers)
                )
                await response.prepare(request)
                async for chunk in upstream.content.iter_chunked(65536):
                    await response.write(chunk)
                await response.write_eof()
                return response
        except (TimeoutError, aiohttp.ClientError):
            # Never expose exception URLs, request bodies, authorization codes or tokens.
            return web.Response(status=502, text="Local backend unavailable")

    app = web.Application(handler_args={"auto_decompress": False})
    app.router.add_route("*", "/{path:.*}", proxy)
    return app


LOCAL_PORTS = (8000, 8001, 8443, 8444)
REMOTE_PORTS = (8001, 8444)


class UsageError(ValueError):
    """Option combination that does not fit the runtime's mode; the message is safe to print."""


def check_ports(ports=LOCAL_PORTS) -> None:
    """Raises OSError if another socket listens on one of `ports`.

    Connections of an earlier run waiting in TIME_WAIT do not count: on POSIX the probe
    binds with SO_REUSEADDR, as the servers do, which still refuses a listened port.
    """
    sockets = []
    try:
        for port in ports:
            sock = socket.socket()
            sockets.append(sock)
            if os.name == "posix":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
    finally:
        for sock in sockets:
            sock.close()


async def stop_process(process) -> None:
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), 5)
        except TimeoutError:
            process.kill()
            await process.wait()


async def wait_ready(session, settings, contexts, processes, timeout: float) -> None:
    """Ready once issuer metadata names the configured issuer and MCP answers 401."""
    issuer = settings["issuer"]
    issuer_tls, resource_tls = contexts

    async def poll():
        issuer_ok = False
        while True:
            if any(process.returncode is not None for process in processes):
                raise RuntimeError("a local backend exited during startup")
            try:
                if not issuer_ok:
                    async with session.get(
                        endpoints(issuer)["metadata"], ssl=issuer_tls
                    ) as response:
                        issuer_ok = (
                            response.status == 200
                            and (await response.json()).get("issuer") == issuer
                        )
                async with session.get(settings["resource"], ssl=resource_tls) as response:
                    mcp_ok = response.status == 401
                if issuer_ok and mcp_ok:
                    return
            except (TimeoutError, aiohttp.ClientError, ValueError):
                pass
            await asyncio.sleep(0.2)

    await asyncio.wait_for(poll(), timeout)


def commands(runtime: Path, remote: bool, binary: Path | None) -> list[list[str]]:
    server = [sys.executable, str(Path(__file__).with_name("server.py")), "--runtime-dir"]
    server.append(str(runtime))
    return [server] if remote else [[str(binary)], server]


async def run(args) -> None:
    runtime = outside_repository(args.runtime_dir)
    if runtime.stat().st_mode & 0o077:
        raise ValueError("runtime directory must be private (0700)")
    settings = load_settings(runtime)
    remote = is_remote(settings)
    if remote and (args.authotron_bin is not None or args.show_credentials):
        raise UsageError(
            "--authotron-bin and --show-credentials are not used with a remote-issuer runtime"
        )
    if not remote and args.authotron_bin is None:
        raise UsageError("--authotron-bin is required for a local-issuer runtime")
    binary = None if remote else args.authotron_bin.expanduser().resolve(strict=True)
    check_ports(REMOTE_PORTS if remote else LOCAL_PORTS)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(runtime / "tls-cert.pem", runtime / "tls-key.pem")
    verify = ssl.create_default_context(cafile=str(runtime / "tls-ca.pem"))
    contexts = (system_tls_context() if remote else verify, verify)
    env = clean_environment()
    if not remote:
        env["AOT_CONFIG_PATH"] = str(runtime / "authotron.json")
    processes, runners = [], []
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    startup_task = stop_task = None
    try:
        for command in commands(runtime, remote, binary):
            processes.append(
                await asyncio.create_subprocess_exec(
                    *command,
                    env=env,
                    cwd=runtime,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            )
        async with aiohttp.ClientSession(
            trust_env=False,
            auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            skip_auto_headers={"Accept-Encoding", "Content-Type"},
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=2, sock_read=30),
        ) as session:
            proxies = ((8444, 8001),) if remote else ((8443, 8000), (8444, 8001))
            for port, backend in proxies:
                runner = web.AppRunner(
                    proxy_app(session, backend), access_log=None, shutdown_timeout=2
                )
                runners.append(runner)
                await runner.setup()
                await web.TCPSite(runner, "127.0.0.1", port, ssl_context=tls).start()
            startup_task = asyncio.create_task(
                wait_ready(session, settings, contexts, processes, args.startup_timeout)
            )
            stop_task = asyncio.create_task(stopped.wait())
            done, _ = await asyncio.wait(
                (startup_task, stop_task), return_when=asyncio.FIRST_COMPLETED
            )
            if stop_task in done:
                return
            await startup_task
            print(
                f"{'Remote-issuer' if remote else 'Local'} demo ready: "
                f"issuer {settings['issuer']}; MCP {settings['resource']}",
                flush=True,
            )
            if remote:
                print(
                    "Sign in at the remote issuer in your browser; Ctrl-C stops the demo.",
                    flush=True,
                )
            elif args.show_credentials:
                credentials = json.loads((runtime / "credentials.json").read_text())
                print(
                    f"Demo username: {credentials['username']}\nDemo password: {credentials['password']}",
                    flush=True,
                )
            else:
                print(
                    "Browser login credentials are in private credentials.json; Ctrl-C stops the demo.",
                    flush=True,
                )
            while not stopped.is_set():
                if any(process.returncode is not None for process in processes):
                    raise RuntimeError("a local backend exited")
                try:
                    await asyncio.wait_for(stopped.wait(), 0.25)
                except TimeoutError:
                    pass
    finally:
        for task in (startup_task, stop_task):
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        for runner in reversed(runners):
            await runner.cleanup()
        for process in reversed(processes):
            await stop_process(process)
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument(
        "--authotron-bin",
        type=Path,
        help="Authotron executable; required for local-issuer runtimes, rejected for remote",
    )
    parser.add_argument("--startup-timeout", type=float, default=30)
    parser.add_argument(
        "--show-credentials",
        action="store_true",
        help="explicitly display synthetic credentials once startup succeeds",
    )
    args = parser.parse_args()
    if args.startup_timeout <= 0:
        parser.error("--startup-timeout must be positive")
    logging.getLogger("aiohttp.server").disabled = True
    try:
        asyncio.run(run(args))
    except UsageError as exc:
        parser.exit(2, f"{exc}\n")
    except (TimeoutError, OSError, ValueError, RuntimeError):
        parser.exit(
            1,
            "Demo failed: check runtime files, dependencies, binary, and loopback ports; children stopped.\n",
        )


if __name__ == "__main__":
    main()
