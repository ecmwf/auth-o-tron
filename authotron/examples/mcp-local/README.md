# Local Authotron + MCP demo

This disposable demo uses Authotron's browser login and OAuth authorization-code
flow with PKCE to authorize a local MCP client. It creates a synthetic `alice`
account with role `reader`, a random password, an RSA OAuth signing key, and a
seven-day local TLS CA and certificate for the IP address `127.0.0.1`.

## Install and build

From the repository root, build Authotron and install the example dependencies into an isolated
virtual environment outside the repository (Python 3.11+):

```sh
cargo build -p authotron
python3 -m venv /tmp/authotron-mcp-venv
/tmp/authotron-mcp-venv/bin/python -m pip install './authotron/examples/mcp-local[test]'
```

The example's dependencies include `cryptography` and `aiohttp`, in addition to
the MCP server/client dependencies. The runner uses `aiohttp` HTTPS reverse
proxies with a stdlib TLS context; the server CLI starts its loopback ASGI server.
The `test` extra installs `pytest` and `jsonschema` for the test suite.
Installation supplies dependencies only; run the scripts from this checkout as shown below.

## Prepare a new runtime

Choose a **new directory with an existing parent, outside the repository**.
Preparation refuses existing directories, files, and symlinks; it never replaces
an existing runtime. Do not use `mktemp -d` for the final runtime directory because
that creates an existing directory. For example, from the repository root:

```sh
export MCP_RUNTIME="/tmp/authotron-mcp-demo-$(date +%s)-$$"
/tmp/authotron-mcp-venv/bin/python authotron/examples/mcp-local/prepare_demo.py \
  --runtime-dir "$MCP_RUNTIME"
```

The runtime has mode `0700`; every generated file has mode `0600`:

| File | Purpose |
| --- | --- |
| `authotron.json` | Complete version `2.0.0` configuration; contains synthetic secrets |
| `credentials.json` | Synthetic browser login username and password |
| `oauth-private.pem` | RSA OAuth signing key |
| `tls-key.pem` | TLS leaf private key |
| `tls-cert.pem` | TLS leaf certificate for `127.0.0.1` |
| `tls-ca.pem` | Public local CA certificate; used explicitly by the client |
| `settings.json` | Public endpoint settings; contains no secrets |

The CA signing key is discarded. No CA is installed into system or browser trust.
Keeping the runtime outside the checkout also keeps these generated secrets out
of source archives.

## Start the demo

From the repository root, start the runner in one terminal:

```sh
/tmp/authotron-mcp-venv/bin/python authotron/examples/mcp-local/run_demo.py \
  --runtime-dir "$MCP_RUNTIME" \
  --authotron-bin "$PWD/target/debug/authotron" \
  --show-credentials
```

`--authotron-bin` is required and accepts an external executable path. The runner
passes `AOT_CONFIG_PATH` pointing to the generated `authotron.json` and removes
inherited `AOT_*` overrides and proxy environment variables. It launches:

| Listener | Purpose |
| --- | --- |
| `http://127.0.0.1:8000` | Authotron backend |
| `http://127.0.0.1:8001` | MCP server backend (`server.py --runtime-dir ...`) |
| `https://127.0.0.1:8443` | HTTPS proxy to Authotron |
| `https://127.0.0.1:8444` | HTTPS proxy to MCP |

All listeners bind only to loopback. Leave these four ports free before startup.
The client additionally needs callback port `49152` free. The runner checks OAuth
metadata and MCP HTTP readiness, with a default 30-second startup deadline;
`--startup-timeout 60` changes that deadline. Ctrl-C or SIGTERM stops the proxies
and both children. A startup failure or child exit also triggers cleanup.
Child output and proxy access logs are suppressed so authorization codes, cookies,
and tokens are not logged. Credentials are displayed only when the explicit
`--show-credentials` flag is supplied after successful startup; otherwise retrieve
them from the private `credentials.json` file.

In another terminal, from the repository root (set `MCP_RUNTIME` to the same path):

```sh
/tmp/authotron-mcp-venv/bin/python authotron/examples/mcp-local/client.py \
  --runtime-dir "$MCP_RUNTIME"
```

The client loads `settings.json` and verifies demo HTTPS using `tls-ca.pem`.
When its authorization URL opens in your browser, the browser will warn about
the untrusted local certificate. If you choose to proceed, accept a local
certificate exception only for `https://127.0.0.1:8443`, then sign in using the
synthetic credentials and approve `mcp:read`. Browser policies may disallow a
local exception. The setup never changes browser trust or disables client TLS
verification. Use the IP address exactly; the certificate does not cover
`localhost`. The callback is plain HTTP on loopback, as allowed for a native
OAuth client.

## Shared settings contract

`prepare_demo.py`, `server.py`, and `client.py` share exactly these six keys:

```json
{
  "issuer": "https://127.0.0.1:8443/",
  "resource": "https://127.0.0.1:8444/mcp",
  "callback": "http://127.0.0.1:49152/callback",
  "client_id": "mcp-local",
  "scope": "mcp:read",
  "jwks_uri": "https://127.0.0.1:8443/oauth/jwks"
}
```

The issuer's trailing slash is significant. The browser public origin is exactly
`https://127.0.0.1:8443` without a trailing slash. Proxies preserve `Origin`,
`Location`, multiple `Set-Cookie` headers, request bodies, and streamed response
bodies, and do not follow OAuth redirects. They strip hop-by-hop and untrusted
forwarding headers. This demo uses stateless MCP HTTP responses; WebSockets are
not supported. Authotron uses an in-memory browser session backend and no store
or metrics listener. Restarting it invalidates active browser transactions.

## Security and limitations

This demo uses a preregistered, fixed public native client (`mcp-local`) and a
synthetic read-only scope (`mcp:read`). Access tokens last five minutes; there are
no refresh tokens, SSO brokering, Dynamic Client Registration (DCR), or Client ID
Metadata Documents (CIMD). The plaintext loopback backends and disposable local
TLS setup are demo-only and are not a production deployment configuration.

## Test and remove

Setup tests generate their own temporary runtimes; they never use an existing
runtime or a user-local Authotron configuration. Run the normal tests from the
repository root without setting `AUTHOTRON_DEMO_BIN`:

```sh
/tmp/authotron-mcp-venv/bin/python -B -m pytest authotron/examples/mcp-local -q
```

Tests cover directory refusal, modes, versioned JSON schema and configuration
fields, random credentials, source archive exclusion, certificate verification
and hostname rejection, environment sanitization, proxy preservation of
browser/OAuth HTTP data, and access-token validation. Pytest runs both the
pytest-based authorization tests and the unittest-compatible setup tests.

Opt in to all real-process tests by supplying the built Authotron binary. Stop
other local demos and leave ports `8000`, `8001`, `8443`, `8444`, and `49152` free:

```sh
AUTHOTRON_DEMO_BIN=/path/to/authotron \
  /tmp/authotron-mcp-venv/bin/python -B -m pytest authotron/examples/mcp-local -q
```

The real-process suite checks startup, timeout and SIGTERM cleanup, and default
credential-output suppression. The end-to-end tests obtain an authorization code
using PKCE, validate authorization-server and protected-resource metadata, invoke
the official MCP SDK tool, and exercise the actual native client callback. They
also check claim and scope rejection and authorization-code replay rejection.
`test_e2e.py` additionally verifies secret-free client diagnostics after a failed
code exchange and uses bounded MCP deadlines and process-group cleanup.

After stopping the runner, remove the disposable runtime and isolated environment:

```sh
rm -r -- "$MCP_RUNTIME" /tmp/authotron-mcp-venv
```
