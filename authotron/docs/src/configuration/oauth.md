# OAuth configuration foundation

OAuth/MCP authorization-server support is **not implemented yet**. The v2
`oauth` section reserves and validates configuration for future work. Setting
`enabled: true` fails startup with an Unsupported error, before browser, network,
or store initialization. It does not activate any endpoints or metadata.

Omitting this section (including migrated v1 configurations) keeps OAuth disabled.

```yaml
oauth:
  enabled: false
  issuer: "https://login.example.org"
  authorization_code_ttl_seconds: 60
  access_token_ttl_seconds: 300
  clients: []
```

| Setting | Default | Validation |
| --- | --- | --- |
| `enabled` | `false` | Enablement is currently unsupported |
| `issuer` | absent | Required when enabled; absolute HTTPS origin only |
| `authorization_code_ttl_seconds` | `60` | 30–300 seconds inclusive |
| `access_token_ttl_seconds` | `300` | 60–3600 seconds inclusive |

Unknown OAuth fields are rejected. Supplied issuers and TTLs are validated even
when disabled. Issuers must have no userinfo, query, fragment, whitespace, or
control characters. An optional trailing `/` is allowed; issuer URI paths such as
`https://login.example.org/oauth` are unsupported in this origin-only baseline.
Future authorization endpoints must use a consistent, available public HTTPS origin.

## Local public-client preregistration

`oauth.clients` defaults to an empty list, including for migrated v1 settings.
Up to 64 public clients may be preregistered locally; this is not dynamic client
registration. All entries are validated even when OAuth is disabled.

```yaml
clients:
  - client_id: mcp-desktop
    display_name: MCP Desktop
    application_type: native
    redirect_uris: ["http://127.0.0.1:49152/callback?installation=desktop"]
```

Each entry requires `client_id` (1–128 ASCII bytes: letters, digits, `.`, `_`, `-`),
a nonblank, control-free `display_name` (at most 128 UTF-8 bytes), and 1–8
`redirect_uris` (at most 2048 bytes each). IDs must be unique, and URL client IDs
(CIMD) are unsupported. Unknown fields, including secrets and authentication
methods, are rejected. These are public clients with fixed token endpoint
authentication semantics of `none`; confidential clients/BFFs are deferred.

`application_type` uses OpenID Connect terminology: `web` (default) or `native`.
Both allow absolute HTTPS callbacks with a host. Only `native` additionally allows
HTTP to literal `127.0.0.1` or `[::1]` with an explicit nonzero port. HTTP callbacks
using DNS localhost or other IPs, and callbacks using custom schemes, are
unsupported. Callbacks forbid userinfo,
fragments, backslashes, raw whitespace/control characters, and invalid ports.
Static queries are allowed except for response names `code`, `state`, `iss`,
`error`, `error_description`, and `error_uri` (including percent-encoded names).
Callback strings are retained verbatim for future exact matching of the complete
URI, including port, path and query; there is no variable-port exemption.

Authorization codes, PKCE S256, RS256 access tokens, discovery/JWKS, browser CORS,
and MCP integration remain future capabilities. No tokens are issued and
`enabled: true` still fails startup as Unsupported. No OAuth signing keys
are configured here. The legacy HMAC `jwt.secret` must never be published through
future JWKS or reused as an OAuth asymmetric signing key.
