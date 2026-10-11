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
  resources: []
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

## Explicit resource/scope policy

Both `oauth.resources` and each client's `resources` default to `[]`; a client
without an explicit binding receives no grants. Example under `oauth`:

```yaml
resources:
  - resource: https://mcp.example.org/mcp
    allowed_realms: [ecmwf, local]
    scopes:
      - name: notifications:read
        required_roles: [reader]
# Add this binding to a preregistered client's entry:
# resources:
#   - resource: https://mcp.example.org/mcp
#     scopes: [notifications:read]
```

Resources must be canonical absolute HTTPS URLs (lowercase scheme/host; no
userinfo, query, fragment, whitespace, backslash, or explicit default port).
Strings are retained exactly; paths/trailing slashes are distinct, with no prefix matching.
Root resources may be registered with or without a trailing slash, as permitted
by RFC 8707; clients must still request the exact form that was registered.
Limits: 64 resources/bindings, 2048 URI bytes, 1–16 unique realms (1–128 ASCII bytes,
letters/digits/`._-`), 1–32 unique scopes (1–64 RFC 6749 scope-token bytes), and
0–32 unique required roles per scope (nonblank, control-free, ≤128 UTF-8 bytes).
Unknown fields, duplicates and dangling references fail validation even when disabled.
`authorize_scopes` assumes fresh verification and trusted successful augmentation;
it does not authenticate or repair upstream fail-open augmentation. Callers must
bound identity role data before evaluation. A bounded
nonblank username, allowed realm, exact client binding and **all** required roles
are required. Empty roles still require that authenticated realm. Attributes and
existing user scopes never grant permissions. Requests require 1–32 unique valid
scopes; failures reject the whole request, and success retains request order.
Fixed errors distinguish invalid configuration/client/resource/scope and access denial.

## RS256 signing references

`oauth.signing` is optional and defaults to absent. This slice validates **file
references only**; it does not read files, load keys, sign tokens, or publish JWKS.
Supplying references is allowed while OAuth is disabled. Example under `oauth`:

```yaml
signing:
  active_kid: signing-2026-10
  keys:
    - kid: signing-2026-10
      private_key_file: /run/secrets/oauth/active.pem
    - kid: signing-2026-09
      public_key_file: /run/secrets/oauth/previous-public.pem
```

There must be 1–8 keys with unique IDs of 1–64 ASCII bytes (letters, digits,
`.`, `_`, `-`). `active_kid` must select a key with a private file reference.
Inactive keys may reference a public file, a private file, or both; a private-only
key is intended to provide its derived public key. References must be absolute
UTF-8 paths of at most 4096 bytes without control characters and with a filename
component; `/` is rejected. This is not a regular-file or existence check. Path
constraints are runtime-only; JSON Schema string lengths cannot express UTF-8
byte limits. Paths are trusted
admin configuration, never request-selected. Inline key material, algorithm
selection, and unknown fields are rejected.

File existence, bounded PEM reads, 2048–4096-bit RSA checks, key-pair matching, RS256
encoding, and public-only JWK projection require the next key-loader slice.
That loader must support mounted Secret projected-symlink paths while checking
that the opened target is a regular file.
Missing signing config does not replace the current Unsupported startup guard;
a future operational authorization server must require usable signing keys.
No automatic reload or rotation is implemented. Future deployments must coordinate
active-key changes across replicas and retain old public keys through the longest
issued access-token lifetime plus clock skew before retirement.

Authorization codes, PKCE S256, RS256 access tokens, discovery/JWKS, browser CORS,
and MCP integration remain future capabilities. No tokens are issued and
`enabled: true` still fails startup as Unsupported. Only OAuth signing file references
are configured here. The legacy HMAC `jwt.secret` must never be published through
future JWKS or reused as an OAuth asymmetric signing key.
