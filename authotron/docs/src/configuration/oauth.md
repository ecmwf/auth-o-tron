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

`oauth.signing` is optional and defaults to absent. Configuration validation checks
**references only** and performs no file I/O. The key manager loads only on an
explicit `oauth::keys::KeyManager::load` call; startup does not invoke it.
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

The Unix loader accepts PKCS8/PKCS1 private PEM and SPKI/PKCS1 public PEM, enforcing
2048–4096-bit RSA, private-key consistency, and matching public/private modulus and
exponent when both files are supplied. It derives missing public keys and preserves
configured key order, including inactive public-only rotation keys. Loads are
all-or-nothing. Nonblocking opens follow mounted Secret projected symlinks and
check the opened target is regular; reads are bounded to 16 KiB plus one overflow
byte before PEM parsing. Loader-owned temporary PEM read buffers are zeroized.
Dependency parsing is not claimed to wipe every intermediate allocation. Errors contain fixed
classes/messages without paths, key contents, or underlying crypto errors.
Private manager state has no Debug/Serialize or public signing API. The internal
signing capability is limited to sibling OAuth modules, with a load-time RS256
sign/verify consistency probe (not an access token). Public JWKS serialization
contains only `kty`, `alg`, `use`, `kid`, `n`, and `e`; integers are unpadded
base64url. This is an in-process capability, not an HTTP JWKS endpoint.
Missing signing config does not replace the current Unsupported startup guard;
a future operational authorization server must require usable signing keys.
No automatic reload or rotation is implemented. Future deployments must coordinate
active-key changes across replicas and retain old public keys through the longest
issued access-token lifetime plus clock skew before retirement.

## Typed access-token capability

`oauth::tokens::TokenIssuer::new(&config, &key_manager)` validates config, requires
an issuer (≤2048 bytes), and matches supplied signing references to the manager's
loaded snapshot. `issue_access_token` accepts a client, exact resource, requested
scopes and freshly verified user. Callers must enforce trusted successful augmentation,
consent and a server-owned grant/code proof; this helper performs none of those checks.
It works in-process with OAuth disabled; no HTTP issuance exists.
Issuance re-runs policy, bounds identity fields to 128 control-free UTF-8 bytes and
roles to 64 entries of 128 bytes each. Header: RS256, `typ: at+jwt`, active `kid`.
Claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `client_id`, `scope`, `roles`.
Issuer spelling and audience resource are exact. Subject is `urn:authotron:subject:`
plus base64url SHA-256 of length-prefixed issuer/realm/username; stable, not anonymous.
Roles are only the unique required-role union for granted scopes; usernames, realms,
unrelated roles, attributes, emails, user scopes and credentials are omitted.
Scope order is preserved. Server-clock time and checked configured TTL determine
expiry (through year 9999); `jti` is UUIDv4. Wire limit: 32 KiB. Non-Debug responses
serialize only `access_token`, `token_type: Bearer`, `expires_in`, `scope`; no refresh.
Errors are fixed configuration/identity/policy/time/signing/size classes. Consumers
must enforce `at+jwt`, RS256, expected issuer/audience; a complete MCP validator is future work.

## Authorization-request input gate

`oauth::authorization::validate_authorization_request(&config, raw_query_bytes)`
is a pure gate usable while OAuth is disabled, requiring valid config and an issuer.
Queries are bounded to 8 KiB/32 parameters, with strict percent escapes/UTF-8 and
`+` decoded as space. Unknown parameters are ignored and never retained as identity,
roles, scopes or redirects. Known duplicates fail, including multiple `resource` values.
Required: explicit `client_id`, exact `redirect_uri` (even for one callback),
`response_type=code`, one exact registered/bound `resource`, `scope`, challenge and S256 method.
No URI normalization/aliases. Scope: 1–32 unique RFC 6749 tokens separated by single
ASCII spaces, client/resource-bound; role eligibility requires fresh identity later.
Optional opaque `state` retains decoded text, ≤1024 UTF-8 bytes without controls.
It remains untrusted client text: do not log it or interpret it as identity or
authorization metadata.
Challenge: canonical unpadded base64url SHA-256 (43 characters/32 bytes). Immutable
`challenge().verify` requires 43–128 unreserved ASCII verifier bytes and compares
digests in constant time. Successful requests have immutable getters, not login,
consent or grant proof. Fixed-error failures **stay local; never redirect to raw
submitted callbacks**. Error-redirect routing, extensions, authorization HTTP routes,
transaction storage and code issuance are future work.

## Authorization-transaction record codec

`oauth::records::AuthorizationTransaction::new` owns a validated request, a
32-byte browser-binding hash (not a raw cookie), and trusted absolute expiry in
Unix milliseconds. Version-1 JSON contains only client ID, callback, resource,
scopes, opaque state, S256 challenge digest, binding digest, expiry and version.
The record/DTO have no Debug or public Deserialize; state remains untrusted text,
never identity or a logging field. No identity, consent flag, grant or code is stored.
`encode`/`decode` enforce a 16 KiB wire cap; decode checks it before JSON parsing.
The canonical reconstructed known query must also fit the 8 KiB request gate,
including at construction, so persisted records can round-trip without loosening validation.
Decode rejects unknown fields/versions, malformed timestamps, expiry at or before
trusted `server_now_ms`, and requests invalid under the current registry/bindings.
Expiry must be positive and representable through year 9999. Browser digest
matching is constant-time. Callers supply trusted server/backend time and enforce
TTL computation; timestamps are never request-selected. This codec is not a MAC
or cache authenticator and assumes trusted storage. Role eligibility, login and
consent still require later fresh identity checks. No backend, nonce generation,
atomic consumption, HTTP route or startup hook is implemented; startup remains Unsupported.

Authorization codes, HTTP token issuance, discovery/JWKS, browser CORS,
and MCP integration remain future capabilities. No HTTP tokens are issued and
`enabled: true` still fails startup as Unsupported. The legacy HMAC `jwt.secret`
must never be published through
future JWKS or reused as an OAuth asymmetric signing key.
