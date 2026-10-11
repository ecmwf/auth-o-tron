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
  authorization_transaction_ttl_seconds: 300
  max_authorization_transactions: 1024
  max_authentication_age_seconds: 300
  authentication_clock_skew_seconds: 30
  clients: []
  resources: []
```

| Setting | Default | Validation |
| --- | --- | --- |
| `enabled` | `false` | Enablement is currently unsupported |
| `issuer` | absent | Required when enabled; absolute HTTPS origin only |
| `authorization_code_ttl_seconds` | `60` | 30–300 seconds inclusive |
| `access_token_ttl_seconds` | `300` | 60–3600 seconds inclusive |
| `authorization_transaction_ttl_seconds` | `300` | 30–900 seconds inclusive |
| `max_authorization_transactions` | `1024` | 1–100000 records inclusive |
| `max_authentication_age_seconds` | `300` | 1–3600 seconds inclusive |
| `authentication_clock_skew_seconds` | `30` | 0–60 seconds inclusive |

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

## Strict augmentation precursor

`Auth::check_augmenters_strict(user, &metrics)` is available in-process and returns
`Result<User, AugmentationError>`. It applies the existing exact realm filter,
runs ordinary matching augmenters in parallel, waits for all of them, then runs
`plain_advanced` augmenters sequentially in configuration order. Any ordinary
failure prevents the advanced phase; an advanced failure stops that sequence.
Failures discard the identity result, including mutations made before an error.
Fixed errors are `Failed` and `Unavailable` (identity ownership could not be recovered).
Strict pipeline failure logs use a fixed diagnostic; attempt/duration metrics
remain once per normally completed augmenter. Panics are not caught by this helper.
Built-in implementation logging is documented in [Augmenters](augmenters.md);
third-party implementations remain responsible for their own log contents.
Legacy best-effort augmentation retains its
existing partial-mutation, logging and continuation behavior. Callers still own
fresh credential verification, deadlines and bounded identity projection. This
helper is not authentication, consent or grant proof. The OAuth verification
capability below uses it, while browser routes remain best-effort and OAuth startup remains Unsupported.

## Strict OAuth credential-verification capability

`oauth::authentication::verify_identity(credentials, &browser_state, &auth, &metrics)`
returns an opaque `VerifiedOAuthIdentity` or fixed Rejected/Limited/Timeout/Unavailable
errors. Fresh selected Basic/API-key verification, strict augmentation and OAuth
projection run through the existing single admission/deadline pipeline: local-first
permits, shared quotas/optional leases and the in-flight RAII gauge are reused.
One strict-helper deadline starts at entry and covers lease release and proof
construction too. Late completion returns Timeout, not a proof or a cleanup error.
Tokio deadlines are cooperative, not hard real-time. Cancellation releases local
permits/gauge immediately; bounded detached cleanup or expiry may release shared
leases later, so this is not remote-provider fencing. Legacy browser cleanup is unchanged.
API-key verification is uncached; Basic credential encoding preserves Unicode passwords.
Only server code selects strict mode; no submitted field controls provider or mode.
OAuth names/realm are nonblank, control-free and ≤128 UTF-8 bytes; roles are at most
64 entries of the same text bound. Attributes and existing user scopes are discarded.
The proof has no public constructor, Deserialize, Serialize, Debug or Clone; `as_user`
is read-only. `verified_at_ms` records checked trusted server time after verification
completes, through year 9999; it is not a caller timestamp or a max-age decision.
Callers must check Origin/CSRF and the bound OAuth transaction before invoking this.
The proof is credential verification only: consent, resource policy, code/grant proof
and future age checks remain separate. No session/cookie or code is created. Existing
browser verification retains best-effort augmentation, 256-byte names and display
attributes. No HTTP integration or startup enablement is implemented.

## Authenticated authorization context

`oauth::context::AuthenticatedAuthorization::new` consumes an owned transaction and
opaque `VerifiedOAuthIdentity`, with the browser-binding hash, current OAuth config,
and trusted server/backend time in Unix milliseconds. It accepts no raw User and
has no Debug, Clone, public serialization or field mutation. The transaction codec revalidates
the unexpired transaction/current request; binding and all requested-scope role/realm
policy must pass before construction. It owns the existing bounded proof without
copying identity fields or retaining attributes/scopes from credentials.
Read-only getters expose `transaction`, `as_user`, `verified_at_ms`,
`authorized_scopes` (eligible, not consented), and `expires_at_ms`.
Identity age expires at exactly `verified_at_ms + max_authentication_age_seconds`;
clock skew permits a future verification timestamp only within the configured bound.
Skew adds no grace to that age deadline; accepted future timestamps can leave up to
max-age plus skew relative to backend time. Context expiry is the minimum of that
deadline and transaction expiry. Clocks must be synchronized across replicas.
Fixed errors distinguish Configuration, InvalidTime, InvalidTransaction, Binding,
StaleIdentity and AccessDenied, without identity data. Callers still enforce
Origin/CSRF, and must recheck current policy/freshness at future issuance. This is
in-process policy eligibility only: development-memory persistence is described
below, but no shared/durable authenticated persistence, consent flag, grant, code,
or HTTP/startup integration is implemented.

### OAuth-internal authenticated-context codec

`AuthenticatedAuthorization::encode/decode` are restricted to sibling OAuth modules,
not external callers or request JSON. Version-1 private JSON accepts only username,
realm, roles, verification time, and a canonical unpadded base64url transaction blob.
There are no attributes, user scopes, consent flags, stored authorized-scope lists,
or derived expiry claims. The wire limit is 64 KiB, checked before JSON parsing;
decoded transaction bytes are capped at 16 KiB before the transaction codec runs.
Identity bounds use the fresh-verification projection validator before allocating
the restored User. Decode recomputes binding, current request/realm/role eligibility,
age/skew and minimum expiry through the context constructor.
This requires trusted authenticated backend storage: it is not a MAC or proof of
fresh provider execution. OAuth-internal snapshot restoration does not rerun
providers/augmenters, so verification-time roles remain a revocation window until
authentication age expires; current policy is still rechecked. Deserialization
allocations are wire-bounded, not an end-to-end hard memory guarantee. Fixed codec
errors add TooLarge, InvalidRecord and UnsupportedVersion. The development-memory
store below uses this private codec; shared authenticated-context storage is future work.

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
shared transaction storage and code issuance are future work. The explicit
development-memory API is described below; it is not wired into an HTTP flow.

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
consent still require later fresh identity checks. The codec itself supplies no
backend, nonce generation or atomic consumption; the memory API below adds those
capabilities. No HTTP route or startup hook is implemented; startup remains Unsupported.

## Explicit development-memory transaction store

`oauth::store::MemoryTransactionStore::new(Arc<OAuthConfig>)` requires valid config
and an issuer. It is an explicit development-only choice, never a default or
fallback, and is distinct from the legacy token store and browser-session state.
Async `create(validated_request, browser_hash)` returns a secret `TransactionId`
and absolute expiry; `lookup` and `consume` require that ID and binding hash.
IDs contain 32 cryptographically random bytes, use canonical unpadded base64url,
and expose wire text only through `as_secret_str`; they and handles have no Debug
or serialization. Only SHA-256 ID hashes index stored versioned codec bytes.
Expiry uses trusted server time captured under lock plus the transaction TTL, with checked arithmetic;
it never extends on reads. Valid operations prune expired entries and enforce the
configured count cap. Capacity errors are fixed `Limited`; missing/expired IDs and
binding mismatches are `Missing`; config failures are `Configuration`, and codec,
clock, entropy or poisoned-lock failures are fixed `Unavailable` errors.
Consume validates codec/current config and binding before removing under one lock:
wrong binding does not burn an unexpired transaction, and concurrent consumers have
one winner. Invalid records provide no proof and remain until expiry cleanup.
No guard spans an await. Idle expired data is count-bounded; no cleanup task runs.
These async APIs perform synchronous O(n) pruning and codec validation under a
mutex. The cap bounds logical records, not retained map allocation. Revalidation
uses the store's retained immutable configuration, not automatic hot reload.
Wall-clock rollback can lengthen elapsed lifetime for unpruned records; removed
records cannot reappear.
Memory is per instance, cannot support cross-replica transactions, and has no
restart persistence. Tune capacity to process budgets (pending records ≤16 KiB,
authenticated records ≤64 KiB; 100000 authenticated records allow 6.5536 GB
(approximately 6.10 GiB) of payload,
plus overhead). Pending transactions prove input validation only, never login,
consent or grants. No backend is wired at startup; OAuth remains Unsupported.

### Development-memory authenticated promotion

Async `promote_authenticated(id, browser_hash, context)` replaces a Pending entry
exactly once with an Authenticated entry under the same hashed key/capacity slot.
It samples trusted time under lock, decodes the pending record, checks binding and
exact canonical source transaction bytes/expiry, then revalidates the context with
the store's config snapshot before replacement. Expiry shrinks to context freshness
or the original transaction deadline, never extends. Failures leave unexpired input
unchanged; a second promotion returns Missing and cannot overwrite the earlier identity.
`lookup`/`consume` are Pending-only. New `lookup_authenticated`/`consume_authenticated`
return typed contexts via the private codec, without refreshing expiry; wrong kind,
missing/expired IDs or wrong binding return Missing. Codec/metadata failures return
Unavailable without consuming corrupt state. Both kinds share the configured count
cap, and only successful typed consume removes an unexpired entry. No operation
adds consent, grants or codes. Source matching binds request/expiry facts, not a new
transaction-ID field inside the record. Valkey authenticated promotion and HTTP
integration remain separate future slices.

### Shared Valkey connector foundation

The crate-internal connector now reuses the existing validated
`BrowserBackendConfig::Valkey` credentials, TLS and timeout settings independently
of browser-session policy. Browser Valkey operations use that same bounded
connection-manager implementation. Defaults remain 2 seconds to connect and
1 second per operation; only explicit connection calls perform network I/O.
It supports one primary endpoint, with verified `rediss` TLS and no memory fallback.
Connector errors expose only Configuration/Unavailable classes. Connection-manager
reconnect is distinct from command replay: commands are issued once, and timeout
or lost-response mutation outcomes may be ambiguous; callers must not blindly retry.
No OAuth backend or connection is initialized at startup.

### Shared Valkey authorization transactions

`oauth::valkey_transactions::ValkeyTransactionStore::new(config, &backend)` is an
explicit connection call requiring Valkey settings. Async `create`, `lookup`, and
`consume` use the memory store's ID/handle/record contracts, without local cache or
fallback. Namespace: `<key_prefix>:oauth:authorization-transactions:v1:`, with only
hashed-ID record keys and an expiry sorted-set index, separate from UI state.
Replicas sharing a namespace must use consistent policy snapshots, TTL and capacity.
Creation obtains server `TIME`, encodes/revalidates the record, then Lua checks the
current server time and expiry window, prunes expired index members, checks shared
capacity, and uses `SET NX PXAT` plus `ZADD`. No client/replica clock determines expiry.
Lookup checks types, metadata and `STRLEN` before a bounded `GET`, returning exact
bytes and server time for Rust codec/config/binding checks. Reads never refresh TTL.
Consume validates that read in Rust, then Lua compares exact bytes and expiry at
current server time before `DEL`/`ZREM`; changed data or another winner fail closed.
Wrong binding or invalid current policy/record cannot burn an unexpired transaction.
Lua checks key types and mutation ACL permissions before writes. Atomic execution
is not rollback: unexpected write failures/OOM or lost responses can leave ambiguous
outcomes; operations are not automatically replayed. Invalid data yields fixed
Unavailable errors, not raw backend diagnostics. The index is bounded to 100000
members and uses no `KEYS` scans; record reads are capped at 16 KiB. Expired members
are pruned in one atomic script: a large expired batch can occupy the shared
server and exceed a caller's operation deadline, so tune capacity and timeouts.
This remains
authorization-input storage only, not login/consent proof or atomic code issuance.

Authorization codes, HTTP token issuance, discovery/JWKS, browser CORS,
and MCP integration remain future capabilities. No HTTP tokens are issued and
`enabled: true` still fails startup as Unsupported. The legacy HMAC `jwt.secret`
must never be published through
future JWKS or reused as an OAuth asymmetric signing key.
