# OAuth authorization server

Auth-O-Tron implements an **opt-in OAuth 2.0 public-client authorization-code flow
with S256 PKCE**. Preregistered MCP/native clients can authenticate through the
branded Basic or ECMWF API-key forms, explicitly approve resource scopes, and exchange
a one-use code for a signed access token. Memory and shared Valkey backends are supported.

OAuth is disabled by default. Disabled OAuth registers none of the routes below and
does not load OAuth keys or connect an OAuth backend. Existing CLI authentication,
legacy HMAC tokens, browser sessions and `/login/account` remain separate.

## Readiness and configuration

Enabled OAuth requires:

- Enabled UI with at least one configured direct Basic/API-key provider.
- Valid browser-session settings and an explicitly selected Memory or Valkey backend.
- A root HTTPS issuer whose origin matches `ui.browser_session.public_origin`.
- Nonempty preregistered client/resource policy and usable RS256 signing keys.
- Transaction capacity of at least one slot per registered client.

Configuration checks precede OAuth file/network initialization. Startup fails closed
on missing settings, unusable keys or backend connection failure, without fallback.
Serve the application behind HTTPS at the configured public origin: the application
listener itself does not terminate TLS. Request Host/forwarded headers do not select
issuer, callbacks, providers or cookie authority. The literal issuer spelling,
including an optional root trailing slash, is preserved in metadata, responses and JWTs.

Merge this complete OAuth/direct-login fragment into your existing v2 server configuration:

```yaml
providers:
  - type: ecmwf-api
    name: ECMWF API Provider
    realm: ecmwf
    uri: https://api.ecmwf.int/v1
    browser:
      id: ecmwf-api-key
      label: ECMWF API key
augmenters:
  - type: plain
    name: MCP access
    realm: ecmwf
    roles:
      reader: [allowed-account-uid]
ui:
  enabled: true
  branding:
    application_name: MCP sign-in
  browser_session:
    public_origin: https://auth.example.org
    backend:
      type: memory # explicit development-only, single-instance storage
oauth:
  enabled: true
  issuer: https://auth.example.org/
  signing:
    active_kid: signing-2026
    keys:
      - kid: signing-2026
        private_key_file: /run/secrets/oauth/active.pem
  clients:
    - client_id: mcp-desktop
      display_name: MCP Desktop
      application_type: native
      redirect_uris: ["http://127.0.0.1:49152/callback"]
      resources:
        - resource: https://mcp.example.org/mcp
          scopes: [mcp:read]
  resources:
    - resource: https://mcp.example.org/mcp
      allowed_realms: [ecmwf]
      scopes:
        - name: mcp:read
          required_roles: [reader]
```

OAuth login uses the same browser methods as `/login`: every `plain` or
`ecmwf-api` provider with a `browser: {id: ..., label: ...}` block and every
[`ui.oidc` method](oidc.md), and at least one is required when OAuth is enabled.
An OIDC sign-in started during an authorization request is bound to that request
and continues to consent. Providers without `browser` stay API-only. See
[Choosing browser methods](ui.md#choosing-browser-methods). Several methods may
coexist; submitted fields cannot select another provider or realm. OAuth uses fresh verification
and **strict** augmentation, never a cached best-effort browser session.

For shared replicas, replace the browser backend with:

```yaml
backend:
  type: valkey
  url: rediss://valkey.example.org:6379/0
  key_prefix: authotron
  password: "" # inject using AOT_UI__BROWSER_SESSION__BACKEND__PASSWORD
  connect_timeout_ms: 2000
  operation_timeout_ms: 1000
```

Keep issuer, policy, signing configuration, prefixes and capacity limits coherent
across replicas. Only one primary is supported; Cluster/Sentinel discovery and
automatic fallback are not implemented. Backend durability depends on its configuration.

## HTTP endpoints

| Route | Contract |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata with literal issuer, authorization/token endpoints, JWKS URI, code grant, public-client `none` authentication, S256 and `scopes_supported` (sorted unique union of all configured resource scope names) |
| `GET /oauth/jwks` | Public RSA JWKs only: `kty`, `alg`, `use`, `kid`, `n`, `e` |
| `GET /oauth/authorize` | Strict bounded authorization query; reserves a client-partition slot, resumes an exact matching active request, or shows a 409 conflict for a different request |
| `GET /login/method/{id}` | Browser method modal/native forms capture the current OAuth transaction ID in a server-rendered hidden field |
| `POST` to the selected login form | Single trusted Origin, one-use flow CSRF, exact hidden-ID/cookie match and pending lookup before fresh strict verification; promotes authenticated state and redirects to fixed `/oauth/continue` |
| `GET /oauth/continue` | Always a local consent page, not an automatic callback redirect; refresh rotates the challenge |
| `POST /oauth/consent` | Explicit approve/deny with Origin, transaction binding and consent CSRF; atomic code issuance or denial, then 303 to the registered callback |
| `POST /oauth/token` | Backchannel public-client code exchange with exact callback/resource and PKCE; atomic redemption followed by the proof-consuming signing bridge. With refresh enabled, also the `refresh_token` grant (see [Refresh tokens](#refresh-tokens)) |
| `POST /oauth/revoke` | RFC 7009 revocation of a refresh-token family by a public client (`token`, `client_id`, optional `token_type_hint`) |

These routes are absent on the metrics router. Existing HTTP route/status metrics and
direct-login admission/deadline metrics cover the flow without identity, URL, state,
code or token labels. Metadata advertises no registration endpoint. When any client
enables refresh tokens, `grant_types_supported` adds `refresh_token` and metadata adds
`revocation_endpoint` with `revocation_endpoint_auth_methods_supported: ["none"]`.

### Token and revocation rate limits

`POST /oauth/token` and `POST /oauth/revoke` are limited per client IP with a fixed
window, before the request body is parsed:

```yaml
oauth:
  endpoint_rate_limit:
    window_seconds: 60               # 1..3600, default 60
    token_requests_per_window: 60    # 1..100000, default 60
    revoke_requests_per_window: 30   # 1..100000, default 30
    max_tracked_clients: 10000       # 1..1000000, default 10000
    trusted_proxies: [10.0.0.0/8]    # CIDRs, default none
```

A request over the limit gets `429 Too Many Requests`, `Retry-After: <seconds until
the window resets>` and `{"error": "temporarily_unavailable"}`. RFC 6749 registers no
token-endpoint error for throttling; `temporarily_unavailable` is its closest error code,
and `slow_down` is reserved for device-flow polling.

- **Client IP.** The TCP peer address. If the peer matches `trusted_proxies`, the
  server reads `X-Forwarded-For` from right to left and uses the first address that
  is not a trusted proxy. A malformed entry stops the walk at the last trusted hop.
  Without `trusted_proxies`, forwarded headers are ignored. Behind an ingress or load
  balancer, every client then shares the proxy's address and therefore one window.
  List the proxy ranges so that clients are counted separately.
- **Keys.** IPv4 addresses are counted individually. IPv6 addresses are counted per
  /64. IPv4-mapped IPv6 addresses count as IPv4. Each endpoint has its own window.
- **Memory.** Counters live in each replica's memory and are not shared through
  Valkey. With N replicas, a client can get up to N times the limit. Counters reset
  on restart. At most `max_tracked_clients` client windows are kept per replica. When
  the table is full, expired windows are dropped first. If it is still full, requests
  from IPs not already in the table get 429 until windows expire.

## Client flow

Generate a fresh verifier and S256 challenge for each authorization attempt. For example:

```sh
VERIFIER="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
```

Open the following authorization URL in the browser, inserting the generated challenge
and a fresh client-generated `state` value:

```text
https://auth.example.org/oauth/authorize?client_id=mcp-desktop&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback&response_type=code&resource=https%3A%2F%2Fmcp.example.org%2Fmcp&scope=mcp%3Aread&state=CLIENT_STATE&code_challenge=CHALLENGE&code_challenge_method=S256
```

`scope` may be omitted (RFC 6749 §3.3): the server then requests every scope the client
is bound to for that resource (`clients[].resources[].scopes`). Clients such as Codex CLI
rely on this. The defaulted scopes are recorded in the transaction exactly as if they had
been requested explicitly, so role policy, the consent page and the token `scope` claim all
use them. A present `scope` is narrowed to the client's binding for the requested resource
(RFC 6749 §3.3): unknown names and scopes bound only to other resources are dropped,
duplicates collapse, and the remaining scopes (in binding order) are recorded exactly like
defaulted ones. For example, `scope=aviso:read mcp:read` for an Aviso-only binding yields
`aviso:read`, and the token response `scope` says so. A present `scope` that is empty, has
empty tokens or invalid characters, or keeps no scope after narrowing is rejected with
`invalid_scope`.

The client must verify the callback `state` and exact `iss`, then exchange its code:

```sh
curl --fail-with-body https://auth.example.org/oauth/token \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=mcp-desktop' \
  --data-urlencode "code=$CODE" \
  --data-urlencode 'redirect_uri=http://127.0.0.1:49152/callback' \
  --data-urlencode 'resource=https://mcp.example.org/mcp' \
  --data-urlencode "code_verifier=$VERIFIER"
```

Success is JSON containing only `access_token`, `token_type: Bearer`, `expires_in`
and `scope`. Responses use `Cache-Control: no-store`, `Pragma: no-cache` and `nosniff`.
The token endpoint requires no cookie or Origin, does not accept Basic client
authentication, and supports only `authorization_code`. Mandatory fields and known
duplicates are checked within an 8 KiB/32-field form bound; unknown token fields are
ignored and cannot override scopes, resource or expiry. Fixed JSON errors are
`invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type` and
`server_error`, without backend diagnostics. Invalid verifier/request bindings preserve
an unexpired code; replay after successful redemption fails. Signing failure after
redemption does not restore the code or permit proof retry.

Authorization-gate failures stay local, never redirecting to submitted callbacks.
Valid denial redirects with `error=access_denied`, original state and issuer, without
a code. Approvals redirect with code/state/issuer only, never an access token. Static
registered callback queries are retained. OAuth cookies are cleared after a valid decision.

### Policy denial

Once `/oauth/authorize` has validated the request, its registered callback is exact and
known, so a policy denial is reported to the client per RFC 6749 §4.1.2.1 instead of
leaving it waiting for a callback:

- **At login.** Valid credentials (`POST /login/method/{id}` with the OAuth transaction)
  whose verified identity lacks a required role or comes from a realm not in
  `allowed_realms` atomically consume the pending transaction and 303 to the registered
  callback with `error=access_denied`, the original `state` and `iss`, without a code.
  OAuth cookies are cleared. The browser attempt is recorded with the `denied`
  outcome (distinct from `rejected` credentials). Wrong credentials still re-render the
  `401` form.
- **Policy changed before consent.** If the identity was eligible at login but policy
  is tightened before `/oauth/continue` or `/oauth/consent`, the stored record is
  classified as policy-ineligible (distinct from corruption), atomically removed, and
  the client receives the same `access_denied` redirect. A corrupted record (including
  a damaged consent envelope around an otherwise policy-denied identity) or a backend
  outage remains a local `503` and is not removed.
- **GET resume paths.** `GET /oauth/continue` performs the removal and redirect.
  `GET /oauth/authorize` and `GET /login` (or a method form) recovery for a
  policy-denied flow do not redirect to the client themselves; they 303 to
  `/oauth/continue`. These GET paths authorize the redirect only by the browser binding
  cookies (transaction ID plus browser nonce, which must match the stored record); they
  perform no Origin or CSRF check. The target is always the registered callback stored
  in the transaction, re-validated against the current configuration before the
  redirect; a callback no longer registered fails locally instead.

Origin, CSRF, transaction-binding and missing/expired-transaction failures never
redirect; replaying the consumed transaction fails locally. Identities are not logged.

## Binding and browser protections

Two `__Host-` cookies carry a random browser nonce and opaque transaction ID, with
Secure, HttpOnly, SameSite=Lax and Path=/; only nonce/ID hashes index persisted state.
The hidden transaction field must match the current transaction cookie. Missing,
duplicate, malformed or switched OAuth context is rejected, never falling back to
ordinary browser authentication. Stale forms from another tab cannot authenticate
a new client's request. Without OAuth context, the existing `/login/account` flow
retains its normal behavior.

Credential POST checks remain strict. GET login entry points instead provide
recovery: authenticated/consent-ready transactions resume `/oauth/continue`;
expired, lost, or malformed OAuth state clears the OAuth cookies and shows an
explicit restart/direct-sign-in choice. Backend outages remain errors and do not
silently switch the flow to direct authentication. Only one OAuth flow is active
per browser cookie pair: an exact validated-request match resumes that flow rather
than allocating another slot. A different client, callback, resource, scopes,
state, or PKCE challenge produces a 409 conflict page with an explicit link to
continue the current request; no cookies change and no automatic redirect occurs.
Finish or deny the current request before starting a different authorization.

Credential and consent pages escape all configured/client/identity text. They do not
render client state or tokens. The consent page names the user as "Signed in as" the
sign-in's display name (an OIDC method's `display_name_claim`), or else the username;
the display name never reaches codes or tokens. Modal JavaScript whitelists the optional canonical
transaction field and navigates only to literal same-origin `/oauth/continue` or
`/login/account`. Native POST fallback remains supported. Consent alone uses a native
POST redirect; its CSP allows self plus the registered callback origin because browsers
can enforce form-action on redirects. Scripts/resource loads remain restricted, and
external branding is suppressed on credential/consent pages. Browser cross-origin token
CORS is disabled; cross-origin public SPAs are not supported in this baseline.

## Policy, time and storage

Requests require exact client/callback/resource. Requested scopes outside the client's
binding for that resource are dropped; at least one must remain. Role policy applies to
every remaining scope. There is no URI aliasing, per-scope consent or first-party skip.
Web callbacks require HTTPS; native callbacks additionally permit HTTP loopback
on `127.0.0.1`, `[::1]` or `localhost`, with or without a port. Accepting `localhost`
deliberately deviates from RFC 8252 §8.3 for interoperability: Claude Code, MCP Inspector,
Cursor and Gemini CLI use `localhost` callbacks.

Loopback callbacks match port-agnostically (RFC 8252 §7.3): a registered
`http://127.0.0.1/callback` (or one with any port) matches an authorization request for
`http://127.0.0.1:<port>/callback` with any canonical port 1–65535. The request must carry
an explicit port; scheme, host, path and query must be literally identical. Hosts are
compared case-sensitively and are not interchangeable: a `localhost` registration does not
match `127.0.0.1` or `[::1]`, so register each host a client uses. HTTPS callbacks always
match exactly. The exact requested callback is stored with the authorization transaction,
used for the consent CSP `form-action` origin and the final redirect, and must be repeated
byte-for-byte at token exchange. Callback userinfo/fragments/control characters, malformed
percent escapes, and reserved response query names are rejected. Resource URIs also
reject malformed percent escapes; valid escapes retain their literal spelling rather
than being decoded for matching. Resources are canonical HTTPS and explicitly
bound to each client. Eligible identity must have an allowed realm and every required
role; attributes and preexisting user scopes never grant permissions.

| Setting | Default | Bound |
| --- | --- | --- |
| `authorization_transaction_ttl_seconds` | 300 | 30–900 seconds |
| `authorization_code_ttl_seconds` | 60 | 30–300 seconds |
| `access_token_ttl_seconds` | 300 | 60–3600 seconds |
| `max_authorization_transactions`, `max_authorization_codes` | 1024 each | 1–100000 each, separate capacity |
| `max_authentication_age_seconds` | 300 | 1–3600 seconds |
| `authentication_clock_skew_seconds` | 30 | 0–60 seconds; future verification timestamps only, no age-deadline grace |

Transaction capacity is partitioned across registered clients without borrowing:
each receives `floor(max_authorization_transactions / client_count)` slots, and
the remainder is assigned one slot at a time in configuration order. The shares
sum to the global cap; enabled startup rejects fewer slots than clients. Pending,
authenticated, and consent-ready records occupy the same client share. Memory
reserves under its mutex; Valkey checks and reserves atomically and reclaims
expired or consumed index members. Client-index metadata expires by its latest
original reservation deadline even without another request. Early consumption
can leave bounded metadata until that deadline; admission reconciles it against
the authoritative global index. Keep client ordering and all limits identical
across replicas, and drain active transactions before changing the partition.

This isolates one client's reservations from another client's capacity; it is
**not authenticated caller isolation or a denial-of-service guarantee**. Client
IDs are public and cookies can be replaced. An attacker can target one client's
share, every registered client, or request-processing resources. Production
deployments still require trusted edge admission/rate controls; never derive an
abuse-control identity from untrusted forwarded headers. Reusing a live browser
flow avoids accidental reservations but does not identify an attacker.

Code expiry is the minimum of code TTL, original consent ceiling, transaction expiry
and authentication freshness. Current policy/TTL tightening can shorten eligibility;
relaxation never extends stored ceilings. Valkey state transitions use server TIME;
replica clocks must be synchronized for verification and signing. Access tokens use
their own configured lifetime and may outlive the short authorization deadlines.
Verification-time roles and issued-token lifetime remain revocation windows; snapshot
restoration does not rerun upstream verification.

Private codecs are wire-bounded: Pending 16 KiB, authenticated context 64 KiB,
ConsentReady/code grant 96 KiB. Trusted authenticated storage is required, not a MAC
against compromised cache contents. Code envelopes bind their actual code hash and
originating literal issuer. Valkey namespaces are `:oauth:authorization-transactions:v8:`
and `:oauth:authorization-codes:v4:`; code hashes contain exactly code_hash/issuer/expiry/payload.
Shared issuance atomically persists code while consuming consent; redemption compares
all code fields/index score/effective deadline before atomic deletion and proof release.
Expected failures preserve unexpired state. Unexpected write failures, OOM, cancellation
or lost replies can leave ambiguous mutation outcomes: atomic execution is not rollback.
A command whose connection was closed is sent once more on a new connection (see
[Durable refresh-token storage](#durable-refresh-token-storage)); a second run of an
issue, transition or redemption finds its snapshot consumed and fails as missing. There
is no other replay and no fallback. Memory is development-only, per-instance,
without restart persistence. Capacity bounds logical records, not total allocation;
100000 96 KiB records alone permit about 9.15 GiB payload plus overhead.

The v6 transaction and v3 code namespaces store the provider's pre-augmentation roles
and the browser method id that refresh tokens need. Upgrading from earlier versions
drops in-flight authorization attempts and unredeemed codes, so users must restart
those logins. Do not mix old and new
application replicas behind one login endpoint. Restricted backend ACLs must permit
`ZRANGE` as well as the existing sorted-set/hash operations, with access to all keys
beneath the configured OAuth transaction prefix, including its client indexes.

## Identity claims for resource servers

By default an access token's `roles` lists only the roles that its granted scopes
require: it says what the grant allows, not who the user is. A resource server that
decides from the user's realm and roles itself, for example which data each realm or
role may read, can ask for them per resource:

```yaml
oauth:
  resources:
    - resource: https://aviso-mcp.example.org/mcp
      allowed_realms: [ecmwf, demo-sso]
      scopes:
        - name: aviso:read
          required_roles: []
      identity_claims:
        roles: [aviso-reader] # or ["*"]: every role of the user
```

Access tokens for that resource then carry two more claims:

- `realm`: the user's realm, a string.
- `roles`: the user's roles after augmentation that `identity_claims.roles` names,
  compared exactly, sorted and unique, instead of the required roles; `["*"]` alone
  names every role the list could name, leaving out one with surrounding whitespace or
  control characters, or named `*`. For a family coupled to an OIDC offline session
  these come from the latest upstream refresh, through the method's `role_map`.

Both are present whenever the resource opted in; `roles` may be empty. The list holds 1
to 64 names of 1 to 128 bytes, without control characters or surrounding whitespace,
and `*` only alone. A token carries at most 64 roles, since identities with more are
refused. Scope checks are unchanged. Without `identity_claims`, tokens are unchanged
and carry no `realm`.

**When removed roles disappear.** Each refresh computes the claims again from the roles
it re-checks, and tokens already issued keep theirs until `exp`. Augmentation runs again
at every refresh, so a role an augmenter no longer grants is gone at the next one. The
sign-in method's roles are asked for again only by a family coupled to an OIDC offline
session, whose refresh renews the upstream grant: a role removed at that provider is
gone at the next refresh. Every other family keeps the method's roles of its sign-in
until it ends, idle or at its absolute lifetime. To take a removed role away sooner,
[revoke the user's logins](#revoking-logins), for example with
`authotron admin logins revoke --realm <realm> --username <name>`; the application
then signs in again and gets the current roles.

**Rolling it out.** Turning `identity_claims` on changes what `roles` means for that
resource: from the roles the granted scopes require to the user's own roles. A
resource server that reads `roles` as the former must be switched in the same rollout,
and tokens issued before the change, without `realm`, stay valid until their `exp`.

aviso-server reads these claims with `mcp.identity.source: token_claims`: it takes the
realm and roles from the validated access token instead of looking the user up.

**Trust.** The resource server trusts this issuer for `realm` and `roles` as it does for
the token itself: whoever controls the signing keys, or the methods, augmenters and
role maps that grant roles, decides what the resource server sees. Review those as part
of the resource server's access policy, and list only the roles it needs, so that
tokens disclose no more about the user than that.

## Refresh tokens

Refresh tokens are opt-in per client:

```yaml
oauth:
  max_refresh_token_families_per_user: 50 # 1..1000, default 50
  clients:
    - client_id: mcp-cli
      # ...
      refresh_tokens:
        enabled: true
        idle_ttl_seconds: 2592000      # 30 days without use; default 30 days
        absolute_ttl_seconds: 7776000  # 90 days after login; default 90 days
        upstream_offline_access: false # couple OIDC sign-ins to the provider; default false
        retry_window_seconds: 30       # 0..30; answer retried refreshes; default 30
  refresh_token_retry_key_file: /run/secrets/oauth/retry.key # required with Valkey
```

With `upstream_offline_access`, families started by an OIDC sign-in follow the
provider's offline session; it needs `oauth.upstream_token_encryption`. See
[Upstream offline access](oidc.md#upstream-offline-access).

Both lifetimes must be between 300 seconds and 400 days (34560000 seconds), and
`idle_ttl_seconds` must not exceed `absolute_ttl_seconds`; startup rejects other values.
For an enabled client, every authorization-code exchange returns a `refresh_token`
next to the access token. The code is consumed before the family is stored. If storing fails
(for example, the backend is unavailable), the exchange still succeeds and returns the
access token without a `refresh_token`. The server logs
`oauth.refresh_token.issue_failed` and counts `issue_failed`, and the user signs in
again once the access token expires. This avoids failing a login whose code can no
longer be retried. The client does not need to request `offline_access`,
because common MCP clients never send it.

**Format and storage.** A refresh token is 256 random bits encoded as 43 base64url
characters. The server stores its SHA-256 hash, and the latest rotation keeps the
current token sealed by the previous one and the retry key (see *Retries* below).
Each login starts a *family* holding the client, resource, granted scopes, realm,
username and the roles the provider returned before augmentation. Families live in the browser-session backend:
Memory (development, per process, lost on restart) or Valkey under
`<key_prefix>:oauth:refresh-tokens:v3:`. Each Valkey operation is one Lua script, and
keys expire at the family's idle deadline. The `v3` record adds the sealed successor and
retry counters of the latest rotation; moving from an earlier namespace drops existing
families, and users must log in again. Only preview deployments ran earlier namespaces;
their keys expire at their own idle and absolute deadlines, or can be deleted at once,
for example `valkey-cli --scan --pattern '<key_prefix>:oauth:refresh-tokens:v2:*'`
piped to `valkey-cli unlink`. Restricted ACLs must allow `EVAL`, `GET`,
`SET`, `DEL`, `EXISTS`, `TYPE`, the hash commands `HSET`/`HGET`, the sorted-set commands
`ZADD`/`ZRANGE`/`ZREM`/`ZCARD`, and `PEXPIREAT`/`PEXPIRETIME` under that prefix, and
`SCAN` for [admin commands](#revoking-logins) without `--username`. A family
coupled to an OIDC offline session also keeps its sealed upstream grant in the family
hash, and an upstream refresh holds a short-lived `lock:<family>` key.

**Lifetimes.** A family expires `idle_ttl_seconds` after its last use, and never later
than `absolute_ttl_seconds` after login. A refresh moves the idle deadline but never the
absolute one. Lowering `absolute_ttl_seconds` also shortens existing families. Raising
it does not extend them.

**Per-method cap.** A family records the browser method (`browser.id`) used to sign
in. That method's optional `refresh_max_lifetime_seconds` further caps the absolute
lifetime: the family ends at the earlier of the client's and the method's limit.
Like the client limit, lowering or adding a cap shortens existing families at their
next refresh. A shorter cap for a weaker credential, such as an API key, limits how
long that login stays usable:

```yaml
providers:
  - type: ecmwf-api
    # ...
    browser:
      id: ecmwf-api-key
      label: ECMWF API key
      refresh_max_lifetime_seconds: 2592000 # 30 days
```

If the method is removed or its `id` changes, its families are revoked at their next
refresh.

**Refresh grant.** `POST /oauth/token` with `grant_type=refresh_token`,
`refresh_token` and `client_id` (the client the family was issued to). Two optional
parameters are accepted:

- `scope`: a space-separated subset of the family's scopes.
- `resource`: must equal the family's resource.

On every refresh the server:

1. Checks that the client still exists and still has refresh tokens enabled, that the
   login method is still configured, and that the absolute lifetime has not passed.
   For `plain` (password) methods, it also checks that the user is still listed in
   the provider's `users`. A family coupled to an OIDC offline session then renews it
   at the provider and takes the refreshed roles
   ([details](oidc.md#upstream-offline-access)).
2. Re-runs **strict** augmentation, starting from the stored provider roles. Roles
   that the augmenters no longer grant are dropped.
3. Re-evaluates the current client/resource/scope policy.

Only after these checks pass does it issue a new access token and a new refresh token,
which replaces the presented one. Responses are `Cache-Control: no-store`. Errors:

| Condition | Response |
| --- | --- |
| Unknown, expired, rotated or revoked token; token issued to another client; user no longer meets policy | 400 `invalid_grant` |
| Client no longer enabled; login method removed; password user removed; absolute lifetime shortened past now | 400 `invalid_grant`, family revoked |
| `scope` not a unique subset of the granted scopes | 400 `invalid_scope` |
| `resource` differs from the family | 400 `invalid_target` (RFC 8707) |
| Unknown `client_id` | 400 `invalid_client` |
| Augmentation failure/timeout or backend unavailable | 503 `server_error`; the token stays valid |

**Rotation and reuse detection.** Each refresh replaces the presented token with a new
random one. Presenting an already-rotated token is treated as theft: the whole family
is revoked, and the current token stops working too. One exception keeps a lost
response from costing the user a sign-in.

**Retries.** A client may present a token again because the response never reached it
(a network failure, a client killed mid-request), or because two processes share one
credential file and refresh at the same time. If it presents the token the family
rotated *within the last `retry_window_seconds`* (30 by default), the server answers
as the first time: the **same** refresh token and a new access token, after the same
policy checks and strict augmentation. The family is not rotated again. Each rotation
is answered at most three times this way; further attempts get `invalid_grant` and
the family is kept. A family coupled to an OIDC offline session does not call the
provider again; the access token is built from the provider roles that the first
answer's rotation stored. Two refreshes of one token at the same time both receive the
token the first one rotated to. With `retry_window_seconds: 0` there are no retries:
presenting the previous token is reuse at once. Answers count as `retried` and are
logged as `oauth.refresh_token.retried`.

To answer a retry, each rotation stores the new token encrypted (AES-256-GCM) under a
key derived (HKDF-SHA256) from the token it replaces and from the **retry key**,
`oauth.refresh_token_retry_key_file`: 32 bytes of standard Base64, the same on every
replica. The store holds neither. The family record keeps only the latest rotation's
encrypted token, but Valkey's append-only file (AOF), its replicas and its command logs
(`MONITOR`, and `SLOWLOG` for slow scripts) keep earlier ones too, until the next AOF
rewrite. What a copy of the store reveals:

- **Without the retry key**, no token, whether it is a point-in-time copy (an RDB
  snapshot, a backup of the data) or the AOF, a replica or a command log, and
  whatever old refresh tokens come with it.
- **With the retry key**, a point-in-time copy and a family's previous token reveal its
  current token. The AOF, a replica's stream or a command log also hold the earlier
  encrypted tokens, so any refresh token of a family since the last AOF rewrite reveals
  each later one in turn, up to the current token.

So keep the retry key out of Valkey, its hosts and its backups: mount it from a
Secret, like the signing key. Protect the AOF, backups and replicas like the refresh
tokens, and deny `MONITOR` and `SLOWLOG` in Valkey's ACLs to every user that does not
need them; Auth-O-Tron needs neither. The key is required when a client has refresh
tokens and the browser-session backend is Valkey; startup refuses to start without it,
before reading any file or connecting, and refuses a file that is another configured
key or secret file, under its name or another one such as a symbolic link, and a key
equal to an upstream token key or to an OIDC client secret that is 32 bytes of
standard Base64. A Memory store, which answers
every retry in the process that rotated, uses a random key per process when the
setting is absent. Any replica holding the key can answer a retry.

The window has a price: within it, whoever holds the previous token obtains the current
one. Two holders of one token, a legitimate client and a thief or two processes
sharing a file, stay in step as long as each refreshes within the window of the
other's last rotation, and neither is detected. Reuse is detected once one of them
presents its older token after the window has passed, or a token older than the
previous one: then the family is revoked. When three consecutive rotations of a
family were each answered again, the server logs a WARN
`oauth.refresh_token.retry_pattern`, which this situation produces. Clients that
never share tokens can set `retry_window_seconds: 0`.

The server remembers only recent rotated tokens: the last 32 per family. Each one is
also forgotten once the idle deadline set at its rotation passes. Older tokens can no
longer be told apart from unknown ones. Presenting one returns `invalid_grant` but does
*not* revoke the family. This caps storage at 33 token hashes per family, regardless of
how often the family refreshes. The cost is that a token stolen and replayed after
more than 32 later refreshes, or after more than `idle_ttl_seconds`, no longer
triggers revocation. It still grants nothing.

**Per-user cap.** A user may hold at most `max_refresh_token_families_per_user` live
families across all clients. A new login beyond the cap revokes that user's oldest
family. It never rejects the new login.

**Revocation.** `POST /oauth/revoke` with `token` and `client_id` (no client
authentication; public clients) revokes the whole family of any refresh token it
belongs to. Unknown, malformed, foreign-client or access tokens return 200 with no
effect (RFC 7009 §2.2). Signed access tokens cannot be revoked and remain valid until
their `exp`. Users and operators can revoke logins too; see
[Revoking logins](#revoking-logins).

**Caveats.**

- Refresh has no user credentials. A password user removed from a `plain` provider
  is detected because the user list is local. Changing that user's password is not
  detected. For `ecmwf-api` methods, a disabled or rotated API key is not detected
  either. Only augmenter-derived roles and current policy are re-evaluated. Limit
  this window with `absolute_ttl_seconds` or the method's
  `refresh_max_lifetime_seconds`, or revoke families explicitly.
- With the Memory backend, families are per process. A refresh token works only on the
  replica that issued it and is lost on restart. Multi-replica deployments need Valkey.
- Metrics: `authotron_oauth_refresh_tokens_total{event}` with `issued`, `rotated`,
  `retried`, `reuse_detected`, `family_revoked` (every revoked family, including
  per-user cap evictions) and `issue_failed`, and
  `authotron_oauth_upstream_tokens_total{event}` for coupled families.
- Every revoked family is logged as `oauth.refresh_token.family_revoked` with its
  reason ([audit events](logging.md#oauth-audit-events)).

### Revoking logins

A *login* is a refresh-token family: one sign-in of one user at one client, with every
refresh token it rotates through. Revoking it ends all of them at once and, for a
family coupled to an OIDC offline session, revokes its upstream grant at the provider.
Access tokens already issued stay valid until their `exp`. Every revocation is logged
as `oauth.refresh_token.family_revoked` with its
[reason](logging.md#oauth-audit-events). There are three ways:

- **The user**, on the account page ([Your logins](ui.md)): one login or all of their
  own, matched by exactly the session's realm and username (`user_revoke`).
- **The client**, with `POST /oauth/revoke` and any token of the family, as above
  (`client_revoke`).
- **An operator**, with `authotron admin logins`, a command of the server binary
  (`admin_revoke`). It loads its configuration as the server does (`AOT_CONFIG_PATH`
  if set, else `./config.yaml`, then `AOT_` variables) and reaches the same Valkey,
  so it opens no listener and adds no endpoint. Run it where the server runs: the
  image keeps the binary at `/app/authotron`, and `kubectl exec` starts it in the
  container's working directory with its environment, so it finds the server's file
  (in the Helm chart's pods, `/app/config.yaml`) and its overrides:

```sh
kubectl exec deploy/authotron -- /app/authotron admin logins list --realm ecmwf --username alice
kubectl exec deploy/authotron -- /app/authotron admin logins revoke --realm ecmwf --username alice --dry-run
kubectl exec deploy/authotron -- /app/authotron admin logins revoke --realm ecmwf --username alice
kubectl exec deploy/authotron -- /app/authotron admin logins revoke --realm ecmwf --all-users --client mcp-cli
```

`--realm` is always required; `--username` and `--client` narrow the selection, each
compared exactly. Revoking without `--username` reaches every user of the realm and
must say so with `--all-users`. `list` prints client, method, realm, username, when the
login started, was last used (its latest refresh) and expires if unused and at the
latest, and the family reference of the audit log, newest first and at most `--limit`
rows (default 100, at most 10000); it never prints a token or a family id.
`revoke --dry-run` prints the logins `revoke` would end and changes none of them;
with `--username`, it removes expired entries from that user's family index, as every
listing of a user's logins does. `revoke` prints them too, ends them, then revokes the
upstream grants of coupled families at the provider itself, eight at a time and
waiting at most ten seconds for each answer, and prints how many logins ended and how
the upstream revocations went: revoked, not supported by the provider, failed or timed
out, or skipped because no configured key and method open the grant any more. After 16 failures in a row it takes the provider to be down
and attempts no more; those not attempted count as failed. A login that ended
meanwhile is not counted. Each upstream grant that failed, was not attempted or was
skipped, and may still be live at the provider, gets a line with its family
reference and username, such as
`upstream grant left: 3f2a9c0b71de alice (failed)`; its login is revoked all the same,
and the provider's own expiry of the grant still applies. The command
writes its report to standard output and logs to standard error in the configured
`logging` format and level, including the store's durability check of a server start;
the `family_revoked` and `oauth.upstream.revocation_*` events of a revocation are
logged at INFO even when the configured level is `warn` or `error`.

**Keeping the record.** These lines go to the standard error of the `kubectl exec`
session, not to the pod's log, so log collection does not see them. Keep them with
the report, for example:

```sh
kubectl exec deploy/authotron -- /app/authotron admin logins revoke --realm ecmwf --username alice 2>&1 \
  | tee "revoke-alice-$(date -u +%Y%m%dT%H%M%SZ).log"
```

Who ran the command is recorded by the Kubernetes API server's audit log, if enabled,
as an `exec` into the pod; Auth-O-Tron does not know the operator. The command's
counts are its own: the server's `authotron_oauth_refresh_tokens_total` and
`authotron_oauth_upstream_tokens_total` do not include its revocations.

The exit status is 0 when done, 1 when it failed, 2 for invalid arguments and 3 when
`revoke` revoked the logins but left upstream grants; after a failure during `revoke`,
run it again, and revoke the grants it left at the provider, or wait for their expiry
there. With the Memory backend it fails: families live
inside each server process, and restarting the server ends them all.

**Cost.** With `--username`, the command reads that user's family index only. Without,
nothing indexes families by realm or client, so it scans: one
`SCAN ... MATCH <key_prefix>:oauth:refresh-tokens:v3:family:* COUNT 500` and one
short script per step. No single command holds up Valkey, but a scan visits every key
of the database once, whatever its prefix, and takes time in proportion to the
database's size. A login started during a scan may be missed; run the command again
to catch it.

### Durable refresh-token storage

Refresh-token families live only in the backend; nothing else can reconstruct them.
They outlive Valkey restarts only if Valkey persists its data. Recommended settings:

```text
appendonly yes
appendfsync everysec   # at most about one second of rotations lost on a crash
dir /data              # on a persistent volume, not emptyDir
maxmemory-policy noeviction
```

RDB snapshots alone are not enough: a restore loses every rotation since the last
snapshot, so clients that refreshed afterwards hold tokens the store no longer knows.

If state is lost anyway, the server fails closed. Every refresh returns
`invalid_grant`, clients discard their tokens, and users sign in again. Access tokens
already issued stay valid until their `exp`. Nothing falls back to memory.

At startup, when any client enables refresh tokens, the server checks the store once
and logs one event. Startup continues whatever the outcome:

| Event | Level | When |
|---|---|---|
| `oauth.refresh_token.store_durable` | INFO | Valkey `INFO persistence` reports `aof_enabled:1` |
| `oauth.refresh_token.store_not_durable` | WARN | Valkey reports `aof_enabled:0` (`backend=valkey`), or the Memory backend is selected (`backend=memory`) |
| `oauth.refresh_token.store_durability_unverified` | WARN | `INFO persistence` failed, was ACL-denied, or lacked `aof_enabled` |

Only `aof_enabled` is checked. The RDB `save` setting is not read, because
`CONFIG GET` is usually ACL-denied and snapshots are not durable enough anyway. To
let the check run, grant the backend user `+info`, which is read-only. The check reads
the server at startup only. It does not notice persistence turned off later, and it
cannot tell whether `/data` is on a persistent volume.

A single Valkey with AOF on a persistent volume survives pod restarts. After a Valkey
restart, the first request reconnects transparently: the first command on each replica
finds its connection closed, reconnects and is sent once more, within
`operation_timeout_ms`. Requests that arrive while Valkey is still down return 503 and
leave the presented refresh token valid. The client cannot tell an unsent command from
one whose reply was lost, so a rotation can run twice; the second run finds its own
rotation applied and reports it done, so the refresh succeeds with the token it
generated. A rotation is never applied twice. Timeouts are never resent.

A Valkey node can also fail without closing its connections: a crashed host, a
network partition or dropped packets leave commands unanswered. A command without a
reply within `operation_timeout_ms` returns 503 and is not resent, because it may
have run. Its connection then gets a PING, with the shorter of one second and
`operation_timeout_ms` to answer: a connection that answers was only slow and is
kept; one that stays silent is replaced, so the replica's next commands open a new
connection instead of waiting on it. Only the requests in flight on that connection
fail, including any sent while the PING is pending. A command runs to the end even
if its request is abandoned. A timed-out refresh either left the presented token
current or rotated it, so the client's retry within its `retry_window_seconds`
succeeds either way while fewer than three retries answered that rotation; with a
window of 0, a rotated token is reuse and the user signs in again. Failed connection
attempts are logged as `valkey.connection.attempt_failed` (WARN, error kind only), at
most once a minute, and the next attempt waits at least 200 ms after a failed one, so
requests against an unreachable Valkey do not each open a connection.

A single Valkey is still a single point of failure. For production, choose a managed
or replicated Valkey, or a future database backend, as an operations decision.

## Signing and deferred capabilities

Keys are trusted absolute file references, loaded explicitly on enabled startup.
The Unix loader accepts bounded PKCS8/PKCS1 private PEM and SPKI/PKCS1 public PEM,
checks 2048–4096-bit RSA and private/public consistency, and publishes only public JWKS.
One active key and up to eight unique IDs are supported; inactive public keys permit
verification overlap. Rotation/reload is not automatic: follow
[Key rotation](#key-rotation). Never expose or reuse legacy `jwt.secret` as an OAuth
RSA key.

The HTTP token controller always uses atomic redemption then
`TokenIssuer::issue_from_redeemed`. The direct raw-User entry point
`issue_access_token` is private and test-only; production issuance requires
atomic code-redemption proof. The issuer binds
the exact cached issuer and rechecks current grant eligibility before signing RS256
with `typ: at+jwt` and active kid. Claims include iss/sub/aud/iat/exp/jti/client_id/scope
and only the required-role union, with no username/email/credentials or unrelated roles,
unless the resource asks for [identity claims](#identity-claims-for-resource-servers).
Resource servers must enforce RS256, at+jwt, exact issuer/audience and current validity.
The MCP resource server owns its protected-resource metadata and access-token validation.

Dynamic/CIMD registration, confidential-client authentication, browser token CORS and
automatic operational key rotation are deferred. The supported flow is preregistered
public clients with a fresh sign-in through a browser method (password, API key or an
[OpenID Connect method](oidc.md)), explicit consent and code/S256 exchange.

## Key rotation

Keys are read at startup only. Each step below is one configuration change, rolled
out to every replica before the next step starts; refresh-token families on a
shared Valkey live through all of them. Replicas briefly run different steps during
a rollout, which is why a new key is always added before it is used and removed only
after nothing needs it.

**Access-token signing keys** (`oauth.signing`, up to eight keys). Every listed key
is published at `/oauth/jwks`; `active_kid` signs.

1. **Add** the new key next to the active one, leaving `active_kid` unchanged. The
   JWKS lists both. Resource servers must have fetched it before the next step, so
   wait at least their JWKS cache lifetime.
2. **Switch** `active_kid` to the new key. Access tokens issued from now on,
   including those of refreshes, carry its `kid`. Refresh-token families are not
   bound to a signing key and continue unchanged. Tokens of the old key still
   verify, because it is still published.
3. **Remove** the old key once the longest access-token lifetime
   (`access_token_ttl_seconds`) plus clock skew has passed since the last replica
   switched. It leaves the JWKS; no token it signed is still valid.

After step 2, the old entry may keep only its public key:

```yaml
oauth:
  signing:
    active_kid: signing-2027
    keys:
      - kid: signing-2027
        private_key_file: /run/secrets/oauth/signing-2027.pem
      - kid: signing-2026
        public_key_file: /run/secrets/oauth/signing-2026.pub.pem
```

**Upstream token encryption keys** (`oauth.upstream_token_encryption`, up to four
keys). New sign-ins and every stored upstream grant are sealed with `active_kid`;
any listed key opens the grants sealed under it.

1. **Add** the new key file, leaving `active_kid` unchanged, so that every replica
   can open what the others will seal with it.
2. **Switch** `active_kid` to the new key. From then on, each refresh of a coupled
   family stores its upstream grant sealed under the new key, whether or not the
   provider rotated its token (counted as `rotated` or `resealed` in
   `authotron_oauth_upstream_tokens_total`). Grants sealed under the old key keep
   opening. While the switch rolls out, or after rolling it back, a replica still on
   the old active key reseals the grants it refreshes back under that key; both keys
   open everything, so this is harmless, and the last switch decides.
3. **Remove** the old key once no live family needs it. A family that is refreshed
   after the switch no longer does; one that is not refreshed before its idle
   deadline expires. Each family's idle deadline was set at its last rotation with
   the `idle_ttl_seconds` in force then, so wait for the longest value any coupled
   client had since before the switch, not only the current one, after the last
   replica switched. Check that `reseal_failed` stayed at zero meanwhile: a family
   whose reseal failed may still be sealed under the old key (its next refresh tries
   again). A family still sealed under a removed key fails closed at its next
   refresh: 400 `invalid_grant` without a provider request, the family is revoked
   (`oauth.upstream.unopenable`, then `oauth.refresh_token.family_revoked` with
   `reason="upstream_unusable"`), its upstream grant cannot be revoked at the
   provider (`revocation_skipped`), and the user signs in again.

**Refresh-token retry key** (`oauth.refresh_token_retry_key_file`, one key). Replace
the file on every replica in one rollout. Tokens and families are not affected; only
a retry spanning the change, its rotation sealed under one key and its answer on a
replica with the other, gets `invalid_grant`, and the family is kept.

The login playground renderer derives key ids from key material and replaces each
key in one step when its file is deleted; it does not stage these rotations.

## Self-contained verification

For an SDK-backed resource server and native client, see the repository example
[`authotron/examples/mcp-local`](https://github.com/ecmwf/auth-o-tron/tree/main/authotron/examples/mcp-local).
It demonstrates local HTTPS, protected-resource metadata, Bearer-token validation,
and a scope-protected synthetic MCP tool. Its disposable credentials and keys are
generated outside the repository; it is not a production deployment template.

`cargo test -p authotron --test oauth_http_integration -- --test-threads=1` runs
Basic and mocked ECMWF API-key HTTP flows, checks signatures from the HTTP JWKS,
tests replay and non-consuming bad-verifier handling, stale hidden-ID/cookie swaps,
Origin/CSRF/denial, token-form errors and disabled/readiness/metrics isolation.
The fixture generates disposable RSA keys and uses only public synthetic credentials.

`cargo test -p authotron --test oauth_http_integration disposable_valkey_http_oauth_cross_replica_flow -- --ignored --test-threads=1`
starts and removes its own password-protected Valkey container, runs both direct login
methods across two app states and verifies the resulting tokens. Existing ignored
browser/authorization Valkey fixtures additionally cover quotas, ACL failures,
metadata corruption, forced CAS races, expiry and outages. No cluster or deployment is used.
