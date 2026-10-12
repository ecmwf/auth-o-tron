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
`ecmwf-api` provider with a `browser: {id: ..., label: ...}` block, and at least one is
required when OAuth is enabled. Providers without `browser` stay API-only. See
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
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata with literal issuer, authorization/token endpoints, JWKS URI, code grant, public-client `none` authentication and S256 |
| `GET /oauth/jwks` | Public RSA JWKs only: `kty`, `alg`, `use`, `kid`, `n`, `e` |
| `GET /oauth/authorize` | Strict bounded authorization query; reserves a client-partition slot, resumes an exact matching active request, or shows a 409 conflict for a different request |
| `GET /login/method/{id}` | Browser method modal/native forms capture the current OAuth transaction ID in a server-rendered hidden field |
| `POST` to the selected login form | Single trusted Origin, one-use flow CSRF, exact hidden-ID/cookie match and pending lookup before fresh strict verification; promotes authenticated state and redirects to fixed `/oauth/continue` |
| `GET /oauth/continue` | Always a local consent page, not an automatic callback redirect; refresh rotates the challenge |
| `POST /oauth/consent` | Explicit approve/deny with Origin, transaction binding and consent CSRF; atomic code issuance or denial, then 303 to the registered callback |
| `POST /oauth/token` | Backchannel public-client code exchange with exact callback/resource and PKCE; atomic redemption followed by the proof-consuming signing bridge |

These routes are absent on the metrics router. Existing HTTP route/status metrics and
direct-login admission/deadline metrics cover the flow without identity, URL, state,
code or token labels. Metadata advertises no registration endpoint or refresh grant.

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
render client state or tokens. Modal JavaScript whitelists the optional canonical
transaction field and navigates only to literal same-origin `/oauth/continue` or
`/login/account`. Native POST fallback remains supported. Consent alone uses a native
POST redirect; its CSP allows self plus the registered callback origin because browsers
can enforce form-action on redirects. Scripts/resource loads remain restricted, and
external branding is suppressed on credential/consent pages. Browser cross-origin token
CORS is disabled; cross-origin public SPAs are not supported in this baseline.

## Policy, time and storage

Requests require exact client/callback/resource and all requested scopes. There is no
URI aliasing, partial consent, first-party skip or variable native loopback-port matching.
Web callbacks require HTTPS; native callbacks additionally permit HTTP loopback
on `127.0.0.1`, `[::1]` or `localhost` with an explicit fixed port. Accepting `localhost`
deliberately deviates from RFC 8252 §8.3 for interoperability: Claude Code, MCP Inspector,
Cursor and Gemini CLI use `localhost` callbacks. Callback userinfo/fragments/control characters, malformed
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
originating literal issuer. Valkey namespaces are `:oauth:authorization-transactions:v4:`
and `:oauth:authorization-codes:v1:`; code hashes contain exactly code_hash/issuer/expiry/payload.
Shared issuance atomically persists code while consuming consent; redemption compares
all code fields/index score/effective deadline before atomic deletion and proof release.
Expected failures preserve unexpired state. Unexpected write failures, OOM, cancellation
or lost replies can leave ambiguous mutation outcomes: atomic execution is not rollback;
there is no automatic replay or fallback. Memory is development-only, per-instance,
without restart persistence. Capacity bounds logical records, not total allocation;
100000 96 KiB records alone permit about 9.15 GiB payload plus overhead.

The v4 transaction namespace introduces client capacity indexes. Upgrading from
v3 requires draining/restarting in-flight authorization attempts; the authorization
code namespace is unchanged. Do not mix v3/v4 application replicas behind one
login endpoint. Restricted backend ACLs must permit `ZRANGE` as well as the
existing sorted-set/hash operations, with access to all keys beneath the configured
OAuth transaction prefix, including its client indexes.

## Signing and deferred capabilities

Keys are trusted absolute file references, loaded explicitly on enabled startup.
The Unix loader accepts bounded PKCS8/PKCS1 private PEM and SPKI/PKCS1 public PEM,
checks 2048–4096-bit RSA and private/public consistency, and publishes only public JWKS.
One active key and up to eight unique IDs are supported; inactive public keys permit
verification overlap. Rotation/reload is not automatic: coordinate replicas and retain
old public keys through the longest access-token lifetime plus clock skew. Never expose
or reuse legacy `jwt.secret` as an OAuth RSA key.

The HTTP token controller always uses atomic redemption then
`TokenIssuer::issue_from_redeemed`. The direct raw-User entry point
`issue_access_token` is private and test-only; production issuance requires
atomic code-redemption proof. The issuer binds
the exact cached issuer and rechecks current grant eligibility before signing RS256
with `typ: at+jwt` and active kid. Claims include iss/sub/aud/iat/exp/jti/client_id/scope
and only the required-role union, with no username/email/credentials or unrelated roles.
Resource servers must enforce RS256, at+jwt, exact issuer/audience and current validity.
The MCP resource server owns its protected-resource metadata and access-token validation.

External SSO/OIDC, refresh tokens, dynamic/CIMD registration, confidential-client
authentication, browser token CORS and automatic operational key rotation are deferred.
The first supported flow is preregistered public clients with fresh Basic/API-key login,
explicit consent and code/S256 exchange; no separate production demo or deployment is required.

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
