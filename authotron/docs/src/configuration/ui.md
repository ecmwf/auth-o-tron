# Login UI

The login UI is an optional branded browser entry page, disabled by default.
Without SSO links or browser-enabled providers it remains a **branding preview**.
SSO links navigate to application-owned browser login flows. Browser-enabled
`plain` and `ecmwf-api` providers verify credentials on Auth-O-Tron and establish a
short-lived augmented identity-view session. These paths do not make this page an OAuth
authorization server or issue authorization codes.

The `ui` section is supported only by ConfigV2 (`version: "2.0.0"`). Migrating a v1 configuration leaves the UI disabled.

## Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ui.enabled` | boolean | `false` | Enable the login page and its stylesheet |
| `ui.branding.application_name` | string | `"Auth-O-Tron"` | Application name, displayed as plain text |
| `ui.branding.logo_url` | optional string | `null` | Validated HTTPS absolute URL or root-relative path |
| `ui.branding.title` | optional string | `null` | Page title; when null or blank, renders `Sign in to {application_name}` |
| `ui.branding.description` | optional string | `null` | Description; omitted when null or blank |
| `ui.sso` | array | `[]` | Operator-configured SSO navigation links (`label`, `start_url`); not providers |
| `ui.browser_session` | optional object | omitted | Required when any provider has a `browser` block; shared HTTPS public origin, session TTL and backend |

Direct browser login methods are configured on providers, not under `ui`; see
[Choosing browser methods](#choosing-browser-methods). The `ui` section rejects
unknown fields, so configurations containing unsupported keys fail to load.

## Choosing Browser Methods

A `plain` or `ecmwf-api` provider becomes a browser login method when it has a
`browser` block with a `label`. Without that block the provider is **API-only**:
it still authenticates `/authenticate` and other API requests but is not offered
on `/login`. The same browser-enabled set is used for OAuth authorization login.

```yaml
providers:
  - type: plain
    name: Local users
    realm: local
    users:
      - username: alice
        password: replace-this-example-password
        roles: [reader]
    browser:
      id: staff
      label: Staff login
  - type: ecmwf-api
    name: ECMWF API Provider
    realm: ecmwf
    uri: https://api.ecmwf.int/v1
    browser:
      id: ecmwf-api-key
      label: ECMWF API key
  - type: plain
    name: Service accounts # API-only: no browser block
    realm: services
    users: []
ui:
  enabled: true
  sso:
    - label: Continue with SSO
      start_url: https://app.example.org/oauth2/start?rd=%2Faccount
  browser_session:
    public_origin: https://auth.example.org
    backend:
      type: memory
```

Rules, checked at startup:

- `browser` accepts exactly `id` (required) and `label` (required).
- `id` is the stable method identifier used in the method URL, form flow tags
  and the `method` metric label. It must match `^[a-z0-9][a-z0-9-]{0,31}$`
  (1–32 bytes: lowercase ASCII letters, digits and hyphens, not starting with a
  hyphen), be unique across providers, and not be one of the reserved values
  `callback`, `new` or `account`. Valid: `staff`, `ecmwf-api-key`, `2fa`.
  Invalid: `Staff`, `-staff`, `staff_login`, an empty string, `account`.
- The label is trimmed and must be 1–64 characters without control characters.
  It is the chooser entry and form heading.
- A non-null `browser` block on any other provider type rejects the
  configuration. `browser: null` is the same as omitting it (API-only).
- Ids are unique; labels are unique case-insensitively; at most 16 browser methods.
- Any browser method requires `ui.browser_session` with an explicit `backend`.
- Enabled OAuth requires at least one browser method.

Each method is served at `/login/method/{id}` (for example
`/login/method/ecmwf-api-key`). Ids are matched exactly against the raw request
path; unknown, reserved or differently cased ids, and any percent-escaped spelling
(for example `/login/method/pass%77ord`), return the branded 404 page. The chooser lists methods in
provider order by label, followed by SSO links. Startup logs the configured
methods by id at INFO level. Reordering providers or changing a label keeps every
method URL; changing an `id` changes that method's URL.

Migration: earlier releases served methods at `/login/method/{n}` by position and
accepted `browser: {label}` alone. Every `browser` block now needs an `id`, and
bookmarks or links to numeric method URLs must be updated to the id-based URL.

Omitting `ui` or `branding` uses these defaults. Application name, title, and description are escaped plain text, not HTML. The footer is fixed: [Powered by Auth-O-Tron](https://github.com/ecmwf/auth-o-tron).

The footer includes Auth-O-Tron's embedded favicon as a decorative mark. Logos
are displayed on a white surface in light and dark themes; use application
artwork designed for a light background.

Branding is public information on an unauthenticated page. Do not put secrets in
branding text or logo URLs.

External HTTPS logos on previews or SSO-only choosers are fetched by the browser,
not the server. Their `no-referrer` policy prevents sending the page URL, but the
image host still receives the browser's network request. Direct-login choosers,
credential forms and account pages retain only same-origin logos and use
`img-src 'self'`. Configure a same-origin asset to keep branding on all pages.

`logo_url` must be an absolute HTTPS URL without userinfo, or a root-relative path starting with `/` but not `//`. Backslashes, control characters, and whitespace are forbidden. Invalid values, including other URL schemes, reject the configuration. For example, `https://example.com/logo.svg` and `/assets/logo.svg` are valid; `http://example.com/logo.svg`, `//example.com/logo.svg`, and `https://user@example.com/logo.svg` are invalid.

A root-relative logo must already be served by the configured origin or ingress.
The bundled official Aviso example artwork is available at
`/static/aviso-logo.png` when the UI is enabled, with no runtime upstream request.
Auth-O-Tron does not fetch configured logo URLs or read arbitrary local files.
URL validation occurs during configuration loading; the generated JSON schema
describes URLs as strings and does not enforce the URL restrictions itself.
Arbitrary mounted-logo assets and configurable colors are not implemented.

## SSO Links

Each `ui.sso` entry has a nonblank `label` and a validated `start_url` with the same
HTTPS/root-relative restrictions as logo URLs. The destination must be an
application-owned endpoint that starts an approved login flow, not a token
endpoint or an arbitrary request-supplied callback. For example:

```yaml
ui:
  enabled: true
  sso:
    - label: Continue with demo SSO
      start_url: https://aviso-browser.example.org/oauth2/start?rd=%2Faccount
```

Labels and URLs are escaped. Only configured destinations appear: query
parameters such as `start_url`, `redirect_uri`, or `return_to` never select the
destination. Operators are responsible for trusting the configured application
origin. A safe URL alone does not make a third-party application trustworthy.
The identity provider must separately register the browser client's exact
callback, and the client must enforce state, nonce, PKCE, issuer/audience checks,
and safe post-login destinations. These links are not an OAuth authorization
server or a substitute for that protocol.

The schema describes SSO labels as strings; the runtime also rejects blank
labels and unknown SSO fields. Schema validation alone does not enforce all
URL and label checks.

## Same-Page Direct Login

When direct login is configured, its chooser links open an accessible native
dialog on `/login`. The selected form is fetched only when opened, obtaining a
fresh cookie-bound CSRF transaction bound to that method. Forms for different
methods do not share a pre-generated token. Configured SSO links remain ordinary navigation.

Loading, invalid credentials and retry states stay inside the dialog. Credentials
are cleared after dispatch and on close; closing is inhibited during a POST.
Escape and the close button otherwise dismiss it and restore focus to its link.
The standalone credential links still work without JavaScript or dialog support.
Successful verification navigates only to `/login/account` after a successful,
same-origin final response at that fixed destination.

The enhancement is bundled at `/static/login.js`; there is no inline script or
separate frontend build. Direct choosers allow scripts, requests, images and form
submissions only to their own origin. `Referrer-Policy: strict-origin` preserves
the browser's exact POST Origin while withholding URL paths. Credentials are
submitted only in URL-encoded POST bodies, never URLs, logs or browser storage.

## Enabled Example

This is a configuration fragment for an Aviso-branded preview:

```yaml
version: "2.0.0"
ui:
  enabled: true
  branding:
    application_name: "Aviso"
    logo_url: null
    title: null
    description: "Aviso sign-in preview"
```

The existing Figment environment overrides also apply, for example `AOT_UI__ENABLED=true` and `AOT_UI__BRANDING__APPLICATION_NAME=Aviso`.

For a runnable loopback-only example, see `authotron/examples/login-ui/aviso.yaml`:

```bash
AOT_CONFIG_PATH=authotron/examples/login-ui/aviso.yaml cargo run -p authotron
```

Open `http://127.0.0.1:8080/login`. No local user configuration is required.

## Browser Application Callbacks

The opt-in [OAuth authorization server](oauth.md) provides the preregistered
public-client code/S256 flow through the browser method forms and explicit consent.
When OAuth is disabled, standalone browser verification and the preview retain their
existing behavior. OAuth requests are transaction-bound and do not reuse browser sessions.

Branding and SSO links do not register an authentication client or callback.
The browser sign-in flow must register an exact callback URI for each application
client, such as the Aviso backend's `/auth/callback`, and use authorization codes
with state and PKCE checks rather than redirecting with access tokens. External
SSO may have a separate callback into the auth authority before the application
callback is reached.

## Direct ECMWF API-Key Login

This path is independent of Keycloak, OIDC clients and SSO links:

```yaml
providers:
  - type: ecmwf-api
    name: ECMWF API Provider
    realm: ecmwf
    uri: https://api.ecmwf.int/v1
    browser:
      id: ecmwf-api-key
      label: ECMWF API key
ui:
  enabled: true
  browser_session:
    public_origin: https://auth.example.org
    session_ttl_seconds: 300
    backend:
      type: memory
```

Public origin
must be an absolute HTTPS origin without credentials, path, query or fragment.
Session TTL defaults to 300 seconds and must be between 60 and 86,400 seconds.
Configuration is checked before creating stores or browser network state.

The method's chooser entry opens `GET /login/method/{id}` with an `api_key` form. Submission requires a
same-origin POST with the host-only form-nonce cookie and one-use CSRF token;
transactions expire after `transaction_ttl_seconds` (default five minutes). The response redirects only to the fixed
`/login/account` identity view, not an arbitrary application callback.

Keys are limited to 512 bytes and requests to 8 KiB. Verification is uncached,
follows no redirects, and bounds response/identity
sizes. ECMWF's upstream contract puts the encoded key in its `token` query:
this is not a browser redirect, and errors are sanitized to avoid exposing that
URL. The key is never retained in browser transaction/session state or echoed
on failure. UID is required; optional email is display data, not a verified-email
assertion. No JWT or OAuth token is issued by these browser routes.

Successful login rotates an opaque host-only Secure/HttpOnly/SameSite=Lax
cookie. Only a bounded projection of the augmented identity and absolute expiry
are retained in the selected browser backend.
There is no refresh or sliding expiry; credential re-entry is required after expiry.
Upstream revocation is observed on a later verification, so an existing session
can remain usable until its configured deadline. Browser cookies do not
authenticate the existing bearer APIs.

Direct login requires an **explicit backend selection**, with no implicit memory
backend or fallback. `memory` is for single-replica development: restarting it
signs users out. `valkey` shares forms, sessions, capacity, quotas and optional verification
leases between replicas using the same endpoint and prefix. The browser backend
is separate from the existing API-token store and the browser-SSO demo's state.

### Browser Backend and Limits

All fields below are under `ui.browser_session`. Numeric bounds are inclusive,
validated at startup, and described by the generated schema. Unknown fields are
rejected. URL and prefix restrictions also require runtime validation.

| Field | Default | Valid range / requirement |
|-------|---------|---------------------------|
| `public_origin` | required | Absolute HTTPS origin, no userinfo, path, query or fragment |
| `backend.type` | required | `memory` or `valkey` |
| `session_ttl_seconds` | 300 | 60–86400; absolute expiry, no sliding refresh |
| `transaction_ttl_seconds` | 300 | 30–900; also the form cookie's Max-Age |
| `max_forms` | 1024 | 1–100000 |
| `max_sessions` | 1024 | 1–100000 |
| `max_forms_per_window` | 120 | 1–100000 |
| `max_logins_per_window` | 60 | 1–100000; includes invalid credential attempts |
| `rate_window_seconds` | 60 | 1–3600 |
| `max_inflight_logins` | 8 | 1–256; **per-pod** nonblocking admission |
| `max_shared_inflight_logins` | `null` (disabled) | Optional 1–65536; shared expiring lease cap across Valkey replicas |
| `verification_timeout_seconds` | 10 | 1–30; total verification and augmentation deadline |
| `backend.url` | required for Valkey | One `redis://` or `rediss://` primary endpoint and numeric database path; no userinfo, query or fragment |
| `backend.key_prefix` | required for Valkey | 1–128 ASCII bytes; letters, digits, colon, underscore, hyphen; unique per release |
| `backend.password` | required for Valkey | Nonempty separate secret; never serialized or included in Debug / backend error messages |
| `backend.connect_timeout_ms` | 2000 | 1–30000 |
| `backend.operation_timeout_ms` | 1000 | 1–10000 |

For shared deployments:

```yaml
ui:
  enabled: true
  browser_session:
    public_origin: https://auth.example.org
    session_ttl_seconds: 300
    backend:
      type: valkey
      url: redis://service:6379/0
      key_prefix: authotron:browser:release
      connect_timeout_ms: 2000
      operation_timeout_ms: 1000
```

Browser methods are still enabled by provider `browser` blocks as described above.

Supply the required password using the existing environment override
`AOT_UI__BROWSER_SESSION__BACKEND__PASSWORD` from a secret. Do not log the source
configuration or secret environment. `rediss://` uses certificate- and
hostname-verified TLS with trusted public roots; there is no insecure TLS bypass.
`redis://` is plaintext and should only be used on an appropriately protected
internal network. The client supports a single primary endpoint; an external HA
service that transparently routes to the primary is suitable. Redis Cluster and
Sentinel discovery are not implemented, and the multi-key scripts do not provide
Cluster hash-slot routing.

Valkey server `TIME` determines expiry and fixed-window boundaries. Lua atomically
prunes expiry indexes and enforces capacity, consumes forms only after flow/CSRF
match, and rotates sessions while accounting for a previous SID. No key scans are
used. Session reads do not refresh TTL. Stored records have a versioned envelope
and a strict browser-only projection; a `STRLEN` guard rejects records over 64 KiB
before fetching or parsing their JSON. Memory uses monotonic expiry and periodic
30-second cleanup. Memory account lookups expire only the requested entry rather
than scanning both stores; capacity reclamation scans only the affected store.
Shared and memory quota windows need not have identical phase.

Longer session lifetimes **increase credential-revocation latency**: revocation
is checked on the next verification, not on each account view. At the maximum,
an existing browser identity view can remain usable for up to 24 hours. Adjust
the lifetime deliberately; it is an absolute deadline, never sliding expiry.

Verification acquires the **local permit first**, before any backend admission
command. Requests rejected by a saturated local budget return 429 immediately
and do not spend shared verification quota or send admission commands. Locally
admitted invalid credentials and optional shared-cap rejections do spend the
shared verification quota. Pending backend admissions are bounded by the local
budget, and there is no verification waiting queue.

`max_inflight_logins` is per pod. Without `max_shared_inflight_logins`, replicas
can each use their full local budget; only the shared verification rate quota is
charged, with no global concurrency lease acquisition/release overhead. An
optional shared cap protects aggregate upstream concurrency, but can also prevent
additional replicas from increasing throughput. The explicit memory backend
honors the smaller of local and optional shared caps **within that one development
instance**; it does not coordinate replicas.

Optional shared leases expire after the
configured verification deadline plus a fixed two-second grace, and release
checks both the lease ID and its expiry. Normal completion awaits release within
the same verification deadline; cleanup cannot extend the local admission budget.
Completion is checked against the elapsed deadline even when a future returns
ready late. Once the deadline has elapsed the outcome is timeout. Before then,
verification rejection/timeout takes precedence over release failure; successful
verification followed by release failure fails closed as backend unavailable.
Request cancellation performs bounded asynchronous cleanup, with expiry recovery
after process crashes. Leases are **not perfect fencing**: a suspended process
can resume after its lease expires. The ECMWF HTTP request remains capped at
ten seconds even when the overall verification/augmentation deadline is longer.

The default 60 logins per 60-second window is conservative demo admission, not a
production throughput recommendation. An illustrative production-tuning fragment
(not a benchmark or capacity claim) is:

```yaml
ui:
  browser_session:
    max_inflight_logins: 64
    max_shared_inflight_logins: null
    max_logins_per_window: 10000
    rate_window_seconds: 60
```

Keep the required origin/backend and other configuration alongside this fragment.
Choose limits from measured provider/augmentation latency, upstream capacity and
failure behavior. The rate quota and form/session capacity remain global in Valkey:
HPA scaling does not multiply these budgets. A low global rate quota cannot be
removed by increasing replicas or the per-pod concurrency limit. Capacity planning
also needs the retained-session count, session TTL and Valkey memory overhead.

The unlabeled per-process `authotron_browser_logins_inflight` gauge supports a
custom per-pod HPA signal. CPU-based HPA is independent of this gauge; custom
metrics require an externally configured Prometheus/custom-metrics adapter and
pod/namespace scrape labels. The chart does not install that adapter. See
[browser metrics and HPA mapping](../reference/metrics.md#browser-login-and-hpa).

Valkey connection/authentication failure prevents enabled direct-login startup
with a sanitized error. Disabled/API-only UI does not connect to Valkey. Runtime
backend failures return generic 503, never missing-session 401, redirect or local
fallback. Form/session capacity failures return 503; quota/admission failures
return 429. None of these failures issue a new browser session cookie. The health
endpoint remains process liveness and does not depend on Valkey.
Later operations reconnect after a broken connection; interrupted mutations are
never automatically replayed. A command timeout can have an ambiguous outcome
(for example, a form consumed remotely before the response is lost); retry with
a fresh form. Orphaned records and leases remain bounded by their expiry.

Scripts preflight mutation permissions with `redis.acl_check_cmd`, as well as key
types, before writes. This requires Valkey/Redis support for that API (Valkey 8 is
live-tested). In particular, denying `ZADD` cannot leave a new session record
without its capacity-index entry. Lua serializes successful operations but does
**not** provide rollback: OOM or unexpected runtime failures can still leave a
partial mutation, and network/protocol failures can obscure the outcome. A record
left without an index entry can persist until its absolute TTL, temporarily
weakening index-based capacity accounting. Counts and projection limits are not a
hard end-to-end memory guarantee under those failures; do not treat the permission
preflight as transactional rollback.

Live script verification uses an isolated, disposable Docker Valkey fixture:

```bash
cargo test -p authotron disposable_valkey -- --ignored --test-threads=1
```

It requires Docker and `valkey/valkey:8`; it never uses an operator's server or
local configuration. Ordinary workspace tests are self-contained without Docker.

## Direct Username/Password Login and Shared Sessions

Each browser-enabled `plain` provider is its own method, independent of other
methods and SSO links. Only providers with a `browser` block are offered; other
providers in the same realm stay API-only. Invalid `browser` blocks, origins and
TTLs fail startup before stores are created. The existing CLI/API Basic authentication behavior is unchanged.

Example configuration fragment (synthetic credentials; configure the other
required ConfigV2 settings normally):

```yaml
version: "2.0.0"
providers:
  - type: plain
    name: Local users
    realm: local
    users:
      - username: alice
        password: replace-this-example-password
        roles: [reader]
    browser:
      id: staff
      label: Staff login
  - type: ecmwf-api
    name: ECMWF API Provider
    realm: ecmwf
    uri: https://api.ecmwf.int/v1
    browser:
      id: ecmwf-api-key
      label: ECMWF API key
augmenters:
  - type: plain
    name: Local access
    realm: local
    roles:
      notifications: [alice]
ui:
  enabled: true
  browser_session:
    public_origin: https://auth.example.org
    session_ttl_seconds: 300
    backend:
      type: memory
  sso:
    - label: Continue with SSO
      start_url: https://app.example.org/oauth2/start?rd=%2Faccount
```

`browser_session` contains the shared origin, lifetimes, backend and limits for
all browser methods. Configurations with browser methods must explicitly select
`backend: {type: memory}` for single-replica development or supply the Valkey
backend settings above. UI is disabled by default; the session lifetime default
is 300 seconds (range 60–86400).

For a `plain` method, `GET /login/method/{id}` displays a username/password form;
credentials are accepted only by form POST.
Usernames are nonempty, at most 256 UTF-8 bytes, and cannot contain a colon or
control characters. Passwords are nonempty and at most 1,024 UTF-8 bytes, with
Unicode and whitespace preserved exactly. Requests are capped at 8 KiB.
Passwords are not rendered, logged, or retained in transaction/session state.
Only configured provider roles and server-side augmenters determine identity;
submitted roles, attributes, realm, provider and duplicate fields are rejected.
Errors are generic, and browser routes never send a `WWW-Authenticate` challenge
that could trigger the browser's HTTP Basic dialog.

All methods share the same bounded transaction/session stores, cookies, quotas
and configurable admission limit (default eight). Each form has an independent
transaction ID and challenge, carried together in the opaque `csrf` field. The
`__Host-authotron_form` cookie is a stable form nonce, not the current form's
transaction ID. Opening another form with that nonce, or completing one form,
does not invalidate outstanding forms. Malformed or mismatched submissions cannot
consume another form's transaction. CSRF tokens are cookie-bound, single-use,
expire after the configured transaction TTL, and are also bound to the method
id and provider type. Submitting a form to a different method returns 403 without
consuming the form; a field set that does not match the method's provider type returns 400. Each POST requires exactly
one Origin header matching the configured normalized HTTPS origin. Forwarded
headers and submitted fields never choose the origin or destination.

This preserves multiple forms once the browser has a form nonce. Concurrent first
visits without a cookie (also after cookie expiry) can still race to establish
different nonces; the losing form fails closed and must be reopened. The composite
CSRF format rejects forms issued by earlier versions; Valkey form records carry a
method-bound `flow` value `<kind>:<id>` (`basic:<id>` or `key:<id>`, at most 38
bytes), and the Lua script rejects any other shape.

Auth-O-Tron stores browser records under `<key_prefix>:v2:` (for example
`authotron:browser:release:v2:form:<sid>`); the `v2` segment is the record format
version owned by the server. Upgrading from a release that stored records directly
under `<key_prefix>:` orphans those records: in-flight forms are rejected and
existing browser sessions are no longer found, so users sign in again. Orphaned
keys expire with their original TTLs. Drain earlier-version replicas before
upgrading, because mixed versions do not share forms, sessions, quotas or
admission leases.

After **each successful direct verification**, Auth-O-Tron invokes the existing
`Auth::check_augmenters` pipeline: matching-realm ordinary augmenters run in
parallel, then `plain_advanced` augmenters run serially in configuration order.
Existing augmenter error semantics remain: an individual augmenter error is
recorded and does not itself reject the verified identity. A configurable overall
deadline (default ten seconds) and the admission permit cover verification,
augmentation, and awaited shared-lease release;
timeout creates no session. The resulting identity is checked and projected
before session storage and redirecting to `/login/account`.

The account view escapes username, realm, roles and displayed attribute values.
Only `ecmwf-email`, `email` and `display_name` are displayed; arbitrary attributes
and scopes are not rendered. These are operator-controlled display data, not
verified-email claims. Do not put sensitive data in these display fields.

### Browser Identity Bounds

After augmentation, all browser methods keep only UID (`username`), realm, roles,
and the three allowlisted display attributes. All other attributes and all
scopes are **discarded**, not retained in browser sessions. Limits are UTF-8
bytes, inclusive:

| Projection field | Limit |
|------------------|-------|
| UID / realm | 256 bytes each; UID must contain non-whitespace text and no control characters; valid text is preserved verbatim |
| Roles | 64 entries, each at most 128 bytes |
| `ecmwf-email` / `email` | 320 bytes each |
| `display_name` | 256 bytes |
| Retained text aggregate | 16 KiB, summing UID, realm, roles and retained attribute names/values |

Exceeding a retained-field limit rejects the entire browser login with generic
401 and no session. Entitlements are never silently truncated. At these current
per-field limits the largest retained text payload is 9,628 bytes, below the
defense-in-depth aggregate ceiling. Container/allocator and escaped-HTML overhead
are additional. Hidden attributes/scopes do not count toward this projection
budget because they are discarded; operator-supplied augmentation configuration
is still trusted and can allocate before projection.

Checks inspect borrowed data before constructing the small projection. Session
creation enforces the same invariant even for internal callers. Sessions share
immutable identity data via `Arc`, so account lookups do not deep-clone it while
holding the memory session-store mutex. Valkey reads construct an immutable bounded
projection. The configured session count cap applies to either backend.
Stored-session decoding repeats UID checks and validates expiry against Chrono's
representable range before returning a session; corrupt far-future timestamps
return a generic private 503 rather than panicking account rendering.

LDAP also has bounded streaming-result accumulation and a size-limited cache;
see [LDAP limits](augmenters.md#ldap-result-and-cache-limits). These are
application-data limits, not an end-to-end hard memory guarantee for the LDAP
transport decoder, its internal queues, or trusted configuration.

The chooser stays visible when more than one browser method or any SSO link is
configured, even when already signed in. With exactly one method and no SSO links,
`/login` redirects a signed-in browser to the account view. Successful sign-in
rotates only the submitting browser's previous session; other sessions remain
independent. No browser method route mints a JWT, treats the cookie as API bearer
authentication, or signs the user into a different-origin application.

Credential/account pages make only same-origin image requests, falling back to
the application wordmark for external logos. They use `strict-origin` referrer
policy so browser form POSTs retain a usable Origin header while not disclosing
URL paths; other login pages retain `no-referrer`. All browser responses are
non-cacheable. The Auth-O-Tron token store is not used.

**Boundary:** this logs into Auth-O-Tron's identity view, not an existing
different-origin Aviso application. Application session/callback handoff is a
separate, registered-client integration; no generic JWT redirect is implied.

The page does not issue codes or act on request `redirect_uri`/`return_to`
parameters. Selecting a configured SSO link navigates to the client that starts
authorization and owns its callback. The isolated browser SSO demo under
`authotron/examples/browser-sso` uses Keycloak, OAuth2-proxy and ephemeral Valkey
sessions; it does not use Auth-O-Tron's token store or connect to real Aviso data.
Its renderer tests do not establish live ingress TLS/forwarded-header behavior,
the proxy-native identity endpoint's response headers, or callback/refresh
acceptance. Those checks remain deployment prerequisites, not guarantees supplied
by rendering Kubernetes objects.

## Endpoints and Image Requirement

When `ui.enabled: true`, `GET /login` serves the entry page and `GET /static/login.css` serves its stylesheet. Both require no authentication and exist only on the main application port (`server.port`), not the metrics port. When disabled, neither route is registered. Trailing-slash forms of the login pages (`/login/`, `/login/account/`, `/login/method/{id}/` for configured methods) redirect `GET`/`HEAD` with `308` to the relative canonical path, dropping any query string; they are registered only alongside the pages themselves. Existing `/` and `/authenticate` behavior is unchanged.

The page uses origin-root asset paths (`/static/login.css` and `/favicon.ico`). If
an ingress exposes Auth-O-Tron beneath a rewritten path prefix, route those root
asset paths as well; this preview does not have a configurable base path.

The chart's current default image `0.3.6` lacks these endpoints. Test with an image built from `feat/login-ui-shell`; deployments will need an eventual released version containing the UI.
