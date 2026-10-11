# HTTP Endpoints

Auth-O-Tron exposes endpoints on two ports. The main application port (default 8080) handles authentication and token management. The metrics port (default 9090) exposes health checks and Prometheus metrics.

## Main Application Port (8080)

### GET /authenticate

Primary authentication endpoint. Validates credentials and returns a JWT.

| Aspect | Details |
|--------|---------|
| **Request headers** | `Authorization: Basic <base64>` or `Authorization: Bearer <token>`. Optional: `X-Auth-Realm: <realm>` |
| **Success (200)** | `Authorization: Bearer <jwt>` header in response |
| **Failure (401)** | `WWW-Authenticate` challenge header listing available schemes |
| **Notes** | Supports comma-separated credentials. If multiple credentials share the same scheme, the last one is used. |

**Example:**

```bash
curl -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
  http://localhost:8080/authenticate
```

### GET /whoami

Returns the authenticated user's identity as JSON. The response reflects the same identity (after provider validation and augmenter enrichment) that would be embedded in a JWT issued by `/authenticate`, so callers can inspect their effective identity without decoding a JWT.

| Aspect | Details |
|--------|---------|
| **Request headers** | `Authorization: Basic <base64>` or `Authorization: Bearer <token>`. Optional: `X-Auth-Realm: <realm>` |
| **Success (200)** | JSON body with the authenticated user |
| **Failure (401)** | `WWW-Authenticate` challenge header listing available schemes |

**Example:**

```bash
curl -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
  http://localhost:8080/whoami
```

**Response:**

```json
{
  "version": 1,
  "username": "user",
  "realm": "localrealm",
  "roles": ["admin"],
  "attributes": {},
  "scopes": {}
}
```

### GET /token

Creates an opaque token for the authenticated user. Requires the token store to be enabled.

| Aspect | Details |
|--------|---------|
| **Auth** | Required |
| **Success (200)** | `{"token": "<uuid>"}` |
| **Failure (503)** | Token store disabled |

### GET /tokens

Lists all opaque tokens belonging to the authenticated user.

| Aspect | Details |
|--------|---------|
| **Auth** | Required |
| **Success (200)** | `{"tokens": [...]}` |
| **Failure (503)** | Token store disabled |

### DELETE /token/{token}

Deletes a specific opaque token.

| Aspect | Details |
|--------|---------|
| **Auth** | Required |
| **Param** | `{token}` - UUID of token to delete |
| **Success (204)** | No content |
| **Failure (503)** | Token store disabled |

### GET /providers

Returns configured authentication providers.

| Aspect | Details |
|--------|---------|
| **Auth** | None |
| **Success (200)** | `{"providers": [{"name": "...", "type": "...", "realm": "..."}]}` |

### GET /augmenters

Returns configured augmenters.

| Aspect | Details |
|--------|---------|
| **Auth** | None |
| **Success (200)** | `{"augmenters": [{"name": "...", "type": "...", "realm": "..."}]}` |

### GET /

Landing page with service info and version.

| Aspect | Details |
|--------|---------|
| **Auth** | None |
| **Success (200)** | HTML page with service info |

### GET /login

Serves the branded login entry when ConfigV2 `ui.enabled: true`. Without actions
or direct login it remains a preview. Configured actions link to approved browser
clients; configured Basic or ECMWF API-key login opens its direct credential form
in a same-page dialog, with standalone navigation as the JavaScript-free fallback.
An existing direct browser session redirects to `/login/account` only when no
alternative direct flow or sign-in actions are configured; otherwise the chooser stays visible.
With opt-in OAuth enabled and a bound authorization transaction, the same direct
forms perform fresh strict verification and continue to explicit consent instead
of creating an ordinary browser session. See [OAuth](../configuration/oauth.md)
for metadata/JWKS, authorize, consent and code/S256 token endpoints. The login entry
itself is not an application callback, and an existing browser session never proves
OAuth authentication.

| Aspect | Details |
|--------|---------|
| **Auth** | None |
| **Success (200)** | HTML login entry or preview; signed-in direct sessions receive a 303 identity-view redirect only when one direct flow and no sign-in actions are configured |
| **Failure (503)** | Generic, private response if a direct browser session lookup fails against its backend; no missing-session redirect or new cookie |
| **Availability** | Main application port only; route is not registered when UI is disabled |

### GET /static/login.css

Serves the login preview stylesheet when ConfigV2 `ui.enabled: true`.

| Aspect | Details |
|--------|---------|
| **Auth** | None |
| **Success (200)** | CSS stylesheet |
| **Availability** | Main application port only; route is not registered when UI is disabled |

### GET /static/login.js and /static/aviso-logo.png

When `ui.enabled: true`, the application port serves the bundled progressive
dialog enhancement as JavaScript and the official Aviso example logo as PNG.
These assets return 404 when UI is disabled or on the metrics router. The script
is loaded only by choosers offering direct login; it does not intercept SSO links.
No runtime request to an external logo host is needed for the bundled artwork.

These endpoints do not change `/` or `/authenticate`. See [Login UI](../configuration/ui.md) for branding settings and logo constraints. The chart's default image `0.3.6` lacks these endpoints; use an image built from `feat/login-ui-shell` for testing, or an eventual released version containing the UI.

## Both Ports (8080 and 9090)

### GET /health

Health check for load balancers and monitoring.

| Aspect | Details |
|--------|---------|
| **Ports** | Both 8080 and 9090 |
| **Success (200)** | Text: `OK` |
| **Use** | NGINX checks, K8s probes |
| **Note** | Available on the metrics port only when `metrics.enabled: true` |

This is process liveness; browser Valkey availability is not a health dependency.

## Metrics Port Only (9090)

### GET /metrics

Prometheus metrics endpoint.

| Aspect | Details |
|--------|---------|
| **Port** | 9090 only |
| **Format** | Prometheus text |
| **Content** | Auth attempts, latency histograms |

Example output:

```
# HELP auth_requests_total Total authentication requests
# TYPE auth_requests_total counter
auth_requests_total{result="success",realm="internal"} 42

# HELP auth_duration_seconds Authentication latency
# TYPE auth_duration_seconds histogram
auth_duration_seconds_bucket{result="success",realm="internal",le="0.1"} 35
```

## Endpoint Summary

### Optional direct browser login

When `ui.enabled` and either `ui.basic` or `ui.ecmwf_api_key` are configured,
`ui.browser_session` with an explicit `backend.type` (`memory` or `valkey`) is required and the application port serves the corresponding
`GET/POST /login/basic` or `GET/POST /login/ecmwf-api-key`, plus `GET /login/account`.
Both forms share bounded admission, a configurable verification-plus-augmentation
deadline (default ten seconds), exact Origin checks, and cookie-bound single-use flow-specific CSRF.
`max_inflight_logins` is a per-pod nonblocking limit (default 8). Optional nullable
`max_shared_inflight_logins` adds a global Valkey lease cap (1–65536); its default
is disabled. Local admission happens before backend quota/lease commands. Quotas,
form/session capacity and expiry remain shared in Valkey. Browser POST outcomes
and active verification operations have separate low-cardinality
[browser metrics](../reference/metrics.md#browser-login-and-hpa), including failed
session persistence and cancellation; existing API authentication metrics retain
their meaning.
Transactions and their cookie Max-Age use `transaction_ttl_seconds` (default 300,
range 30–900). Sessions use absolute `session_ttl_seconds` (default 300, range
60–86400); reads never extend expiry. Increasing this lifetime also increases
credential-revocation latency, up to 24 hours at the maximum.
Successful verification runs server-side augmenters before storing a bounded identity projection and
redirecting to the fixed account view with an expiring HttpOnly session cookie.
These routes do not mint JWTs, use the token store, or implement an Aviso callback.
They return 404 when disabled. See [Login UI](../configuration/ui.md).

| Endpoint | Request / response |
|----------|--------------------|
| `GET /login/basic` | Escaped username/password form with transaction cookie and CSRF token; never consumes query credentials |
| `POST /login/basic` | URL-encoded `username`, `password`, `csrf` only; username ≤256 UTF-8 bytes, password ≤1,024 UTF-8 bytes; Unicode/whitespace password preserved |
| `GET /login/ecmwf-api-key` | API-key form with transaction cookie and CSRF token |
| `POST /login/ecmwf-api-key` | URL-encoded `api_key`, `csrf` only; key ≤512 bytes |
| `GET /login/account` | Session-only augmented identity, escaped roles, and allowlisted `ecmwf-email`, `email`, `display_name`; no session →303 `/login` |

POSTs are limited to 8 KiB. Successful POST →303 `/login/account` with a rotated
Secure/HttpOnly/SameSite=Lax host-only opaque session cookie. Failures are generic:
400 malformed/unknown/duplicate fields, 403 invalid Origin or CSRF, 401 invalid
credentials or verification/augmentation timeout, 413 oversized body, 429
form/verification quota or admission exhausted, 503 form/session capacity or
backend unavailable. A backend lookup failure on `/login/account` or the direct
chooser is generic 503 rather than treating the session as missing. Backend errors,
quota 429 and capacity 503 never issue a new session cookie. All retain the private
non-cacheable response headers.
When an error needs a replacement form, exhausted form capacity can instead
return 503 (or 429 for form quota); the dialog then offers a fresh-form retry without retaining credentials.
After augmentation, UID/realm are limited to 256 bytes each, roles to 64 entries
of 128 bytes each, email fields to 320 bytes each and display name to 256 bytes;
retained text has a 16 KiB aggregate ceiling. Only UID/realm/roles and the three
allowlisted attributes are retained; scopes and hidden attributes are dropped.
Any retained-field excess returns generic 401 without a session or entitlement
truncation. See [browser identity bounds](../configuration/ui.md#browser-identity-bounds).
Browser responses are non-cacheable and never send `WWW-Authenticate` challenges.
Session cookies are not accepted by `/authenticate`, `/whoami`, or token APIs.

| Method | Path | Port | Auth | Purpose |
|--------|------|------|------|---------|
| GET | /authenticate | 8080 | Credentials | Main auth, returns JWT |
| GET | /whoami | 8080 | Credentials | Authenticated identity as JSON |
| GET | /token | 8080 | JWT | Create opaque token |
| GET | /tokens | 8080 | JWT | List tokens |
| DELETE | /token/{token} | 8080 | JWT | Delete token |
| GET | /providers | 8080 | None | List providers |
| GET | /augmenters | 8080 | None | List augmenters |
| GET | /health | Both | None | Health check |
| GET | /metrics | 9090 | None | Prometheus metrics |
| GET | / | 8080 | None | Service info |
| GET | /login | 8080 | None | Configured login entry or preview (only when `ui.enabled: true`) |
| GET | /static/login.css | 8080 | None | Preview stylesheet (only when `ui.enabled: true`) |
| GET/POST | /login/basic | 8080 | Form + CSRF on POST | Optional direct Basic browser login |
| GET/POST | /login/ecmwf-api-key | 8080 | Form + CSRF on POST | Optional direct API-key browser login |
| GET | /login/account | 8080 | Browser session | Augmented browser identity view |
