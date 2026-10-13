# OpenID Connect Sign-In

An entry in `ui.oidc` offers an external OpenID Connect provider (for example
Keycloak) as a sign-in method on `/login`. Auth-O-Tron is the relying party: it
runs the authorization code flow with PKCE, validates the ID token, maps its
claims to an identity in the method's realm and then treats that identity like
one verified by a credential method. The result is a browser session for the
account page or, during an [OAuth authorization request](oauth.md), the
continuation to consent.

OIDC methods are browser methods only. They do not authenticate API requests;
use a `jwt` provider for bearer tokens issued by the same provider.

## Example

```yaml
ui:
  enabled: true
  browser_session:
    public_origin: https://login.example.org
    backend:
      type: valkey
      # ...
  oidc:
    - id: demo-sso
      label: Continue with demo SSO
      realm: keycloak-demo
      issuer: https://idp.example.org/realms/demo
      client_id: authotron
      client_auth: client_secret_basic
      client_secret_file: /run/secrets/oidc/client-secret
      scopes: [profile, email]
```

Register the client at the provider as a confidential client using the
authorization code flow, with exactly one redirect URI:

```text
<public_origin>/login/method/<id>/callback
https://login.example.org/login/method/demo-sso/callback
```

Require PKCE with `S256` at the provider when it supports that setting.

## Settings

| Field | Default | Description |
|-------|---------|-------------|
| `id` | required | Method id; same rules and namespace as provider `browser.id` |
| `label` | required | Chooser text; unique case-insensitively across all browser methods |
| `realm` | required | Realm of signed-in identities; 1–128 bytes, unique across providers and OIDC methods |
| `issuer` | required | Issuer identifier, compared exactly with the discovery document |
| `client_id` | required | 1–256 visible ASCII characters |
| `client_auth` | `client_secret_basic` | `client_secret_basic`, `client_secret_post`, or `none` (public client protected by PKCE alone) |
| `client_secret_file` | none | Absolute path of the client secret; required unless `client_auth` is `none` |
| `scopes` | `[]` | Scopes requested in addition to `openid`; at most 16 |
| `id_token_algorithms` | `[RS256, PS256, ES256]` | Accepted ID token algorithms: `RS256/384/512`, `PS256/384/512`, `ES256`, `ES384`, `EdDSA` |
| `username_claim` | `sub` | `sub`, `preferred_username`, or `email` |
| `roles_claim` | none | Dotted path to a string-array claim of provider roles |
| `role_map` | `{}` | Provider role → local role; only listed roles are kept |
| `max_authentication_age_seconds` | none | 60–86400; sent as `max_age`, and the ID token's `auth_time` must be recent enough |
| `prompt` | none | `login`, `consent`, or `select_account` |
| `additional_endpoint_origins` | `[]` | Up to 8 HTTPS origins besides the issuer's that may host provider endpoints |
| `clock_skew_seconds` | `60` | 0–300; tolerance for `exp`, `iat`, `nbf` and `auth_time` |
| `http_timeout_ms` | `5000` | 500–30000; bound on each provider request including the body |
| `refresh_max_lifetime_seconds` | none | 300–34560000; caps OAuth refresh-token families started by this method, as for provider methods |

Rules, checked at startup:

- `issuer` is an absolute HTTPS URL without userinfo, query or fragment, at most
  2048 bytes. Valid: `https://idp.example.org/realms/demo`. Invalid:
  `http://idp.example.org`, `https://user@idp.example.org/r`,
  `https://idp.example.org/r?x=1`.
- `scopes` are unique RFC 6749 scope tokens. `openid` is always sent and
  `offline_access` is not accepted. Valid: `profile`, `api:read`. Invalid: `a b`,
  `offline_access`.
- `roles_claim` and a non-empty `role_map` go together. `roles_claim` has 1–4
  segments of letters, digits, `_` and `-`. Valid: `realm_access.roles`, `groups`.
  Invalid: `a..b`, `$.roles`. `role_map` holds at most 64 roles of 1–128 bytes.
- `additional_endpoint_origins` entries are canonical origins. Valid:
  `https://keys.example.org`. Invalid: `https://keys.example.org/`,
  `https://keys.example.org/certs`.
- The client secret file must be readable at startup and hold 1–4096 bytes of
  text; surrounding whitespace is ignored. It is never logged. An unreadable file
  stops startup.
- OIDC methods count towards the limit of 16 browser methods, need
  `ui.browser_session`, and are listed after provider methods. They are offered
  for OAuth authorization requests too, so an OIDC method alone satisfies OAuth's
  requirement for a browser method.

## Sign-in flow

1. `GET /login/method/{id}` loads the provider metadata (see
   [Provider metadata and keys](#provider-metadata-and-keys)) and creates a
   single-use sign-in state in the browser transaction store, with the same
   capacity, rate limit and lifetime as credential forms
   (`transaction_ttl_seconds`). It redirects (303) to the provider with
   `response_type=code`, `scope`, `state`, `nonce` and an S256 `code_challenge`.
2. The provider redirects back to `/login/method/{id}/callback` with `code` and
   `state`. Only the query response mode is used, so the `SameSite=Lax` cookies
   arrive with this top-level navigation.
3. The callback consumes the state atomically, exchanges the code with the PKCE
   verifier and client authentication, validates the ID token, maps the claims,
   runs augmentation and either starts a browser session or continues the pending
   authorization request.

The state is the browser form token. Only a hash bound to the browser's
`__Host-authotron_form` cookie is stored; when an authorization request is
pending, the binding also covers its transaction cookies. A callback in another
browser, or with different transaction cookies, cannot consume it: a sign-in
started for a browser session never completes an authorization request, and the
other way round. The nonce and PKCE verifier are derived from the cookie and the
state, so neither is stored. A callback that does not match the stored binding
(another browser, other transaction cookies) or is malformed leaves the state
usable until it expires. Once consumed, a state cannot be replayed, even if the
sign-in then fails.

Verification shares the browser login admission limits (`max_inflight_logins`,
`max_logins_per_window`, optional shared leases) and its deadline
(`verification_timeout_seconds`), which covers the code exchange, key retrieval
and augmentation.

## Validation

- **Authorization response.** If the provider advertises
  `authorization_response_iss_parameter_supported` (RFC 9207), the callback must
  carry `iss` equal to the configured issuer; a present `iss` must match in any
  case. Together with one redirect URI per method this prevents mix-up attacks.
- **ID token.** The header algorithm must be in `id_token_algorithms`; `none` and
  symmetric algorithms are never accepted. The key is selected by `kid` and must
  match the algorithm's key type and curve and any declared `alg`. The claims must
  name the configured issuer; `aud` must contain `client_id` and, with several
  audiences, `azp` must equal `client_id` (a present `azp` must match anyway);
  `exp` must not have passed, and `iat` and `nbf` must not be in the future, each
  with `clock_skew_seconds`; `iat` must be at most 10 minutes old; `nonce` must
  match. With `max_authentication_age_seconds`, `auth_time` is required and must
  be recent enough. `sub` is 1–255 bytes. Tokens over 16 KiB are rejected.
- **Token response.** Only the ID token is read. Access and refresh tokens in the
  response are discarded without being stored.

## Provider metadata and keys

Metadata comes from `<issuer>/.well-known/openid-configuration` (a trailing `/` on
the issuer is ignored for this URL). The document's `issuer` must equal the
configured value exactly. The authorization, token and JWKS endpoints must be
HTTPS URLs without userinfo or fragment on the issuer's origin or one of
`additional_endpoint_origins`. When the document lists
`response_types_supported` or `code_challenge_methods_supported`, they must
include `code` and `S256`.

Requests to the provider never follow redirects, are bounded by
`http_timeout_ms`, and accept bodies up to 64 KiB. Metadata is fetched at
startup in the background and checked every minute; it is refreshed after an
hour. After a failure, no new attempt is made for ten seconds, and the last good
metadata stays in use for up to a day. Signing keys are cached for 15 minutes;
an ID token with an unknown `kid` triggers a key refresh at most once every 30
seconds. Sets with more than 32 keys are rejected; encryption keys and unknown
key types are skipped.

The provider being down does not stop Auth-O-Tron or affect readiness. While no
usable metadata is known and the last attempt failed, the chooser shows the
method as a disabled "(temporarily unavailable)" button, and
`GET /login/method/{id}` returns a 503 page without creating a sign-in state.

## Identity

- **Username.** `sub` by default, which the provider keeps stable for an account.
  `preferred_username` and `email` are mutable at many providers and are used only
  when configured; `email` additionally requires `email_verified: true`. The
  username is 1–128 bytes without control characters; longer subjects are rejected.
- **Roles.** Provider roles are ignored unless `roles_claim` and `role_map` are
  set. Then only roles listed in `role_map` are kept, renamed to their local name.
  A missing claim grants no roles; a claim that is not an array of at most 256
  strings rejects the sign-in.
- **Attributes.** `email` (only when verified, at most 320 bytes) and `name` (as
  `display_name`, at most 256 bytes) are shown on the account page. Other claims
  are not kept.
- **Augmentation.** Augmenters for the method's realm then run as for any
  browser method: best effort for browser sessions, strict for authorization
  requests. Scope policy for OAuth uses the augmented roles, so a resource must
  list the method's realm in `allowed_realms`.

With Keycloak, include the `basic` client scope (it provides `sub` and
`auth_time`). Realm roles are in the ID token only when a role mapper adds them
there, for example an `oidc-usermodel-realm-role-mapper` with claim name
`realm_access.roles` and "Add to ID token" enabled.

## Errors

Callback errors render generic pages with a link back to `/login`; provider error
descriptions, codes and tokens are never shown or logged.

| Situation | Response |
|-----------|----------|
| Unknown, expired, replayed or wrongly bound state; malformed callback | 400 "Sign-in expired" |
| Provider returned `error` (for example the user declined) | 400 "Sign-in not completed"; the state is consumed |
| Wrong `iss`, rejected code, invalid ID token | 400 "Sign-in could not be verified" |
| Claims do not form an acceptable identity, or augmentation rejects it | 403 "Sign-in not permitted" |
| Provider unreachable or answering a server error, client authentication refused, malformed answer | 503 "Sign-in temporarily unavailable" |
| Admission quota or concurrency exhausted, backend unavailable | 429 / 503 as for credential methods |
| Identity denied by OAuth scope policy | 303 `access_denied` to the client's callback |

Logs record the method id and a fixed reason (`unavailable`, `invalid_response`,
`rejected`, `client_rejected`, `invalid_id_token`, `invalid_identity`,
`augmentation`). Callbacks are counted in the
[browser login metrics](../reference/metrics.md#browser-login-and-hpa) with flow
`oidc`.

## Limitations

- **Sessions are not federated.** Signing out at the provider does not end an
  Auth-O-Tron browser session; it expires after `session_ttl_seconds`.
  Auth-O-Tron has no logout endpoint of its own.
- **Refresh tokens are not re-verified at the provider.** OAuth refresh-token
  families started by an OIDC sign-in re-run augmentation and policy on every
  refresh, as for other methods, but do not consult the provider; a disabled
  provider account keeps refreshing until the family ends. Use
  `refresh_max_lifetime_seconds` on the method to bound this.
- **Client authentication** with `private_key_jwt` and the `form_post` response
  mode are not supported.

An ignored test,
`cargo test -p authotron disposable_keycloak -- --ignored --test-threads=1`, runs
the whole flow against a disposable Keycloak container (Docker required).
