# Aviso browser SSO demo

Static frontend for a Keycloak browser SSO demonstration. This is not production
Aviso, contains no real Aviso data, and makes no Aviso API calls.

## Pages and rendering contract

- `welcome.html`: public `/`, with a fixed link to the Auth-O-Tron public login page.
- `account.html`: protected `/account`, served by Nginx behind OAuth2-proxy.
- `account.js`: served at same-origin `/assets/account.js`; loads identity once and
  again when **Reload identity** is pressed. There is no inline JavaScript.

These files are HTML templates, not rendered Rust source. The renderer reads
them and substitutes only these trusted, typed configuration
arguments, escaped for quoted HTML attributes using Python `html.escape(...,
quote=True)`:

| Placeholder | Value |
| --- | --- |
| `{{LOGIN_URL}}` | Absolute Auth-O-Tron public login URL |
| `{{STYLE_URL}}` | Absolute URL of Auth-O-Tron's embedded login CSS |
| `{{FAVICON_URL}}` | Absolute URL of Auth-O-Tron's favicon |
| `{{LOGO_URL}}` | Application logo URL from the public Aviso UI fixture |

Validate configured URLs before escaping; escaping is not URL validation. No
request input or identity values belong in template substitution. The official
Aviso PNG is loaded externally. Existing login CSS supplies layout, wide-string
wrapping, action styling, and visible keyboard focus for links and buttons.

## Sign-in and identity contract

Auth-O-Tron's branded page is the entry point, **not an OAuth authorization
server**. OAuth2-proxy is the authorization-server client / browser BFF; it owns
`/oauth2/start` and `/oauth2/callback`. Keycloak is the authorization server.
The backend flow uses authorization code with PKCE S256, state and nonce checks,
and returns to the fixed protected `/account` path.

`GET /oauth2/userinfo` must be a same-origin, cookie-bound endpoint returning only
the session's human-safe identity as JSON: required `email` (non-empty string),
optional `preferredUsername` (string). For example:

```json
{"email":"demo@example.org","preferredUsername":"demo"}
```

This is the frontend contract the proxy/backend must satisfy, not a call to
Keycloak's token-bearing userinfo endpoint. Unauthenticated requests should return
401/403; identity responses must not be cached. The browser displays only those
two fields using `textContent`, never tokens, raw JSON, or identity headers.
Failed loads clear previous identity. No logout is implemented: exclude the unsafe
GET logout endpoint from the demo's exposed routes. The Auth-O-Tron link is only
navigation, not logout.

## Sessions and refresh

OAuth tokens remain server-side in OAuth2-proxy's Valkey session store, with no
Auth-O-Tron TokenStore involved. Browser cookies are opaque authentication
credentials and must be HttpOnly and Secure. Configure a 60-second Keycloak
access-token lifetime, 30-second OAuth2-proxy request-driven refresh interval,
and 15-minute session lifetime. Refresh is triggered by requests, not a
background timer. Wait beyond access-token expiry, then reload the page or press
**Reload identity** to exercise backend refresh; the displayed identity does not
prove rotation by itself. Keycloak administration and logout endpoints are not
exposed through the public demo ingress.

Keycloak's demo H2 database and Valkey storage are ephemeral; restarting them
logs users out. Generate credentials at runtime into namespace Secrets; do not
commit credentials, client secrets, or cookie secrets.

## Render and review

Run `render_sso.py` from the workspace root with `--chart`, `--ui-host`,
`--issuer-host`, `--app-host`, `--build-image`, `--trusted-proxy-addresses`,
`--secret-file`, and `--output-dir`. The Rust build image must use the same pinned
digest as the branding preview. Trusted proxy addresses must be individual host
addresses observed for the ingress peers, not broad network ranges.
Advertised load-balancer addresses alone may not be those peers: verify actual
connections from the playground's application before using the policy. Exact
Pod peer addresses configure client-address extraction and Keycloak's trusted
forwarding addresses, so those settings still require reassessment on churn. The BFF's
NetworkPolicy instead selects the verified controller namespace and labels,
so Pod-address churn does not widen or silently break that policy. Controller
metadata was inspected read-only with explicit permission; no resources are
applied outside the playground. Do not substitute all-namespace selectors.

The renderer emits `ui-resources.yaml` and private mode-0600
`sso-resources.yaml`, plus the whitelisted build archive. It applies nothing and
cannot select another namespace. The private credential file is generated once
and reused; do not print or commit it. The renderer enforces that the credential
file, output directory, and rendered output files are outside Git and outside
the preview's archived source directories and exact source filenames, including
in projects without Git metadata. These location guards run before credential
generation, source packaging, or Helm rendering, so generated credentials cannot
enter the public source ConfigMap through the compressed build archive.
The Keycloak import and proxy consume the same namespace Secret, and callback
registration/proxy configuration derive from one immutable profile.

### Credential rotation and coordinated replacement

Pod templates carry a SHA-256 checksum of only the Secret keys that each role
consumes: Keycloak uses the client secret and demo password; OAuth2-proxy uses
the client secret, cookie secret and Valkey password; Valkey uses its password.
Only digests appear in annotations, never credential values. Keep generated,
high-entropy credentials. The unchanged bundle renders identical checksums;
changing credentials replaces their consumers even though the Secret name stays
fixed. Nginx and the branding preview do not depend on these credentials.

These checksums trigger replacement, but do not coordinate multiple Deployments.
For rotation, schedule a demo outage and use the same explicit kubeconfig,
context and `authotron-playground` namespace as the apply procedure below:

1. Render and review a complete replacement bundle using a newly generated
   private credential file outside Git and the reserved source paths.
2. Scale `authotron-sso-oauth2-proxy`, `authotron-sso-keycloak` and
   `authotron-sso-valkey` to zero and wait until their old Pods have terminated.
3. Apply the new Secret first, then the complete rendered SSO bundle using the
   documented server-side apply procedure. The bundle restores one replica per
   component. Wait for all three Deployments to be ready before resuming use.
4. Start a fresh browser sign-in. Existing sessions and in-flight logins are lost.

Do not update only the Secret or rotate live consumers independently: environment
variables and Keycloak's imported realm remain at the old generation until Pod
replacement. Keycloak and Valkey use `Recreate`, preventing overlapping independent
ephemeral databases/session stores during ordinary updates. This deliberately
introduces downtime and state loss; it does not provide atomic cross-service
rotation. Both SSO and direct-login use the Valkey pin in `../shared_images.py`.

Get independent review, run the offline tests and required workspace checks,
then use server-side dry-run and apply with explicit kubeconfig, context and
`--namespace=authotron-playground`. All application resources belong only to that
namespace. Reuse the preview's documented SSA procedure; do not apply these
bundles to other namespaces. Valkey and the static upstream are private to the
BFF, and the BFF's ingress policy accepts only the configured ingress peers.

```bash
python3 -m unittest discover -s authotron/examples/browser-sso -p 'test_*.py' -v
ruff format --check authotron/examples/browser-sso
ruff check authotron/examples/browser-sso
```

This frontend does not implement Aviso API authorization, MCP authorization-server
flows, or Basic/API-key bridges.
