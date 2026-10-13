# Keycloak demo SSO

A disposable Keycloak realm that the login playground (`../ecmwf-api-key`) offers
as its `demo-sso` OpenID Connect sign-in method. It contains no real Aviso data
or accounts.

## Realm

`render_sso.py` renders realm `aviso-demo` at
`https://<issuer-host>/realms/aviso-demo`:

- Client `authotron-playground`: confidential, PKCE S256, the single redirect URI
  `https://<ui-host>/login/method/demo-sso/callback`, default scopes `basic`,
  `profile` and `email`, optional scope `offline_access`. Its secret is the bundle
  key `authotron-client-secret`; pass the bundle file to
  `../ecmwf-api-key/render_api_key.py --sso-secret-file`.
- Strict refresh-token rotation (`revokeRefreshToken`, reuse 0) and offline
  sessions of 30 days idle and at most 90 days, matching the playground's OAuth
  refresh-token lifetimes. Browser SSO sessions last 15 minutes; access tokens 60
  seconds.
- User `alice` with a fixed id, so her `sub` (the Auth-O-Tron username) survives
  Keycloak restarts, and the default roles, which include `offline_access`. Her
  password is the bundle key `demo-user-password`.
- Client `authotron-e2e-admin`: a service account with `realm-management`
  `manage-users` and `view-users`, secret `e2e-admin-secret`, for end-to-end
  checks such as disabling `alice` or listing her offline sessions. The admin API
  has no ingress route; reach it only through
  `kubectl port-forward service/authotron-sso-keycloak 8080`.

Keycloak runs `start --optimized` with the development file database in an
`emptyDir` and re-imports the realm on every start. A Keycloak restart therefore
ends every SSO and offline session; Auth-O-Tron refresh-token families coupled to
offline sessions end at their next refresh, and users sign in again.

## Render and review

Run from the workspace root:

```bash
python3 authotron/examples/browser-sso/render_sso.py \
  --ui-host authotron-playground.lumi.apps.dte.destination-earth.eu \
  --issuer-host authotron-sso-playground.lumi.apps.dte.destination-earth.eu \
  --trusted-proxy-addresses <ingress peer addresses> \
  --secret-file /tmp/opencode/authotron-sso-secrets.json \
  --output-dir /tmp/opencode/authotron-sso
```

Trusted proxy addresses must be individual host addresses of the ingress peers
(`/32` or `/128`), not network ranges; they configure Keycloak's trusted
forwarding addresses and need reassessment when the ingress pods move.

The renderer writes only the private, mode-0600 `sso-resources.yaml`: the realm
ConfigMap, the Keycloak Deployment (non-root, read-only root filesystem, no
service-account token, `Recreate`), its ClusterIP Service, an Ingress with exact
issuer routes (discovery, authorization, token, revocation, keys, userinfo,
login actions and static resources; no logout or admin paths), and the Secret
`authotron-browser-sso`. It applies nothing and cannot select another namespace
than `authotron-playground`.

The private credential file holds `demo-user-password`, `authotron-client-secret`
and `e2e-admin-secret`, each 32 random bytes as URL-safe text. It is generated
once, reused, and must stay outside Git and outside the login preview's archived
source paths; do not print or commit it. A bundle missing one of the keys gains
it on the next render, other values are kept. Bundles from the retired
OAuth2-proxy demo still hold `client-secret`, `cookie-secret` and
`valkey-password`; remove those three keys before rendering.

The realm references credentials only as `${...}` placeholders that Keycloak
substitutes from the Secret's environment variables. The pod template carries a
SHA-256 checksum of the credentials Keycloak consumes, so changing one replaces
the pod; only digests appear in annotations.

Get independent review, run the offline tests and required workspace checks, then
use server-side dry-run and apply with explicit kubeconfig, context and
`--namespace=authotron-playground`. Apply the Secret before the Deployment.

```bash
python3 -m unittest discover -s authotron/examples/browser-sso -p 'test_*.py' -v
ruff format --check authotron/examples/browser-sso
ruff check authotron/examples/browser-sso
```
