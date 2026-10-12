# Direct browser-login playground

This disposable renderer enables direct login at `/login`. API-key and optional
Basic forms open in an accessible dialog without leaving the branded chooser;
SSO remains a separate redirect. Standalone credential pages remain available as
a JavaScript-free fallback. API-key credentials submit to `/login/ecmwf-api-key`
and Basic credentials to `/login/basic`; the authenticated identity is shown at
`/login/account`. The renderer targets the backend interface in the source being
packaged; offline renderer checks do not establish backend runtime behavior.
Browser sessions default to **300 seconds**, with configurable absolute expiry
and no sliding refresh. This is
an identity view; an Aviso application callback is not configured. The token store
is disabled. The browser route does not issue a JWT.

The namespace is fixed to **`authotron-palyground`** (intentional spelling). The
renderer imports the existing Kubernetes login-preview renderer and uses its
provider-empty public `login-ui/aviso.yaml` fixture. By default it enables exactly:

```yaml
type: ecmwf-api
name: ECMWF API Provider
realm: ecmwf
uri: https://api.ecmwf.int/v1
```

The provider URI is configuration authority, never a form input. Public origin is
exactly `https://<validated-host>`. By default no browser sign-in link is added;
`--browser-start-url` can preserve a separate approved SSO option alongside the
direct API-key button. It never changes API-key validation or adds a Keycloak
dependency to that path. The host-based browser cookie and backend origin
checks use that origin. No ECMWF API key is placed in cluster configuration.
Both direct methods use the single `ui.browser_session` block for this origin and
the session lifetime; `ui.ecmwf_api_key` and `ui.basic` select only provider names.
Older per-provider origin/lifetime settings must be moved to that shared block.
The direct profile explicitly selects `backend: {type: memory}`; the five-resource
branding baseline keeps Valkey disabled and has no direct-login configuration.
The official Aviso logo is served from `/static/aviso-logo.png` on the same origin
and is retained on the chooser, credential and account pages. The embedded asset
requires no browser request to an external logo host, including during sign-in.

## Render

Requirements: Python 3, PyYAML 6, Helm, and a chart with its locked dependencies
already prepared. Run from the Cargo workspace root. Supply the resolved digest
of the official Rust build image (for example `rust:1.90-bookworm`):

```bash
python3 authotron/examples/ecmwf-api-key/render_api_key.py \
  --chart ../auth-o-tron-chart \
  --host authotron-palyground.lumi.apps.dte.destination-earth.eu \
  --build-image docker.io/library/rust@sha256:<resolved-digest> \
  --secret-file /tmp/opencode/ecmwf-browser-signing.json \
  --output-dir /tmp/opencode/ecmwf-direct-playground
```

To show both choices in the playground, add:

```bash
--browser-start-url 'https://aviso-browser-palyground.lumi.apps.dte.destination-earth.eu/oauth2/start?rd=%2Faccount'
```

The configured URL must be an approved HTTPS browser-client start endpoint;
request parameters do not choose it. Existing direct sessions do not hide the
chooser when alternative sign-in actions are present.

To add Basic login alongside the API-key button and optional SSO link, also add:

```bash
--basic-secret-file /tmp/opencode/authotron-basic-demo.json
```

This creates a private, reusable JSON file with username `browser-demo` and a
random 32-byte password encoded as URL-safe text. The same ownership, mode,
single-link and no-symlink rules as the signing file apply. Never put this file
in Git or print its password in deployment logs. Basic is a separate Auth-O-Tron
plain-provider login, not a Keycloak account or an HTTP Basic browser dialog.

With this option, the public ConfigMap contains only the non-secret configuration
and an empty Basic user list. The complete runtime configuration is mounted from
the existing Opaque Secret's `config.yaml` key; only that private configuration
contains the generated password. The source archive and public ConfigMaps never
contain it. The Basic provider supplies no roles itself: the configured
`plain_advanced` augmenter adds `demo-user` and `augmented`, plus the demo email
`browser-demo@example.invalid`, after authentication. These are demonstration
roles, not production Aviso entitlements. API-key identities pass through the same
augmentation pipeline; this fixture does not invent ECMWF role assignments.

### Shared browser state and expiry

To render dedicated Valkey-backed browser state and two application replicas, add:

```bash
--valkey-secret-file /tmp/opencode/authotron-browser-valkey.json \
--replicas 2 \
--session-ttl-seconds 300 \
--transaction-ttl-seconds 300
```

`--replicas` defaults to 1 and must be a positive integer. Values above 1 require
`--valkey-secret-file`. Session expiry accepts 60–86400 seconds; transaction
(login form) expiry accepts 30–900 seconds. Both default to 300. Longer session
expiry extends the time an authenticated identity can remain usable after
upstream credentials or permissions change; choose a short expiry appropriate to
revocation needs. Expiry is absolute, not renewed by viewing the account page.

The Valkey file contains **only `valkey-password`**, a generated canonical
43-character URL-safe encoding of 32 random bytes, reused on subsequent renders.
It follows the signing/Basic file rules below. All credential file paths must be
distinct, cannot overlap directory ancestry, and cannot collide with the output
bundle or archived sources. The renderer never reads SSO password artifacts and
does not reuse the SSO service or token store.

The shared `ui.browser_session` configuration is:

```yaml
public_origin: https://<validated-host>
session_ttl_seconds: 300
transaction_ttl_seconds: 300
backend:
  type: valkey
  url: redis://authotron-login-preview-browser-valkey:6379/0
  key_prefix: authotron:browser:v1:authotron-login-preview
  connect_timeout_ms: 2000
  operation_timeout_ms: 1000
```

The backend password is supplied only through Secret-backed
`AOT_UI__BROWSER_SESSION__BACKEND__PASSWORD`, never in application configuration
YAML or the URL. Without Basic, the application still mounts its public ConfigMap;
with Basic, its full runtime configuration remains in the Secret, and the public
mirror differs only in the Basic user list.

Other server configuration policy fields remain configurable in
`ui.browser_session`; this renderer leaves their Rust defaults in effect:

| Field | Default |
| --- | ---: |
| `max_forms` | 1024 |
| `max_sessions` | 1024 |
| `max_forms_per_window` | 120 |
| `max_logins_per_window` | 60 |
| `rate_window_seconds` | 60 |
| `max_inflight_logins` | 8 per application pod |
| `max_shared_inflight_logins` | unset; no shared concurrency cap |
| `verification_timeout_seconds` | 10 |

Concurrency is per pod so adding replicas can increase verification capacity.
An optional shared cap protects upstream services when configured; shared rate
limits still apply across all replicas. These conservative playground defaults
are not production throughput claims. Application requests using an established
session are not login verification attempts.

This renderer uses a fixed replica count, not HPA. The chart separately supports
optional CPU or active-login HPA; see the chart README for resource requests,
metrics-server and custom metrics adapter requirements. The per-pod active-login
gauge is `authotron_browser_logins_inflight`. Publishing it alone does not make
Kubernetes consume it as a scaling signal.

The backend contract uses Valkey for shared sessions, transactions and browser
quotas across replicas, with no memory fallback on backend failure. Backend
implementation and cross-replica behavior require independent runtime review.
Lost backend state forces a new login. Replacement uses `Recreate`, deliberately
interrupting the backend rather than routing requests to two independent caches;
users must sign in again after replacement. This standalone Valkey deployment is a
single point of failure, **not HA**; it has no persistence or failover.

Valkey uses the official **9.1.2** digest already verified in
`browser-sso/render_sso.py`, but has its own Deployment, ClusterIP Service and
NetworkPolicy. Only same-namespace Auth-O-Tron preview pods matching the full
application labels may connect on TCP 6379; there is no namespace wildcard or
public Valkey port. Enforcement requires the cluster's NetworkPolicy support.
The server command is `valkey-server /etc/valkey/valkey.conf`, with no password in
argv. Only `valkey.conf` is mounted from the combined Secret, read-only with mode
0440 and group 1000; signing and private Basic configuration are not mounted into
Valkey. Health probes use `VALKEYCLI_AUTH` from the password Secret key, not an
argv password. The private config requires authentication, binds `0.0.0.0`, uses
protected mode, disables AOF and snapshots, sets 128 MB/noeviction, logs to stdout,
and runs in the foreground with `/data` on `emptyDir`. UID/GID 1000, read-only
root, dropped capabilities, RuntimeDefault seccomp, no service-account token and
a 256 MiB memory limit constrain the pod.

### Opt-in OAuth authorization server

OAuth is off unless `--oauth-secret-file` is given. Without it, the rendered
bundle is byte-identical to the profiles above. OAuth state shares the browser
backend, so the flag requires `--valkey-secret-file`; combining it with the memory
backend is rejected before any credential file is created. Example (Basic optional):

```bash
python3 authotron/examples/ecmwf-api-key/render_api_key.py \
  --chart ../auth-o-tron-chart \
  --host authotron-palyground.lumi.apps.dte.destination-earth.eu \
  --build-image docker.io/library/rust@sha256:<resolved-digest> \
  --secret-file /tmp/opencode/authotron-api-key-signing.json \
  --basic-secret-file /tmp/opencode/authotron-basic-demo.json \
  --valkey-secret-file /tmp/opencode/authotron-browser-valkey.json \
  --oauth-secret-file /tmp/opencode/authotron-oauth-signing.json \
  --output-dir /tmp/opencode/authotron-api-key
```

The OAuth file holds **only `private-key-pem`**: an unencrypted RSA-2048 PKCS8 PEM
generated on first use with mode `0600` and reused afterwards. It follows the same
ownership, single-link, no-symlink, outside-Git/archive and distinct-path rules as
the other credential files. Only canonical RSA-2048 (e=65537) PKCS8 PEM is accepted.
Generation and validation use the Python `cryptography` package, which is needed only
with this flag. Deleting the file rotates the key on the next render.

The key is stored as `data.oauth-signing.pem` in the existing Opaque Secret and
mounted read-only (mode 0440, group 1000) at `/run/secrets/oauth/signing.pem`,
only into the application container. Configuration references the path, never the
PEM. `active_kid` is `playground-<first 16 hex of SHA-256(public SPKI DER)>`, so a
new key changes the configuration checksum; the pod template additionally carries
`checksum/oauth-signing-key` (a SHA-256 digest only). The rendered fragment is:

```yaml
oauth:
  enabled: true
  issuer: https://authotron-palyground.lumi.apps.dte.destination-earth.eu/
  signing:
    active_kid: playground-<sha256-prefix>
    keys:
      - kid: playground-<sha256-prefix>
        private_key_file: /run/secrets/oauth/signing.pem
  clients:
    - client_id: mcp-local
      display_name: Local MCP demo
      application_type: native
      redirect_uris: ["http://127.0.0.1:49152/callback"]
      resources:
        - resource: https://127.0.0.1:8444/mcp
          scopes: [mcp:read]
  resources:
    - resource: https://127.0.0.1:8444/mcp
      allowed_realms: [ecmwf, browser-demo] # browser-demo only with Basic
      scopes:
        - name: mcp:read
          required_roles: []
```

Clients must use the issuer
**`https://authotron-palyground.lumi.apps.dte.destination-earth.eu/`** (with the
trailing slash), which matches `ui.browser_session.public_origin`. Its metadata is
at `/.well-known/oauth-authorization-server`. Other OAuth settings keep server
defaults (for example 1024 transactions, 300-second tokens).

**Security notes.**

- `required_roles: []` is deliberate because the MCP tool is synthetic: **any
  successfully authenticated playground user** (any valid ECMWF API key, or the
  Basic demo user) can obtain an `mcp:read` token for resource identifier
  `https://127.0.0.1:8444/mcp`. Tokens therefore carry `roles: []`; mcp-local's
  remote settings set `"required_role": null` so its resource server accepts
  them (a test guards that both sides agree). Do not reuse this policy for a
  real resource.
- The resource identifier is a loopback URL for the local MCP example; any other
  service accepting tokens with that audience and this issuer would accept them.
- The bundle now also contains the RSA private key (Base64 is not encryption).
  The renderer never prints it; it never appears in ConfigMaps, the source
  archive, annotations or command output.
- Only the public client registration above exists; there is no dynamic
  registration, refresh token or confidential client.

The Ingress adds exactly `/oauth/authorize`, `/oauth/continue`, `/oauth/consent`,
`/oauth/token` and `/oauth/jwks` (Exact) and
`/.well-known/oauth-authorization-server` (ImplementationSpecific, because NGINX
admission rejects dotted paths with Exact/Prefix; NGINX treats it as a prefix, and
unknown suffixes return 404 from the application). No other API path is exposed.
The plain `kubernetes-login-preview` Ingress is unchanged.

The secret file's parent directory must already exist. The file must be outside
Git. On first use, the renderer generates 32 random bytes encoded as URL-safe
text and persists a JSON object with **only `jwt-secret`**, mode `0600`. Subsequent
runs reuse that value. Files must be owned by the current process user, regular,
single-link, and mode `0600`; symlinks and symlink ancestry are rejected. Keep the
file private and available for repeated renders. Removing it creates a different
signing credential on the next render. A signing-secret checksum on the pod
template ensures that changing this environment credential replaces the pods.
Credential files and the output directory must be outside Git and outside the
archived source directories, including when the project has no `.git` directory.

Output is only `resources.yaml`, mode `0600`, containing **six resources** by default:

1. Public application ConfigMap, with `jwt.secret: ''`.
2. Deployment retaining the baseline non-root source-build pod.
3. Internal ClusterIP Service.
4. Ingress with the existing `/login` Exact, `/static/` Prefix and `/favicon.ico`
   ImplementationSpecific paths, plus exactly `/login/ecmwf-api-key` and
   `/login/account`, both Exact, and optional `/login/basic` Exact.
5. Immutable public source-archive ConfigMap.
6. Opaque Secret `authotron-ecmwf-browser`, using Base64 `data.jwt-secret` and,
   when Basic is enabled, `data.config.yaml`. With Valkey it additionally holds
   `data.valkey-password` and `data.valkey.conf`. With OAuth it additionally
   holds `data.oauth-signing.pem`.

The shared profile contains **nine resources**: these six plus Deployment,
ClusterIP Service and NetworkPolicy, each named
`authotron-login-preview-browser-valkey`. No extra Namespace, RBAC, Ingress or
storage resource is created.

The application receives `AOT_JWT__SECRET` exclusively through that Secret's
`jwt-secret` key, preserving `AOT_CONFIG_PATH`. The public fixture's demo signing
value is removed before rendering. Although this browser route does not issue
JWTs, the enabled provider must never use a publicly known signing credential.
**Base64 is not encryption:** the bundle contains the actual signing credential;
keep it private. With Basic enabled it also contains the demo password, and with
Valkey it contains its password and private server config. The renderer never
prints credentials.

## Resource contract and review

All six or nine objects explicitly target the fixed namespace. No Namespace,
RBAC, host-path mount, or additional public API route is accepted. Only the exact
profile's volumes, environment references and resources are accepted. The full
bundle is compared against the narrowly transformed baseline,
including exact resource kinds/names, configuration, pod, ingress and Secret.
The existing source SHA annotation and hash-named immutable source ConfigMap
remain intact. `checksum/config` is recomputed from the actual serialized
runtime configuration bytes, including the private configuration when Basic is
enabled. The public configuration is derived from the same object with only the
Basic user list removed; it is not a second runtime configuration source.
Signing and private runtime configuration checksums replace application pods on
rotation. Separate SHA-256 password/config checksums replace both application
and Valkey pods when Valkey credentials change; annotations contain hashes only.

The source archive includes only the baseline's public Cargo build inputs. The
init container builds that source into the shared `emptyDir`, using the same
pinned official Rust image as runtime, UID 1000, read-only roots, dropped
capabilities and no service-account token. It retains the baseline ports,
resource limits and probes. Replacing a pod rebuilds the debug executable;
registry and crates.io egress are needed. No image is published.

Ingress preserves the baseline NGINX class, DNS annotations and issuer reference.
Its TLS Secret remains the existing same-namespace
`authotron-login-preview-tls` for the selected host. No issuer is added.

The renderer applies nothing. The existing namespace must already be present.
After review, the deployment owner can use server-side apply with a stable field
manager; this avoids duplicating the source archive in client-side last-applied
annotations. With unchanged source, inputs and retained signing file, repeated
renders produce the same bundle. Review the dedicated Secret/environment
reference before public deployment. Browser-route privacy and security review
remain the responsibility of the upstream implementation owner.

### Future independent review checklist

Before any deployment, the deployment owner should independently verify:

1. The packaged backend accepts the tagged memory/Valkey interface and enforces
   absolute session/transaction expiry, logout and failed-backend behavior.
2. The rendered six/nine exact resource IDs and references remain entirely in
   `authotron-palyground`, and the dedicated Valkey policy is enforced by the CNI.
3. Credentials occur only in private files/Secret data and Secret-backed env;
   source archives, public configuration, argv, logs and annotations do not leak them.
4. Two application replicas share form consumption, sessions and quotas, and
   losing/restarting Valkey requires new login without memory fallback or HA assumptions.
5. Signing, Basic and Valkey rotation changes the appropriate rollout hashes;
   AVISO logo, dialogs, SSO action, Basic augmentation and expiry/logout flows work.

## Offline verification

```bash
python3 -m unittest discover \
  -s authotron/examples/ecmwf-api-key -p 'test_*.py' -v
ruff format --check authotron/examples/ecmwf-api-key
ruff check authotron/examples/ecmwf-api-key
```

Tests construct explicit synthetic public fixtures and mock Helm. They never
read local configuration, contact ECMWF, use real API keys, or access a cluster.
