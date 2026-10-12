# Namespace-confined login preview

This disposable preview reuses the existing Helm chart's ConfigMap, Service,
Deployment and Ingress. It is restricted to **`authotron-palyground`** (the spelling
is intentional), and the renderer cannot select another namespace or invoke
`kubectl`. Python 3, PyYAML 6 and Helm are required. Prepare the chart's locked
dependencies with `helm dependency build` before rendering.

The renderer packages only explicit Cargo build inputs. Local configuration,
tooling, Git metadata and kubeconfig files are excluded; source symlinks are
rejected. The immutable source ConfigMap and Deployment annotation use a digest
of deterministic archive bytes. Application configuration comes from the public
`examples/login-ui/aviso.yaml` fixture, with the bind address adjusted for a Pod.
`render.py`'s `SOURCE_FILES` is the reviewed public build-input manifest, including
Rust modules, Lua scripts, base64 images, CSS, JavaScript and other embedded assets.
Packaging reads the current bytes of those exact paths, so local source edits and
source exports without Git metadata work identically. Missing inputs or symlinked
inputs/ancestors fail closed. Unlisted files are never enumerated or read: this
excludes `.env`, credential JSON, and even a credential disguised as a new `.rs`
file under a source directory. `RESERVED_SOURCE_DIRS` reserves private-output locations;
it does not authorize recursive packaging. When adding or renaming build inputs,
update the manifest after reviewing the paths as public source. Never put private
data in a listed input: the manifest authorizes its entire current content, not
only its committed bytes. The direct-login and SSO renderers share this policy.

No real providers, token store, metrics server or MongoDB are enabled. The
fixture's signing-secret value is public demo data, not a production credential.

## Render and review

Run from the Cargo workspace root. Resolve the official `rust:1.90-bookworm`
multi-platform image digest, for example with `docker buildx imagetools inspect`,
then supply the immutable reference:

```bash
python3 authotron/examples/kubernetes-login-preview/render.py \
  --chart ../auth-o-tron-chart \
  --host authotron-palyground.lumi.apps.dte.destination-earth.eu \
  --build-image docker.io/library/rust@sha256:<resolved-digest> \
  --output-dir /tmp/opencode/authotron-playground
```

The renderer creates `namespace.yaml`, `resources.yaml`, `source.tar.gz`,
`build.sh` and `application.yaml`; it applies nothing. Review the manifests and
run the build script locally in the **same pinned image** before applying.
Preserve the generated archive and script rather than copying build commands.

## Apply only to the playground

For this cluster, every Kubernetes command must explicitly select this kubeconfig,
context and namespace. Do not use these commands for another namespace:

```bash
export KUBECONFIG=~/.kube/lumi-rke2-cls.yaml
kubectl --kubeconfig="$KUBECONFIG" --context=lumi-rke2-cls \
  --namespace=authotron-palyground apply --server-side \
  --field-manager=authotron-playground-preview \
  -f /tmp/opencode/authotron-playground/namespace.yaml
kubectl --kubeconfig="$KUBECONFIG" --context=lumi-rke2-cls \
  --namespace=authotron-palyground apply --server-side --dry-run=server \
  --field-manager=authotron-playground-preview \
  -f /tmp/opencode/authotron-playground/resources.yaml
kubectl --kubeconfig="$KUBECONFIG" --context=lumi-rke2-cls \
  --namespace=authotron-palyground apply --server-side \
  --field-manager=authotron-playground-preview \
  -f /tmp/opencode/authotron-playground/resources.yaml
```

Server-side apply avoids placing a second copy of the source archive into a
client-side last-applied annotation, which would exceed annotation size limits.
Namespace creation is a separate operation targeting only the fixed name;
Namespace objects are forbidden in the application resource bundle.

## Operational limitations

- This is **only the branding UI shell**, not functional browser authentication.
- No image is built or published to a registry. An unprivileged init container
  builds the source using the public Rust image; runtime uses the same digest.
- Build/init requires registry and crates.io egress, up to two CPUs and 4 GiB of
  memory. Both containers have read-only roots, dropped capabilities and no
  mounted service-account token. Writable build storage is an 8 GiB `emptyDir`.
- Replacing the Pod rebuilds the source. This intentionally uses a large build
  image and a debug executable; it is not a production image strategy.
- The existing configuration checksum triggers rollout on branding changes;
  the source digest also triggers rollout when build inputs change.
- `/login` and `/login/` use Exact ingress paths (the app redirects `/login/` to
  `/login`) and `/static/` uses a Prefix for public
  CSS/images. `/favicon.ico` uses a literal ImplementationSpecific path because
  this cluster's NGINX admission rejects dotted filenames with Exact/Prefix
  types. No regex annotation is enabled; API routes and health probes stay internal.
- Ingress uses the observed NGINX class, DNS transport annotation and
  `letsencrypt-production` issuer reference. No issuer/controller is modified.
  Existing controllers may create DNS records and namespaced TLS resources;
  external DNS and certificate readiness must be verified after deployment.

## Offline checks

```bash
python3 -m unittest discover \
  -s authotron/examples/kubernetes-login-preview -p 'test_*.py' -v
ruff format --check authotron/examples/kubernetes-login-preview
ruff check authotron/examples/kubernetes-login-preview
```

The tests use synthetic source fixtures and mock Helm. They do not read a
kubeconfig, invoke Kubernetes commands, publish images or contact a cluster.
