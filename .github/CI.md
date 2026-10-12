# Server CI checks

`workflows/ci.yaml` runs on pushes and pull requests with read-only repository
permissions. All jobs fail normally on errors, including the Rust 1.88.0 MSRV
job. Repository branch protection must select the desired required checks.

## Rust

The stable job explicitly installs rustfmt and Clippy and runs:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace -- --test-threads=1
docker info
cargo test --locked -p authotron disposable -- --ignored --test-threads=1
```

The last command selects all three ignored Docker Valkey fixtures (browser
state, OAuth transactions, cross-replica OAuth HTTP). Cargo runs test binaries
in sequence and the harness runs one test thread. Fixtures own their disposable
containers; the workflow does not provision fixed-port services. Docker must be
available and able to pull the fixture images. Loopback tests run with proxy
variables unset and `NO_PROXY=127.0.0.1,localhost`.

The separate MSRV job runs
`cargo check --locked --workspace --all-targets --all-features` on toolchain
1.88.0. A release job builds in `rust:1.90-slim-bookworm`, matching the
Dockerfile, with `--locked`.

## Python and Helm

Python 3.12 installs the renderer dependency and the MCP project's actual
`test` extra, which supplies pytest and jsonschema alongside the pinned MCP SDK
and its runtime dependencies:

```sh
python -m pip install 'PyYAML>=6,<7' 'ruff==0.15.2' './authotron/examples/mcp-local[test]'
python -m pip check
python -m ruff check authotron/examples
python -m ruff format --check authotron/examples
python -m unittest discover -s authotron/examples/kubernetes-login-preview -p 'test_*.py' -v
python -m unittest discover -s authotron/examples/ecmwf-api-key -p 'test_*.py' -v
python -m unittest discover -s authotron/examples/browser-sso -p 'test_*.py' -v
cargo build --locked -p authotron --bin authotron
```

The renderer/private-path suites mock Helm and need no sibling chart checkout.
The additional preview smoke check
uses Helm **4.0.1** and an explicit `.ci-chart` checkout of
`ecmwf/auth-o-tron-chart` at the SHA pinned in `workflows/ci.yaml`. Its dependencies are vendored at that revision; no Helm repository
update or dependency download is needed. The synthetic build-image digest is
only rendered, never pulled or executed.

This immutable pin must be reachable in the chart's GitHub repository. It does
not track chart main or unpublished local fixes. Advancing the cross-repository
contract requires explicitly updating the SHA after the desired chart commit
is published. The pin checks the ordinary preview profile; chart-specific
regressions and contracts belong to chart CI.

## Cross-repository pins

The chart pin above lives only in `workflows/ci.yaml`; the chart repository's
reverse pin lives only in its `tests/application-contract.json`. The pins are
independent: the pinned chart may predate the chart's current version. Bump
them in this order:

1. Publish the server commit.
2. Regenerate the chart's application contract fixture against it.
3. Publish the chart commit.
4. Update the chart SHA in `workflows/ci.yaml`.

For MCP, set `AUTHOTRON_DEMO_BIN` to the absolute path of the built
`target/debug/authotron`, then run `python -m pytest -v` from
`authotron/examples/mcp-local`, including process tests otherwise skipped without
that environment variable. CI checks
that the binary is executable before pytest. Tests generate disposable TLS and
OAuth material and start local server/client processes; they require loopback
networking, not Kubernetes or private application configuration.

Helm state and preview output use the runner's temporary directory. CI needs
network access for actions, both source checkouts, Rust/Python dependencies,
Helm installation, and Docker fixture images. No agent-specific directory is a
prerequisite.

Checks report results in job logs; they do not measure line coverage or publish
test/preview artifacts. The preview smoke check validates rendered resources and
compiles its generated public source archive in a separate directory. This catches
missing modules/assets in the explicit packaging manifest. The server is then
built from the checkout for MCP tests.
