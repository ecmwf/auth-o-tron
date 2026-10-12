# Metrics

Auth-O-Tron exposes Prometheus-compatible metrics on a dedicated port for monitoring and observability, following the [ECMWF Codex Observability guidelines](https://github.com/ecmwf/codex/blob/main/Guidelines/Observability.md).

## Endpoint

Metrics are served at:

```
GET /metrics
```

By default, this endpoint is available on port `9090`. The format follows the Prometheus text exposition format.

## Metric Families

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `auth_requests_total` | Counter | result, realm | Total authentication requests |
| `auth_duration_seconds` | Histogram | result, realm | Authentication latency distribution |
| `auth_provider_attempts_total` | Counter | provider_name, provider_type, realm, result | Attempts per authentication provider |
| `auth_provider_duration_seconds` | Histogram | provider_name, provider_type, realm | Provider-specific latency |
| `augmenter_attempts_total` | Counter | augmenter_name, augmenter_type, realm, result | Token augmentation attempts |
| `augmenter_duration_seconds` | Histogram | augmenter_type, realm | Augmentation latency |
| `authotron_browser_logins_inflight` | Gauge | none | Locally admitted browser verification operations, including backend admission and augmentation |
| `authotron_browser_login_attempts_total` | Counter | flow, method, outcome | Completed/cancelled direct form POST attempts, including session persistence outcome |
| `authotron_browser_login_duration_seconds` | Histogram | flow, method, outcome | Form POST handler duration in seconds, through response creation or cancellation |

## Browser Login and HPA

Browser metrics reuse the existing per-process registry and `metrics.enabled`
endpoint behavior. They do not connect to Valkey for exporting metrics or change
API/CLI `auth_requests_total` semantics. The unlabeled in-flight gauge is exposed
at zero on idle processes, including pods with configured browser methods; no login
is needed before an HPA scrape sees it.

`flow` has exactly two values, determined by the method's provider type rather
than its id or label: `basic` for `plain` methods and `ecmwf-api-key` for
`ecmwf-api` methods. `method` is the configured `browser.id` (for example
`password` or `ecmwf-api-key`); at most 16 browser methods bound its values, and
it stays stable when providers are reordered or relabelled. Series appear on the
first POST to each method; they are not pre-initialised. `outcome` has the fixed
values `success`, `rejected`, `denied`, `malformed`, `origin`, `csrf`, `limited`,
`backend_unavailable`, `capacity`, `timeout`, `cancelled`. They describe the actual
POST result: successful verification followed by a failed session write is a
failure, not `success`. If a replacement form cannot be issued, its capacity,
quota or backend failure becomes the final outcome. `timeout` means the total
verification/augmentation deadline expired; upstream failures reported as generic
credential rejection remain `rejected`. `denied` means the credentials were valid
but the identity fails the current OAuth scope policy at login, so the flow ends
with an `access_denied` redirect. Cancellation is recorded when the handler
future is dropped before creating a response.

The counter counts attempts, the duration histogram measures seconds, and the
gauge counts active operations. Histogram timing starts on entering the POST
handler **after bounded form extraction**, includes Origin/CSRF checks, backend
admission, verification/augmentation, session persistence and any replacement-form
creation, and stops when a response is created or the handler is cancelled. It
excludes body transport/extraction and streaming the response to the browser.
The gauge covers only the local-admitted verification phase, starting before
Valkey quota/optional lease admission and ending after verification/augmentation
and optional lease release. It excludes session creation and locally rejected
requests. RAII guards reset it on success, error, timeout and cancellation.

No browser metric labels include credentials, usernames, session IDs, prefixes,
URLs, provider names, chooser labels or raw diagnostic strings. Each method id has
one fixed `flow`, and `outcome` is one of 11 fixed values (`success`, `rejected`,
`denied`, `malformed`, `origin`, `csrf`, `limited`, `backend_unavailable`,
`capacity`, `timeout`, `cancelled`), so there are at most 16 methods × 11 outcomes
per counter/histogram family. `denied` is recorded only when the `access_denied`
redirect is issued; if a concurrent request already consumed the transaction the
400 response is counted as `rejected`. Server-side clock or configuration faults
while building the authenticated context (`InvalidTime`, `Configuration`) return
503 and are counted as `backend_unavailable`. Histogram `le` labels are the fixed
Prometheus bucket boundaries, not caller input. Prometheus attaches deployment
identity such as `namespace` and `pod` as **target labels**, not application labels.

`max_inflight_logins` is the per-pod budget; optional
`max_shared_inflight_logins` is an aggregate Valkey lease cap. Global rate quotas
and form/session capacities remain separate limits. The gauge is a useful custom
HPA signal for local saturation; shared-cap or global-rate rejection can prevent
added replicas from increasing throughput. Short admission failures may also be
missed between scrapes: monitor `limited` attempts and backend errors alongside
CPU, latency and the gauge. Longer session TTLs do not make this gauge rise, but
increase retained-session memory and credential-revocation lag (up to 24 hours
at the maximum configured TTL).

Custom-metric HPA requires an external adapter exposing
`authotron_browser_logins_inflight` through `custom.metrics.k8s.io` as a **Pods**
metric. CPU-based HPA does not need this adapter; the chart does not install one.
For a Prometheus Adapter, an illustrative rule preserving per-pod identity is:

```yaml
seriesQuery: 'authotron_browser_logins_inflight{namespace!="",pod!=""}'
resources:
  overrides:
    namespace: {resource: namespace}
    pod: {resource: pod}
name:
  matches: '^authotron_browser_logins_inflight$'
  as: authotron_browser_logins_inflight
metricsQuery: 'max(<<.Series>>{<<.LabelMatchers>>}) by (<<.GroupBy>>)'
```

The HPA metric name must be `authotron_browser_logins_inflight`; its target is a
per-pod `AverageValue` active-operation count. For example, a target below a tuned
local budget of 64 leaves headroom; neither that budget nor any example target is
a benchmark claim. Select the target, scrape interval, stabilization and scale
policies using observed workload and upstream capacity. Normal request shutdown
releases optional leases; crash/scale-down recovery uses their deadline plus the
fixed two-second grace. This is expiry-based recovery, not perfect fencing for a
suspended process. The live fixture is plaintext loopback Valkey; TLS and external
HA deployment behavior still require deployment-specific verification.

## Label Values

**result** (auth_requests_total): `success`, `no_auth_header`, `invalid_header`, `all_failed`

**result** (auth_provider_attempts_total): `success`, `error`, `timeout`

**result** (augmenter_attempts_total): `success`, `error`

**realm**: The configured authentication realm name, or `unknown` when the request fails before realm resolution

**provider_name**: Identifier for the authentication provider

**provider_type**: Type of provider (plain, jwt, ecmwf-api, efas-api, openid-offline, ecmwf-token-generator)

**augmenter_name**: Identifier for the token augmenter

**augmenter_type**: Type of augmenter

## PromQL Examples

### Request Rate

```promql
rate(auth_requests_total[5m])
```

### Authentication Latency (99th Percentile)

```promql
histogram_quantile(0.99, rate(auth_duration_seconds_bucket[5m]))
```

### Error Rate by Realm

```promql
rate(auth_requests_total{result!="success"}[5m])
```

### Slow Providers (95th Percentile)

```promql
histogram_quantile(0.95, rate(auth_provider_duration_seconds_bucket[5m]))
```

### Provider Success Rate

```promql
rate(auth_provider_attempts_total{result="success"}[5m])
```

## Alerting Recommendations

Consider alerting on:

- High error rates: `rate(auth_requests_total{result!="success"}[5m]) > 0.1`
- Elevated latency: `histogram_quantile(0.95, rate(auth_duration_seconds_bucket[5m])) > 1.0`
- Provider failures: `rate(auth_provider_attempts_total{result=~"error|timeout"}[5m]) > 0`
