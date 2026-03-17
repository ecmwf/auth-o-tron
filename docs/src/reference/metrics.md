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
