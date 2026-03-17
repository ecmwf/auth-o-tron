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

## Both Ports (8080 and 9090)

### GET /health

Health check for load balancers and monitoring.

| Aspect | Details |
|--------|---------|
| **Ports** | Both 8080 and 9090 |
| **Success (200)** | Text: `OK` |
| **Use** | NGINX checks, K8s probes |
| **Note** | Available on the metrics port only when `metrics.enabled: true` |

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

| Method | Path | Port | Auth | Purpose |
|--------|------|------|------|---------|
| GET | /authenticate | 8080 | Credentials | Main auth, returns JWT |
| GET | /token | 8080 | JWT | Create opaque token |
| GET | /tokens | 8080 | JWT | List tokens |
| DELETE | /token/{token} | 8080 | JWT | Delete token |
| GET | /providers | 8080 | None | List providers |
| GET | /augmenters | 8080 | None | List augmenters |
| GET | /health | Both | None | Health check |
| GET | /metrics | 9090 | None | Prometheus metrics |
| GET | / | 8080 | None | Service info |
