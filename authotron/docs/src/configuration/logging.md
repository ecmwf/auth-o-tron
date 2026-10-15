# Logging

The `logging` section configures how Auth-O-Tron outputs diagnostic and operational information. Proper logging is essential for debugging, monitoring, and auditing.

## Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| level | string | info | Minimum log level to output |
| format | string | console | Output format: "json" or "console" |
| service_name | string | authotron | Service identifier in logs |
| service_version | string | (from crate) | Version identifier in logs |

## Log Levels

The `level` field controls which messages are emitted. Messages at the configured level and above are logged.

| Level | Description |
|-------|-------------|
| trace | Very detailed internal state information |
| debug | Information useful for debugging |
| info | General operational information |
| warn | Warning conditions that are not errors |
| error | Error conditions |

## Log Formats

### Console Format

The console format outputs human-readable log lines with color coding:

```
2024-01-15T10:30:00.123Z  INFO auth_o_tron::server: Server started on 0.0.0.0:8080
```

### JSON Format

The JSON format outputs structured logs following OpenTelemetry conventions, aligned with the [ECMWF Codex Observability guidelines](https://github.com/ecmwf/codex/blob/main/Guidelines/Observability.md). This is recommended for production deployments and integration with log aggregation systems.

JSON format includes these fields:

| Field | Description |
|-------|-------------|
| severityText | Log level as text (INFO, ERROR, etc.) |
| severityNumber | Numeric log level code |
| body | The log message |
| timestamp | ISO 8601 timestamp |
| resource | Resource attributes including service name and version |
| attributes | Additional structured attributes |

Example JSON log entry:

```json
{
  "severityText": "INFO",
  "severityNumber": 9,
  "body": "Server started",
  "timestamp": "2024-01-15T10:30:00.123Z",
  "resource": {
    "service.name": "auth-o-tron",
    "service.version": "1.2.0"
  },
  "attributes": {
    "server.host": "0.0.0.0",
    "server.port": 8080
  }
}
```

## Event Naming

Auth-O-Tron uses structured event naming following the pattern `domain.component.action`. Events are grouped by domain, allowing you to filter and analyze related operations.

| Domain | Description |
|--------|-------------|
| auth | Authentication flow events |
| providers | Provider lifecycle and validation |
| augmenters | Augmenter lifecycle and enrichment |
| store | Token store operations |
| routes | HTTP route handler events |
| startup | Server initialization events |
| browser | Browser sign-in methods |
| oauth | OAuth endpoints, refresh-token families and upstream grants |
| valkey | Shared Valkey connections of the browser and OAuth stores |

## OAuth Audit Events

Refresh-token family events name the OAuth `client_id`, the login `method` id, the
`realm` and `username` (as `auth.request.authenticated` does), and `family`: the first
12 hex digits of SHA-256 over the family id, which correlates a family's lines without
revealing the id. Tokens, codes and sealed upstream grants are never logged.

`oauth.refresh_token.family_revoked` records every revoked family with its `reason`:

| Reason | Level | Cause |
|--------|-------|-------|
| `client_revoke` | INFO | The client revoked one of the family's tokens (`/oauth/revoke`) |
| `user_revoke` | INFO | The user revoked the login on the account page |
| `admin_revoke` | INFO | An operator revoked it with `authotron admin logins revoke` |
| `reuse_detected` | WARN | An already-rotated refresh token was presented again |
| `per_user_cap` | INFO | A newer sign-in exceeded `max_refresh_token_families_per_user` |
| `client_disabled` | INFO | The client no longer has refresh tokens enabled |
| `method_removed` | INFO | The login method is gone, or no longer an OIDC method for a coupled family |
| `lifetime_exceeded` | INFO | The absolute lifetime, possibly shortened since sign-in, has passed |
| `account_removed` | INFO | The password account is no longer configured |
| `upstream_invalid_grant` | WARN | The identity provider refused the upstream refresh |
| `upstream_unusable` | WARN | The sealed upstream grant is missing or cannot be opened |
| `identity_changed` | WARN | The refreshed identity no longer matches the family |

Families that expire, or are lost with backend data, are not logged.

| Event | Level | Meaning |
|-------|-------|---------|
| `oauth.refresh_token.retried` | INFO | A family's previous token, presented again within the client's retry window, was answered with the current token (`retries`: answers of this rotation so far) |
| `oauth.refresh_token.retry_pattern` | WARN | Three or more consecutive rotations of the family were each answered again (`streak`): a token shared by two holders refreshing in step looks like this |

Families coupled to an OIDC offline session also log their upstream grant, with the
same identifiers (`family` is `none` for a sign-in's grant that never reached a
family):

| Event | Level | Meaning |
|-------|-------|---------|
| `oauth.upstream.refresh_rejected` | WARN | The provider answered `invalid_grant`; the family ends with `upstream_invalid_grant` |
| `oauth.upstream.refresh_unavailable` | WARN | The provider could not refresh the grant (`reason`: `unavailable`, `invalid_response`, `client_rejected`); the family is kept |
| `oauth.upstream.unopenable` | WARN | The sealed grant cannot be opened with the configured keys |
| `oauth.upstream.identity_changed` | WARN | The refreshed `sub` or username differs |
| `oauth.upstream.id_token_unverified`, `oauth.upstream.identity_missing` | WARN | The refreshed ID token cannot be verified or is missing; the family is kept |
| `oauth.upstream.lock_busy` | WARN | Another refresh of the family held its lock |
| `oauth.upstream.rotation_lost` | ERROR | The provider rotated the grant but the new token could not be stored |
| `oauth.upstream.reseal_failed` | WARN | The provider kept its token, sealed under an older key, and storing it under the active key failed; the family is kept |
| `oauth.upstream.revocation_sent` | INFO | The provider's revocation endpoint accepted the grant |
| `oauth.upstream.revocation_unsupported` | INFO | The provider advertises no revocation endpoint |
| `oauth.upstream.revocation_failed` | WARN | The revocation request failed (`reason`) |
| `oauth.upstream.revocation_skipped` | WARN | Not revoked: the queue was full, or the grant can no longer be opened |

Revocations run on a background worker; their lines carry the span of the request
that ended the grant.

## Example Configuration

**Development (console output, debug level):**

```yaml
logging:
  level: debug
  format: console
```

**Production (JSON output, info level):**

```yaml
logging:
  level: info
  format: json
  service_name: auth-o-tron-prod
  service_version: 1.2.0
```

**Minimal configuration:**

```yaml
logging:
  level: warn
```
