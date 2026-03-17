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
