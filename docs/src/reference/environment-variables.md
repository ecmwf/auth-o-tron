# Environment Variables

Auth-O-Tron requires a YAML configuration file, but any value in it can be overridden through environment variables. This makes it easy to customize deployments in containers and cloud environments without modifying the base config file.

## Core Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AOT_CONFIG_PATH` | Path to the YAML configuration file | `./config.yaml` |

## Configuration Override Convention

All configuration values from the YAML file can be overridden via environment variables using the `AOT_` prefix and double underscores to represent nesting.

The pattern is: `AOT_<SECTION>__<KEY>`

For nested sections, add more double underscores: `AOT_<SECTION>__<SUBSECTION>__<KEY>`

## Common Overrides

| Variable | Config Path | Example Value |
|----------|-------------|---------------|
| `AOT_SERVER__HOST` | server.host | `0.0.0.0` |
| `AOT_SERVER__PORT` | server.port | `8080` |
| `AOT_METRICS__ENABLED` | metrics.enabled | `true` |
| `AOT_METRICS__PORT` | metrics.port | `9090` |
| `AOT_JWT__ISS` | jwt.iss | `my-issuer` |
| `AOT_JWT__SECRET` | jwt.secret | `my-secret` |
| `AOT_JWT__EXP` | jwt.exp | `3600` |
| `AOT_LOGGING__LEVEL` | logging.level | `info` |
| `AOT_LOGGING__FORMAT` | logging.format | `json` |
| `AOT_AUTH__TIMEOUT_IN_MS` | auth.timeout_in_ms | `5000` |
| `AOT_STORE__ENABLED` | store.enabled | `false` |

## Precedence

Environment variables take precedence over YAML configuration values. The loading order is:

1. Load YAML configuration from `AOT_CONFIG_PATH`
2. Merge environment variable overrides
3. Deserialize into the versioned config (v1 configs are converted to v2)
4. Fail fast on parse errors or invalid values (e.g., port collision)

This means you can maintain a base configuration file and selectively override specific values per environment using environment variables.

## Example

```bash
export AOT_CONFIG_PATH=/etc/auth-o-tron/config.yaml
export AOT_SERVER__PORT=8080
export AOT_JWT__SECRET=$(cat /run/secrets/jwt_secret)
export AOT_METRICS__ENABLED=true

./authotron
```
