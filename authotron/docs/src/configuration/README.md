# Configuration Overview

Auth-O-Tron is configured through a YAML file. By default, it looks for `./config.yaml` in the working directory. You can specify a different path using the `AOT_CONFIG_PATH` environment variable.

## Config File Location

```bash
# Default location
./config.yaml

# Custom location via environment variable
export AOT_CONFIG_PATH=/etc/auth-o-tron/config.yaml
```

## Configuration Versioning

The configuration file has a `version` field that determines the schema:

- **version "1.0.0"**: Legacy format with a single `bind_address` field for the server.
- **version "2.0.0"**: Current format with separate `server` and `metrics` sections for more flexible configuration.

Auth-O-Tron still converts a version 1.0.0 server layout to version 2.0.0 at runtime, mapping `bind_address` to `server`. This compatibility applies only to the layout: the JWT settings shared by both versions have a breaking RS256 migration. A legacy `jwt.secret` is no longer accepted in either version. See [Migrating from HMAC JWTs](../migration/rs256.md).

## Environment Variable Overrides

Any configuration value can be overridden using environment variables. The prefix is `AOT_`, and double underscores (`__`) are used to represent nested configuration keys.

For example, to override the JWT issuer:

```bash
AOT_JWT__ISS=my-custom-issuer
```

This would set `jwt.iss` in the configuration.

### Precedence

Configuration values are resolved in this order:

1. **YAML file**: Base configuration values.
2. **Environment variables**: Override values from the YAML file.

This means environment variables always take precedence over file-based settings.

## Complete Example

Here is a complete version 2.0.0 configuration that demonstrates all major sections:

```yaml
version: "2.0.0"

server:
  host: "0.0.0.0"
  port: 8080

metrics:
  enabled: true
  port: 9090

providers:
  - type: plain
    name: local_users
    realm: internal
    users:
      - username: admin
        # Hash of adminpass for this example only.
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$YXV0aG90cm9uLWRvYy0wMg$z1Q74VCoGWdQC7OycwP1XrHF5mtr3GnxX68PUqEe0PQ"
        roles: [admin, user]
      - username: guest
        # Hash of guestpass for this example only.
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$YXV0aG90cm9uLWRvYy0wMw$4EYE6u9AV7M5q2hnrIurr2Ws8jvJuNaM+W4ki331HsQ"
        roles: [readonly]

  - type: jwt
    name: jwt_validation
    realm: external
    cert_uri: https://auth.example.com/.well-known/jwks.json
    iam_realm: example-realm

augmenters:
  - type: plain_advanced
    name: admin_override
    realm: internal
    match:
      username: [admin]
    augment:
      roles: [superuser]
      attributes:
        department: engineering

jwt:
  iss: auth-o-tron.example.com
  aud: my-application
  exp: 3600
  kid: key-2026-01
  private_key: set-via-AOT_JWT__PRIVATE_KEY


logging:
  level: info
  format: json
  service_name: auth-o-tron
  service_version: 1.0.0
```
