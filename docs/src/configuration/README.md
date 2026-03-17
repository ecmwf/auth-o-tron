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

When Auth-O-Tron loads a version 1.0.0 configuration, it automatically converts it to version 2.0.0 at runtime. This conversion maps the legacy `bind_address` to the new `server` section. It is recommended to update your configuration files to version 2.0.0 for clarity and future compatibility.

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
        password: adminpass
        roles: [admin, user]
      - username: guest
        password: guestpass
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
  secret: your-secret-key-here

store:
  enabled: true
  type: mongo
  uri: mongodb://localhost:27017
  database: auth_o_tron

logging:
  level: info
  format: json
  service_name: auth-o-tron
  service_version: 1.0.0
```
