# Providers

Providers are authentication backends that validate credentials. Auth-O-Tron can run multiple providers simultaneously. Each incoming authentication request is tried against all configured providers until one succeeds or all fail.

All providers share these common fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | The provider type (determines which provider is instantiated) |
| name | string | yes | A unique identifier for this provider instance |
| realm | string | yes | The authentication realm this provider handles (see [Realms](../concepts/how-it-works.md#realms)) |

## Provider Types

### 1. Plain Provider

Type: `plain`

The plain provider implements HTTP Basic Authentication against a static list of users defined in the configuration file. This is useful for development, testing, or simple deployments.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| users | array | List of user objects with username, password, and roles |

Each user object has:
- `username`: The login name
- `password`: The password (compared as plaintext)
- `roles`: Array of role strings assigned to the user (optional, defaults to empty)

**Example:**

```yaml
providers:
  - type: plain
    name: local_users
    realm: internal
    users:
      - username: alice
        password: alicepass123
        roles: [admin, developer]
      - username: bob
        password: bobpass456
        roles: [developer]
```

### 2. JWT Provider

Type: `jwt`

The JWT provider validates JSON Web Tokens using a JWKS (JSON Web Key Set) endpoint. It fetches public keys from the configured URI and validates token signatures.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| cert_uri | string | URL to the JWKS endpoint |
| iam_realm | string | The realm/issuer to validate against |

The provider caches the JWKS for 600 seconds to avoid repeated requests to the certificate endpoint.

**Example:**

```yaml
providers:
  - type: jwt
    name: jwt_validation
    realm: external
    cert_uri: https://auth.example.com/.well-known/jwks.json
    iam_realm: example-realm
```

### 3. ECMWF API Provider

Type: `ecmwf-api`

This provider validates tokens against the ECMWF (European Centre for Medium-Range Weather Forecasts) API. It makes an HTTP request to the ECMWF identity service to verify the token.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| uri | string | Base URL of the ECMWF API |

The provider calls `{uri}/who-am-i?token={token}` to validate credentials. Results are cached for 60 seconds to reduce API load. Contact ECMWF for the correct `uri` value.

**Example:**

```yaml
providers:
  - type: ecmwf-api
    name: ecmwf_validator
    realm: ecmwf
    uri: https://api.example.com
```

### 4. EFAS API Provider

Type: `efas-api`

This provider validates tokens against the EFAS (European Flood Awareness System) API. Similar to the ECMWF provider but with a different endpoint pattern.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| uri | string | Base URL of the EFAS API |

The provider calls `{uri}?token={token}` to validate credentials. Results are cached for 60 seconds. Contact ECMWF for the correct `uri` value.

**Example:**

```yaml
providers:
  - type: efas-api
    name: efas_validator
    realm: efas
    uri: https://efas.example.com/api
```

### 5. OpenID Connect Offline Token Provider

Type: `openid-offline`

This provider handles OpenID Connect offline tokens, commonly used with Keycloak. It introspects the token, exchanges it for an access token, and validates the result via JWKS.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| cert_uri | string | URL to the JWKS endpoint |
| public_client_id | string | Client ID for public token introspection |
| private_client_id | string | Client ID for private token exchange |
| private_client_secret | string | Secret for the private client |
| iam_url | string | Base URL of the identity management server |

The flow is: introspect the offline token, exchange for an access token, validate the access token via JWKS.

**Example:**

```yaml
providers:
  - type: openid-offline
    name: keycloak_offline
    realm: keycloak
    cert_uri: https://keycloak.example.com/realms/master/protocol/openid-connect/certs
    public_client_id: public-client
    private_client_id: private-client
    private_client_secret: super-secret-value
    iam_url: https://keycloak.example.com
```

### 6. ECMWF Token Generator Provider

Type: `ecmwf-token-generator`

This provider integrates with the ECMWF token generator service. It validates tokens and can exchange them for access tokens from the ECMWF identity system.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| cert_uri | string | URL to the JWKS endpoint |
| client_id | string | OAuth client ID |
| client_secret | string | OAuth client secret |
| token_generator_url | string | URL of the ECMWF token generator |

The flow is: validate the presented token, exchange for an access token, validate the access token via JWKS.

Contact ECMWF for the correct `cert_uri` and `token_generator_url` values for your environment.

**Example:**

```yaml
providers:
  - type: ecmwf-token-generator
    name: ecmwf_token_gen
    realm: ecmwf
    cert_uri: https://auth.example.com/realms/default/protocol/openid-connect/certs
    client_id: my-client-id
    client_secret: my-client-secret
    token_generator_url: https://auth.example.com/token-generator
```

## Multiple Providers

You can configure multiple providers to support different authentication methods simultaneously:

```yaml
providers:
  - type: plain
    name: dev_users
    realm: development
    users:
      - username: dev
        password: devpass
        roles: [admin]

  - type: jwt
    name: production_jwt
    realm: production
    cert_uri: https://auth.company.com/.well-known/jwks.json
    iam_realm: company-realm
```

When a request arrives, Auth-O-Tron runs all matching providers in parallel. The first successful result wins.
