# JWT Signing

The required `jwt` section configures the short-lived tokens issued by Auth-O-Tron.

## Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| iss | string | yes | Exact issuer claim for issued tokens |
| aud | string | yes | Exact audience claim for issued tokens |
| exp | integer | yes | Token lifetime in seconds |
| private_key | string | yes | RSA private key in PEM format |

## Algorithm and consumer contract

Auth-O-Tron signs issued tokens with RS256 only. The server parses the private key once during startup and fails to start if it is invalid. Consumers receive only the corresponding public key and must pin RS256 while validating the exact configured `iss` and `aud` values. There is no HMAC fallback.

The `authotron-client` constructor accepts the public PEM key, issuer, and audience. It parses the public key once and rejects tokens with another algorithm, issuer, audience, or key.

## Generated Claims

| Claim | Description |
|-------|-------------|
| sub | Subject, formatted as `{realm}-{username}` |
| iss | Exact configured issuer |
| aud | Exact configured audience |
| exp | Expiration time, calculated as `min(config_exp, user_attribute_exp)` |
| iat | Issued-at timestamp |
| roles | User roles |
| username | Authenticated username |
| realm | Authentication realm |
| scopes | Service scopes, if any |
| attributes | Additional user attributes |

## Example Configuration

Generate a private/public key pair:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out jwt-private.pem
openssl rsa -pubout -in jwt-private.pem -out jwt-public.pem
```

Inject the private PEM through the environment rather than committing it to the configuration file:

```yaml
jwt:
  iss: auth-o-tron.example.com
  aud: my-application
  exp: 3600
  private_key: set-via-AOT_JWT__PRIVATE_KEY
```

```bash
export AOT_JWT__PRIVATE_KEY="$(cat jwt-private.pem)"
```

Multiline environment values are supported. In Kubernetes, store the PEM as a Secret value and expose it as `AOT_JWT__PRIVATE_KEY`. Distribute `jwt-public.pem` to consumers; never distribute the private key.

## Example JWT Payload

```json
{
  "sub": "internal-alice",
  "iss": "auth-o-tron.example.com",
  "aud": "my-application",
  "exp": 1704067200,
  "iat": 1704063600,
  "roles": ["admin", "developer"],
  "username": "alice",
  "realm": "internal",
  "scopes": {"data": ["read", "write"]},
  "attributes": {"department": "engineering"}
}
```

## Security Considerations

- Keep the RSA private key in a secret manager or Kubernetes Secret.
- Give consumers only the public key.
- Rotate keys and update consumers as one coordinated deployment.
- Keep issuer and audience values stable and specific to the deployment contract.
- Use short expiration times and require re-authentication.
