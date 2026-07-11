# JWT Signing

The required `jwt` section configures the short-lived tokens issued by Auth-O-Tron.

## Configuration Fields

| Field | Type | Required | Description |
| ------- | ------ | ---------- | ------------- |
| iss | string | yes | Exact issuer claim for issued tokens |
| aud | string | yes | Exact audience claim for issued tokens |
| kid | string | yes | Non-empty identifier for the active signing key |
| exp | integer | yes | Token lifetime in seconds |
| private_key | string | yes | RSA private key in PEM format (2048 bits minimum; 3072 recommended) |

## Algorithm and consumer contract

Auth-O-Tron signs issued tokens with RS256 only. The server parses the private key once during startup and refuses malformed RSA keys, keys below 2048 bits, and an empty `kid`. Use 3072-bit keys for new deployments. Consumers receive only public keys and must pin RS256 while validating the exact configured `iss` and `aud` values. There is no HMAC fallback.

Every JWT header contains the active `kid`. The `authotron-client` constructor accepts an overlapping public keyset, parses it once, and selects exactly one key by `kid`. It rejects RSA public keys below 2048 bits, missing or unknown token identifiers, and duplicate identifiers in the configured keyset.

## Generated Claims

| Claim | Description |
| ------- | ------------- |
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
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

Inject the private PEM through the environment rather than committing it to the configuration file:

```yaml
jwt:
  iss: auth-o-tron.example.com
  aud: my-application
  exp: 3600
  kid: key-2026-01
  private_key: set-via-AOT_JWT__PRIVATE_KEY
```

```bash
export AOT_JWT__PRIVATE_KEY="$(cat jwt-private.pem)"
```

Multiline environment values are supported. In Kubernetes, store the PEM as a Secret value and expose it as `AOT_JWT__PRIVATE_KEY`. Distribute `jwt-public.pem` and its `kid` to consumers; never distribute the private key.

## Staged key rotation

Rotate an RSA signing key without invalidating tokens that are still within their configured maximum lifetime:

1. Generate the new key pair and choose a new, unique `kid`.
2. Publish the new public key and `kid` to every consumer, keeping the old public key in each keyset.
3. Switch Auth-O-Tron to the new `jwt.private_key` and `jwt.kid`. New tokens now identify the new key.
4. Wait at least the maximum token lifetime (`jwt.exp`, plus any verifier clock-skew allowance). A user `exp` attribute can shorten but never extend this lifetime.
5. Retire the old public key from consumers.

Never switch the signer before consumers have the new public key. Never reuse a `kid` for different key material.

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
- Use RSA keys of at least 2048 bits; 3072 bits is recommended for newly generated keys.
- Give consumers only the public keys and their identifiers.
- Use the staged overlap procedure for every rotation.
- Keep issuer and audience values stable and specific to the deployment contract.
- Use short expiration times and require re-authentication.
