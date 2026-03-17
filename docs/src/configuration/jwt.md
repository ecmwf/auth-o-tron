# JWT Signing

The `jwt` section configures how Auth-O-Tron generates and signs JSON Web Tokens for authenticated users. This section is required if you want Auth-O-Tron to issue JWTs.

## Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| iss | string | yes | The issuer claim, identifies who issued the token |
| aud | string | no | Reserved for future use (not currently included in issued JWTs) |
| exp | integer | yes | Token expiration time in seconds |
| secret | string | yes | The HMAC secret key used for signing |

## Algorithm

Auth-O-Tron uses the HS256 (HMAC with SHA-256) algorithm for signing JWTs. This is a symmetric algorithm where the same secret is used for both signing and verification.

**Important:** Keep your secret secure. Anyone with the secret can forge valid tokens.

## Generated Claims

When Auth-O-Tron issues a JWT, it includes the following claims:

| Claim | Description |
|-------|-------------|
| sub | Subject, formatted as "{realm}-{username}" |
| iss | Issuer, from the `iss` config field |
| exp | Expiration time, calculated as `min(config_exp, user_attribute_exp)` |
| iat | Issued at timestamp |
| roles | Array of role strings from the user |
| username | The authenticated username |
| realm | The authentication realm |
| scopes | Array of scope strings (if any) |
| attributes | Map of additional user attributes |

The `exp` claim uses the minimum of:
- The configured expiration time
- Any `exp` attribute on the user object (useful for short-lived tokens)

This allows per-user token lifetime overrides.

## Example Configuration

```yaml
jwt:
  iss: auth-o-tron.example.com
  aud: my-application
  exp: 3600
  secret: your-256-bit-secret-key-here-minimum-32-characters
```

This configuration:
- Sets the issuer to "auth-o-tron.example.com"
- Sets a default expiration of 1 hour (3600 seconds)
- Uses the provided secret for HMAC signing

## Example JWT Payload

A token generated with the above configuration might have this payload:

```json
{
  "sub": "internal-alice",
  "iss": "auth-o-tron.example.com",

  "exp": 1704067200,
  "iat": 1704063600,
  "roles": ["admin", "developer"],
  "username": "alice",
  "realm": "internal",
  "scopes": ["read", "write"],
  "attributes": {
    "department": "engineering",
    "team": "platform"
  }
}
```

## Security Considerations

- Use a secret that is at least 32 bytes (256 bits) for HS256
- Store the secret securely, such as in a secrets manager or environment variable
- Rotate secrets periodically
- Use short expiration times and require re-authentication
- Consider using the `aud` claim to prevent token replay across different services
