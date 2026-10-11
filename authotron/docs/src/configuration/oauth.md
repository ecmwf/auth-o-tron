# OAuth configuration foundation

OAuth/MCP authorization-server support is **not implemented yet**. The v2
`oauth` section reserves and validates configuration for future work. Setting
`enabled: true` fails startup with an Unsupported error, before browser, network,
or store initialization. It does not activate any endpoints or metadata.

Omitting this section (including migrated v1 configurations) keeps OAuth disabled.

```yaml
oauth:
  enabled: false
  issuer: "https://login.example.org"
  authorization_code_ttl_seconds: 60
  access_token_ttl_seconds: 300
```

| Setting | Default | Validation |
| --- | --- | --- |
| `enabled` | `false` | Enablement is currently unsupported |
| `issuer` | absent | Required when enabled; absolute HTTPS origin only |
| `authorization_code_ttl_seconds` | `60` | 30–300 seconds inclusive |
| `access_token_ttl_seconds` | `300` | 60–3600 seconds inclusive |

Unknown OAuth fields are rejected. Supplied issuers and TTLs are validated even
when disabled. Issuers must have no userinfo, query, fragment, whitespace, or
control characters. An optional trailing `/` is allowed; issuer URI paths such as
`https://login.example.org/oauth` are unsupported in this origin-only baseline.
Future authorization endpoints must use a consistent, available public HTTPS origin.

Authorization codes, PKCE S256, RS256 access tokens, discovery/JWKS,
and MCP integration are future capabilities. Local client preregistration is the
next configuration phase; automatic registration is not part of that baseline.
No OAuth signing keys
are configured here. The legacy HMAC `jwt.secret` must never be published through
future JWKS or reused as an OAuth asymmetric signing key.
