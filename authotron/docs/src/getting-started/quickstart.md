# Quick Start

This guide gets Auth-O-Tron running locally with a basic auth provider for testing.

## Minimal Configuration

Create `config.yaml` with this content:

```yaml
version: "2.0.0"

providers:
  - name: "local"
    type: "plain"
    realm: "default"
    users:
      - username: "test_user"
        # Hash of secret123 for this example only.
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$YXV0aG90cm9uLWRvYy0wMA$nIbsJAh7Dy4U3lp30gdyZp5xIvGEixDw6egf5H1ckpQ"

augmenters: []


jwt:
  iss: "auth-o-tron"
  aud: "local-example"
  exp: 3600
  kid: "local-2026-01"
  private_key: "set-via-AOT_JWT__PRIVATE_KEY"

logging:
  level: "info"
  format: "console"

server:
  host: "0.0.0.0"
  port: 8080

metrics:
  enabled: false
```

The example credentials are `test_user:secret123`. Generate a new Argon2id hash with a unique random salt before using the configuration outside this quick start.

## Generate a Test Key and Run the Server

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
export AOT_JWT__PRIVATE_KEY="$(cat jwt-private.pem)"
AOT_CONFIG_PATH=config.yaml ./target/release/authotron
```

You should see startup logs indicating the server is listening on port 8080.

## Test Authentication

Send a request with basic auth credentials:

```bash
curl -i -H "Authorization: Basic dGVzdF91c2VyOnNlY3JldDEyMw==" \
  http://localhost:8080/authenticate
```

The response should be:

```
HTTP/1.1 200 OK
Authorization: Bearer <jwt-token>
```

## Inspect the JWT

Copy the token and decode it to see the claims:

```bash
python3 -c "import base64,sys,json; p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))" "<jwt-token>"
```

You will see the user identity, roles, and other attributes encoded in the payload.

## Next Steps

For a complete NGINX integration example with docker-compose, see `authotron/examples/nginx-auth` in the repository. This demonstrates how to protect backend services using Auth-O-Tron as an authentication sub-request handler.
