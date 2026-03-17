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
        password: "secret123"

augmenters: []

store:
  enabled: false

services: []

jwt:
  iss: "auth-o-tron"
  exp: 3600
  secret: "your-secret-key-for-local-testing-only"

logging:
  level: "info"
  format: "console"

server:
  host: "0.0.0.0"
  port: 8080

metrics:
  enabled: false
```

## Run the Server

```bash
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

For a complete NGINX integration example with docker-compose, see `examples/nginx-auth` in the repository. This demonstrates how to protect backend services using Auth-O-Tron as an authentication sub-request handler.
