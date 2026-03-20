## NGINX + Auth-o-tron Docker Compose Example

A minimal example showing how to deploy Auth-o-tron as a standalone service behind NGINX (with the `auth_request` module) and forward authenticated requests to an API backend. By default it uses [httpbin](https://github.com/postmanlabs/httpbin) to inspect HTTP headers.

### Prerequisites

- Docker & Docker Compose (v1.27+)  
- Public Auth-o-tron image:
  ```bash
  docker pull eccr.ecmwf.int/auth-o-tron/auth-o-tron:0.2.5
  ```

### Usage
## 1. Start the stack
```bash
cd examples/nginx
docker-compose up -d
```
This brings up three services:
- auth-o-tron on port 8080 (internal)
- nginx-proxy on port 80
- httpbin on port 80 (internal)

## 2. Test the flow with curl

Unauthenticated request to a protected endpoint:
```bash
curl -i http://localhost/api/get◊
```
You should receive a 302 Found response with a Location: /authenticate?redirect=… header.
The response will also include a WWW-Authenticate header listing the available authentication methods

Direct JWT access:
```bash
curl -i -H "Authorization: Bearer <your-jwt-token>" http://localhost/api/get
```
A working example (using the credentials in the demo config):
```bash
curl -i http://localhost/api/get -H "Authorization: Basic dGVzdF91c2VyOnNlY3JldDEyMw=="
```

Auth-o-tron allows chaning of multiple authorization tokens:
```bash
curl -i http://localhost/api/get -H "Authorization: Basic dGVzdF91c2VyOnNlY3JldDEyMw==, Bearer some_bearer_token"
```

## Plug in your own application

### Replace the api service in docker-compose.yml:
```yaml
services:
  api:
    image: your-org/your-app:latest
    container_name: app-backend
    networks:
      - authnet
```

Ensure your app listens on port 80 (or update the upstream api_backend in nginx.conf to match).

### Update NGINX upstream in nginx.conf if needed:
```nginx
upstream api_backend {
  server api:80;
}
```

### Redeploy
```bash
docker-compose down
docker-compose up -d
```

All /api/... requests on localhost will now require authentication via Auth-o-tron,
and your backend will receive the JWT in the Authorization header.