# Docker

Auth-O-Tron publishes container images to the ECMWF Container Registry.

## Image Location

```
eccr.ecmwf.int/auth-o-tron/auth-o-tron
```

## Image Variants

Two variants are available for different use cases:

| Variant | Description | Use Case |
|---------|-------------|----------|
| release | Distroless image with minimal footprint | Production deployments |
| debug | Debian-slim with bash and ca-certificates | Development and debugging |

Both variants support multiple architectures: `amd64` and `arm64`.

## Running the Container

Mount your configuration file and set the `AOT_CONFIG_PATH` environment variable:

```bash
docker run -d \
  --name auth-o-tron \
  -p 8080:8080 \
  -p 9090:9090 \
  -v $(pwd)/config.yaml:/etc/auth-o-tron/config.yaml \
  -e AOT_CONFIG_PATH=/etc/auth-o-tron/config.yaml \
  eccr.ecmwf.int/auth-o-tron/auth-o-tron:0.3.0
```

## Docker Compose Example

The `examples/nginx-auth` directory contains a complete setup with Auth-O-Tron, NGINX, and an httpbin backend:

```yaml
version: "3.8"

services:
  auth-o-tron:
    image: eccr.ecmwf.int/auth-o-tron/auth-o-tron:release
    volumes:
      - ./auth-o-tron/config.yaml:/etc/auth-o-tron/config.yaml:ro
    environment:
      AOT_CONFIG_PATH: /etc/auth-o-tron/config.yaml
    networks:
      - authnet

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - auth-o-tron
      - httpbin
    networks:
      - authnet

  httpbin:
    image: kennethreitz/httpbin
    networks:
      - authnet

networks:
  authnet:
```

This example demonstrates the auth_request pattern where NGINX delegates authentication to Auth-O-Tron before proxying requests to the protected backend.
