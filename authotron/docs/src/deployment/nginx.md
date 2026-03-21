# NGINX Integration

Auth-O-Tron integrates with NGINX using the `auth_request` module. This pattern delegates authentication decisions to Auth-O-Tron via an internal subrequest, keeping your backend services simple and stateless.

## How It Works

```mermaid
sequenceDiagram
    participant Client
    participant NGINX
    participant AOT as Auth-O-Tron
    participant Backend

    Client->>NGINX: GET /api/resource<br/>Authorization: Basic ...
    NGINX->>AOT: Subrequest /_auth<br/>(auth_request)
    
    alt Valid credentials
        AOT-->>NGINX: 200 OK + Authorization: Bearer <jwt>
        NGINX->>Backend: GET /resource<br/>Authorization: Bearer <jwt>
        Backend-->>NGINX: 200 OK + Response
        NGINX-->>Client: 200 OK + Response
    else Invalid credentials
        AOT-->>NGINX: 401 Unauthorized
        NGINX-->>Client: 302 Redirect → /authenticate
    end
```

## Example Configuration

The `examples/nginx-auth` directory contains a complete working setup. Here is the NGINX configuration with explanations:

```nginx
events {
    worker_connections 1024;
}

http {
    # Upstream definitions
    upstream authotron {
        server auth-o-tron:8080;
    }

    upstream api_backend {
        server httpbin:80;
    }

    server {
        listen 80;

        # Public endpoint: triggers authentication flow
        location /authenticate {
            proxy_pass http://authotron;
            proxy_set_header Host $host;
        }

        # Internal endpoint: subrequest for auth validation
        location /_auth {
            internal;
            proxy_pass http://authotron;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Original-Method $request_method;
        }

        # Named location: redirect on 401 to trigger auth
        location @trigger_auth {
            return 302 /authenticate?redirect=$request_uri;
        }

        # Protected API: requires valid authentication
        location /api/ {
            auth_request /_auth;
            auth_request_set $auth_status $upstream_status;

            # Forward JWT to backend
            auth_request_set $jwt $upstream_http_authorization;
            proxy_set_header Authorization $jwt;

            # Forward legacy headers (if include_legacy_headers is enabled)
            auth_request_set $auth_username $upstream_http_x_auth_username;
            auth_request_set $auth_realm $upstream_http_x_auth_realm;
            auth_request_set $auth_roles $upstream_http_x_auth_roles;
            proxy_set_header X-Auth-Username $auth_username;
            proxy_set_header X-Auth-Realm $auth_realm;
            proxy_set_header X-Auth-Roles $auth_roles;

            proxy_pass http://api_backend;
            proxy_set_header Host $host;

            error_page 401 = @trigger_auth;
        }
    }
}
```

## Configuration Breakdown

**Upstream definitions** establish the backend services. `authotron` points to the Auth-O-Tron container, and `api_backend` is your protected application.

**The `/authenticate` location** is included in this example for demonstration and browser-based testing. In production, you likely want to remove it — clients should send credentials directly on the protected endpoints and let the `auth_request` subrequest handle validation transparently.

**The `/_auth` location** is marked `internal`, meaning only NGINX can access it. The `auth_request` directive sends a subrequest to Auth-O-Tron to validate the client's credentials.

**The `@trigger_auth` named location** redirects unauthenticated browser requests. This is useful for development but in API-only deployments you may prefer to return 401 directly instead of redirecting.

**The `/api/` location** is protected. The `auth_request` directive triggers the subrequest to `/_auth`. On success, the JWT and any legacy headers are captured from the Auth-O-Tron response and forwarded to the backend. On 401, the error page redirects to `@trigger_auth`.

## Headers Forwarded to Backend

| Header | Description |
|--------|-------------|
| Authorization | The JWT token issued by Auth-O-Tron |
| X-Auth-Username | Authenticated username (requires `include_legacy_headers: true`) |
| X-Auth-Realm | Authentication realm (requires `include_legacy_headers: true`) |
| X-Auth-Roles | Comma-separated roles (requires `include_legacy_headers: true`) |

## Testing the Setup

Unauthenticated requests are redirected to the login flow:

```bash
curl -i http://localhost/api/get
# HTTP/1.1 302 Found
# Location: /authenticate?redirect=/api/get
```

Authenticated requests with valid Basic credentials succeed:

```bash
curl -i -H "Authorization: Basic dGVzdF91c2VyOnNlY3JldDEyMw==" http://localhost/api/get
# HTTP/1.1 200 OK
```

The base64 string `dGVzdF91c2VyOnNlY3JldDEyMw==` decodes to `test_user:secret123`.
