# Kubernetes & Helm

Auth-O-Tron is designed to run as a containerized workload in Kubernetes. An official Helm chart provides a streamlined installation path.

## Helm Chart

The chart is maintained in a separate repository:

```
https://github.com/ecmwf/auth-o-tron-chart
```

## Installation

Clone the chart repository and install:

```bash
git clone https://github.com/ecmwf/auth-o-tron-chart.git
helm install auth-o-tron ./auth-o-tron-chart
```

## Configuration

The following values are commonly customized in `values.yaml`:

### Server Settings

```yaml
server:
  port: 8080       # Application port
  
metrics:
  port: 9090       # Metrics port (internal only)
  enabled: true
```

### Auth-O-Tron Configuration

The `config` section is mounted as a ConfigMap and contains the full Auth-O-Tron configuration:

```yaml
config: |
  server:
    host: 0.0.0.0
    port: 8080
  metrics:
    enabled: true
    port: 9090
  # ... additional config
```

### Service Configuration

```yaml
service:
  type: ClusterIP
  port: 80
  targetPort: 8080
```

### Monitoring

Enable Prometheus ServiceMonitor for metrics scraping:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
```

### RSA Private Key via a Kubernetes Secret

Store the complete multiline RSA private PEM in a Secret and inject it directly as an environment variable:

```bash
kubectl create secret generic auth-o-tron-jwt \
  --from-file=private-key=jwt-private.pem
```

```yaml
extraEnv:
  - name: AOT_JWT__PRIVATE_KEY
    valueFrom:
      secretKeyRef:
        name: auth-o-tron-jwt
        key: private-key
```

The Kubernetes environment preserves newlines in the Secret value. Mount or distribute only the corresponding public PEM to consuming services.

### Pod Annotations

```yaml
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"
```

## Health Probes

Liveness and readiness probes are configured automatically on the `/health` endpoint. When `metrics.enabled: true`, `/health` is available on both the application and metrics ports. Otherwise it is only on the application port.

## Network Architecture

The metrics port is internal to the cluster and should not be exposed via ingress. Configure your ingress to route only to the application port (8080).

## Minimal Override Example

```yaml
server:
  port: 8080

metrics:
  enabled: true
  port: 9090
  serviceMonitor:
    enabled: true

config:
  version: "2.0.0"
  server:
    host: "0.0.0.0"
    port: 8080
  jwt:
    iss: my-org
    aud: my-service
    exp: 3600
    kid: key-2026-01
    private_key: set-via-AOT_JWT__PRIVATE_KEY
  providers:
    - type: plain
      name: default
      realm: default
      users:
        - username: admin
          password: changeme
```
