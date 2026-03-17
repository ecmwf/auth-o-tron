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

### Secrets via Environment Variables

Use `extraEnv` to inject sensitive values from Kubernetes secrets:

```yaml
extraEnv:
  - name: AOT_JWT__SECRET
    valueFrom:
      secretKeyRef:
        name: auth-o-tron-secrets
        key: jwt-secret
```

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
    exp: 3600
    secret: changeme
  providers:
    - type: plain
      name: default
      realm: default
      users:
        - username: admin
          password: changeme
```
