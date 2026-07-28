# Aegis WAF — k8s / Helm Deployment (P-FREE-5)

All manifests are 100% open-source and run on stock k8s without any
commercial operator (no Istio / Linkerd / Datadog required).

## Helm

```bash
helm install aegis ./deploy/helm/aegis \
  --set secrets.postgresPassword=... \
  --set config.threat_feed.auto_block=true
```

## Plain k8s

```bash
kubectl apply -f deploy/k8s/deployment.yaml
```

## What you get for free

| Probe / Object | Why |
|---|---|
| `livenessProbe` /`/ping` | K8s restarts frozen pods automatically |
| `readinessProbe` /`/api/v1/health` | Service only routes to ready pods |
| `startupProbe` (30 × 5s) | First-boot migrations get enough budget |
| `prometheus.io/scrape: "true"` | Any Prometheus picks up `/metrics` |
| `HorizontalPodAutoscaler` | CPU + memory-based scaling |
| `PodDisruptionBudget` | Voluntary disruptions can't take down all pods |
| `NetworkPolicy` | DNS + DB + Redis + egress-HTTPS only |
| `runAsNonRoot` + `readOnlyRootFilesystem` + `drop ALL caps` | Hardened runtime |
| `ServiceMonitor` (opt-in) | Prometheus Operator integration |

## Required dependencies in-cluster

- PostgreSQL 16+ (any operator, free: CloudNativePG, Zalando)
- Redis 7+ (free: spotahome/redis-operator, kubernetes-redis-cluster)

## Optional, all free

- Prometheus Operator (ServiceMonitor)
- Cert-manager (TLS via Let's Encrypt)
- External Secrets Operator (sync from Vault / AWS Secrets Manager)