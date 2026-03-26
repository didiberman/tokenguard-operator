# TokenGuard Operator

A Kubernetes operator that continuously audits ServiceAccount (SA) permissions to enforce least-privilege security. It cross-references what permissions are _granted_ via RBAC against what permissions are actually _used_ (from the Kubernetes audit log), producing a live **Least Privilege Score** and flagging anomalies such as external IP token usage.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [The SAAuditor CRD](#the-saauditor-crd)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Anomaly Detection](#anomaly-detection)
- [Metrics](#metrics)
- [Development](#development)
- [CI/CD](#cicd)
- [License](#license)

---

## Overview

Over-permissioned ServiceAccounts are one of the most common Kubernetes misconfigurations. TokenGuard automates the hard work of identifying permission creep by:

1. **Scanning RBAC** — Walks all `RoleBindings` and `ClusterRoleBindings` to build a complete list of permissions granted to every ServiceAccount in a target namespace.
2. **Consuming the audit log** — Receives Kubernetes audit events via a webhook and records which permissions each ServiceAccount actually exercises.
3. **Scoring** — Computes a `Least Privilege Score` (0–100). A score of 100 means every granted permission is actively used. A low score indicates excess permissions that should be removed.
4. **Alerting** — Detects tokens being used from external (non-private) IP addresses, which can indicate a supply-chain compromise or credential leak.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  Kubernetes Cluster                                             │
│                                                                 │
│   ┌──────────────────┐       Audit Events (POST /audit)        │
│   │  API Server       │ ─────────────────────────────────────► │
│   │  (Audit Webhook)  │                                        │
│   └──────────────────┘       ┌──────────────────────────────┐  │
│                               │   TokenGuard Operator        │  │
│   ┌──────────────────┐        │                              │  │
│   │  RoleBindings /  │ ──────►│  audit.Receiver  (port 9443) │  │
│   │  ClusterRoles    │        │  rbac.Evaluator              │  │
│   └──────────────────┘        │  SAAuditorReconciler         │  │
│                               │  report.Server   (port 9090) │  │
│                               └──────────────┬───────────────┘  │
│                                              │ updates status    │
│                               ┌──────────────▼───────────────┐  │
│                               │  SAAuditor CR                │  │
│                               │  .status.currentScore        │  │
│                               │  .status.usedPermissions     │  │
│                               │  .status.unusedPermissions   │  │
│                               │  .status.anomalies           │  │
│                               └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

The reconcile loop runs every **2 minutes** by default (configurable via `scoringInterval`).

---

## The SAAuditor CRD

`SAAuditor` is a namespaced custom resource in the `security.tokenguard.io/v1` API group.

### Spec

| Field | Type | Required | Description |
|---|---|---|---|
| `targetNamespace` | string | Yes | Namespace whose ServiceAccounts are monitored |
| `scoringInterval` | string | No | How often to recalculate the score (e.g. `"5m"`) |
| `alertThreshold` | integer (0–100) | No | Minimum score before triggering an alert |

### Status (written by the operator)

| Field | Type | Description |
|---|---|---|
| `currentScore` | integer | Least Privilege Score — `(used / granted) * 100` |
| `usedPermissions` | []string | Permissions actually exercised, per ServiceAccount |
| `unusedPermissions` | []string | Granted permissions that have never been observed in the audit log |
| `anomalies` | []string | Critical findings, e.g. external-IP token usage |

### Example Resource

```yaml
apiVersion: security.tokenguard.io/v1
kind: SAAuditor
metadata:
  name: prod-namespace-audit
  namespace: security-ops
spec:
  targetNamespace: production
  scoringInterval: "5m"
  alertThreshold: 80
```

After the first reconcile, the status will be populated:

```yaml
status:
  currentScore: 62
  usedPermissions:
    - "my-app: get /core/pods"
    - "my-app: list /apps/deployments"
  unusedPermissions:
    - "my-app: delete /core/pods"
    - "my-app: create /core/secrets"
  anomalies:
    - "CRITICAL: External IP 203.0.113.42 used SA my-app token"
```

---

## Architecture

```
my-crd-operator/
├── api/v1/
│   ├── saauditor_types.go        # CRD type definitions (Spec, Status)
│   └── zz_generated.deepcopy.go  # Auto-generated DeepCopy methods
├── cmd/
│   └── main.go                   # Entrypoint — wires together manager, audit receiver, RBAC evaluator
├── internal/controller/
│   └── saauditor_controller.go   # Reconcile loop — scores SAs, writes status
├── pkg/
│   ├── audit/
│   │   └── webhook.go            # HTTP server (:9443) that receives K8s audit events
│   ├── report/
│   │   └── server.go             # HTTP server (:9090) serving the HTML report at /report
│   └── rbac/
│       └── evaluator.go          # Walks RoleBindings/ClusterRoleBindings to compute granted permissions
├── config/
│   ├── crd/                      # Generated CRD manifests
│   ├── rbac/                     # RBAC manifests for the operator itself
│   ├── manager/                  # Deployment manifests
│   ├── default/                  # Kustomize overlay (metrics, webhooks)
│   └── samples/                  # Example SAAuditor resource
└── test/
    ├── e2e/                      # End-to-end tests (Kind)
    └── utils/                    # Test helpers
```

### Key components

**`audit.Receiver`** — Implements `manager.Runnable`. Starts an HTTP server on `:9443` (configurable via `--audit-webhook-bind-address`) that accepts `POST /audit` requests from the Kubernetes API server's audit webhook backend. Parses `EventList` payloads, extracts the verb+resource+apiGroup per ServiceAccount, and stores a deduplicated set of `UsedPermissions` along with all observed source IPs (thread-safe via `sync.RWMutex`).

**`report.Server`** — Implements `manager.Runnable`. Starts an HTTP server on `:9090` (configurable via `--report-bind-address`) serving a live HTML dashboard at `/report`. Queries all `SAAuditor` resources and renders scores, used/unused permissions, and anomalies in a dark-themed UI. Access it via `kubectl port-forward` or the `tokenguard-operator-report` Service.

**`rbac.Evaluator`** — Walks all `RoleBindings` (namespace-scoped) and `ClusterRoleBindings` (cluster-wide) that reference a given ServiceAccount. Resolves both `Role` and `ClusterRole` references and formats rules as `"verb /apiGroup/resource"` strings for direct comparison with audit data.

**`SAAuditorReconciler`** — The main controller. For each reconcile:
1. Lists all ServiceAccounts in `spec.targetNamespace`
2. Calls `rbac.Evaluator` for granted permissions
3. Calls `audit.Receiver` for observed permissions
4. Computes `score = (totalUsed / totalGranted) * 100`
5. Checks source IPs for non-private addresses (anomaly detection)
6. Writes results to `SAAuditor.Status` and requeues after 2 minutes

---

## Prerequisites

- Go 1.25+
- Kubernetes cluster v1.35+ (or [Kind](https://kind.sigs.k8s.io/) for local dev)
- `kubectl` configured against your target cluster
- Docker (for building images)
- The Kubernetes API server configured with an **audit webhook** pointing to `http://<operator-service>:9443/audit`

---

## Installation

### Using Helm (recommended)

```bash
helm upgrade --install tokenguard-operator \
  oci://ghcr.io/didiberman/tokenguard-operator/charts/tokenguard-operator \
  --namespace tokenguard-system --create-namespace
```

After installation, view the HTML report:

```bash
kubectl port-forward svc/tokenguard-operator-report -n tokenguard-system 9090:9090
# open http://localhost:9090/report
```

### Using Kustomize

```bash
# Install the CRD
make install

# Build and push the operator image
make docker-build docker-push IMG=<your-registry>/tokenguard:latest

# Deploy to the cluster
make deploy IMG=<your-registry>/tokenguard:latest
```

### Generate a single install manifest

```bash
make build-installer IMG=<your-registry>/tokenguard:latest
kubectl apply -f dist/install.yaml
```

### Configure the Kubernetes Audit Webhook

Add the following to your API server's audit policy (`--audit-webhook-config-file`):

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: tokenguard
    cluster:
      server: http://<tokenguard-service>.<namespace>.svc.cluster.local:9443/audit
users:
  - name: tokenguard
contexts:
  - name: tokenguard
    context:
      cluster: tokenguard
      user: tokenguard
current-context: tokenguard
```

---

## Usage

1. Deploy the operator (see [Installation](#installation)).
2. Create a `SAAuditor` resource targeting the namespace you want to audit:

```bash
kubectl apply -f - <<EOF
apiVersion: security.tokenguard.io/v1
kind: SAAuditor
metadata:
  name: my-audit
  namespace: default
spec:
  targetNamespace: default
  alertThreshold: 75
EOF
```

3. Wait for the first reconcile (up to 2 minutes), then inspect the status:

```bash
kubectl get saauditor my-audit -o yaml
```

4. Identify unused permissions and tighten RBAC accordingly:

```bash
kubectl get saauditor my-audit -o jsonpath='{.status.unusedPermissions}' | tr ',' '\n'
```

5. Check for anomalies:

```bash
kubectl get saauditor my-audit -o jsonpath='{.status.anomalies}'
```

6. View the live HTML report in your browser:

```bash
kubectl port-forward svc/tokenguard-operator-report -n <namespace> 9090:9090
# then open http://localhost:9090/report
```

---

## Anomaly Detection

TokenGuard flags any ServiceAccount token usage originating from a non-private IP address. The following ranges are considered private/internal:

- `10.x.x.x` (RFC 1918)
- `192.168.x.x` (RFC 1918)
- `127.0.0.1` / `::1` (loopback)
- `fd...` (ULA IPv6)

Any source IP outside these ranges generates a `CRITICAL` anomaly entry:

```
CRITICAL: External IP 203.0.113.42 used SA payment-processor token
```

This pattern targets **supply chain compromise scenarios** where a malicious dependency, CI runner, or stolen credential is using a ServiceAccount token from outside the cluster.

---

## Metrics

The operator exposes Prometheus metrics over HTTPS on `:8443` (secured with mTLS by default). Metrics are protected with Kubernetes authentication and authorization.

| Flag | Default | Description |
|---|---|---|
| `--audit-webhook-bind-address` | `:9443` | Address the audit webhook receiver binds to |
| `--report-bind-address` | `:9090` | Address the HTML report server binds to |
| `--metrics-bind-address` | `0` (disabled) | Set to `:8443` (HTTPS) or `:8080` (HTTP) to enable |
| `--metrics-secure` | `true` | Serve metrics over HTTPS |
| `--health-probe-bind-address` | `:8081` | Liveness/readiness probe address |
| `--leader-elect` | `false` | Enable leader election for HA deployments |
| `--enable-http2` | `false` | Enable HTTP/2 (disabled by default due to CVE-2023-44487) |

---

## Development

### Run locally against a cluster

```bash
make run
```

### Run unit tests

```bash
make test
```

### Run end-to-end tests (requires Kind)

```bash
make test-e2e
```

This creates a local Kind cluster (`my-crd-operator-test-e2e`), runs the full e2e suite, and tears down the cluster.

### Lint

```bash
make lint        # Run golangci-lint
make lint-fix    # Auto-fix lint issues
```

### Regenerate manifests and DeepCopy methods

```bash
make generate   # Regenerate DeepCopy methods
make manifests  # Regenerate CRD/RBAC manifests from kubebuilder markers
```

### Available Make targets

```
make help
```

---

## CI/CD

| Workflow | Trigger | Description |
|---|---|---|
| `ci.yml` | Push / PR | Full build + unit tests |
| `lint.yml` | Push / PR | golangci-lint |
| `test.yml` | Push / PR | Unit + integration tests with envtest |
| `test-e2e.yml` | Push / PR | End-to-end tests on Hetzner (secure ephemeral cluster) |
| `release.yml` | Tag push | Build and publish container image |

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
