#!/bin/bash
set -eo pipefail

echo "=========================================================="
echo "🛡️ TokenGuard K8s Operator - Ephemeral Hetzner E2E Runner 🛡️"
echo "=========================================================="

if [ -z "$HCLOUD_TOKEN" ]; then
    echo "ERROR: HCLOUD_TOKEN environment variable is missing."
    exit 1
fi

RUN_ID=${GITHUB_RUN_ID:-local}
SERVER_NAME="tokenguard-e2e-$RUN_ID"
SSH_KEY_NAME="e2e-key-$RUN_ID"
FIREWALL_NAME="e2e-fw-$RUN_ID"

echo "==> 1. Generating specific ephemeral SSH key for this pipeline run..."
ssh-keygen -t ed25519 -f ./e2e_key -N "" -q
hcloud ssh-key create --name "$SSH_KEY_NAME" --public-key-from-file ./e2e_key.pub

echo "==> 2. Fetching runner IP to secure Hetzner Cloud Firewall..."
RUNNER_IP=$(curl -s https://api.ipify.org)
echo "    -> Runner IP: $RUNNER_IP"

# We strictly allow Port 22 (SSH) and Port 6443 (Kube API) ONLY from the GitHub Action Runner's IP.
cat <<EOF > firewall.json
[
  {"direction":"in","protocol":"tcp","port":"22","source_ips":["$RUNNER_IP/32","127.0.0.1/32"]},
  {"direction":"in","protocol":"tcp","port":"6443","source_ips":["$RUNNER_IP/32","127.0.0.1/32"]}
]
EOF
hcloud firewall create --name "$FIREWALL_NAME" --rules-file firewall.json

echo "==> 3. Provisioning Ephemeral CX23 Debian 12 Server in Falkenstein..."
hcloud server create --name "$SERVER_NAME" --image debian-12 --type cx23 --location fsn1 --ssh-key "$SSH_KEY_NAME" --firewall "$FIREWALL_NAME" --without-ipv6
SERVER_IP=$(hcloud server describe "$SERVER_NAME" -o format={{.IPv4}})

echo "==> 4. Waiting for SSH daemon to start at $SERVER_IP..."
sleep 20

echo "==> 5. Installing K3s (Lightweight Kubernetes) securely over SSH..."
ssh -i ./e2e_key -o StrictHostKeyChecking=no root@$SERVER_IP \
  "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server --tls-san $SERVER_IP' sh -"

echo "==> 6. Fetching secure Kubeconfig down to CI runner..."
mkdir -p ~/.kube
ssh -i ./e2e_key -o StrictHostKeyChecking=no root@$SERVER_IP "cat /etc/rancher/k3s/k3s.yaml" | sed "s/127.0.0.1/$SERVER_IP/" > ~/.kube/config

echo "==> 7. Awaiting K3s API Readiness..."
until kubectl get nodes; do 
  echo "Waiting for API server..."
  sleep 5
done

echo "==> ☑️ K3s Cluster provisioned securely. Proceeding with E2E TokenGuard Tests..."
