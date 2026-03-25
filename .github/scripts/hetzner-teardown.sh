#!/bin/bash
set -e

RUN_ID=${GITHUB_RUN_ID:-local}
SERVER_NAME="tokenguard-e2e-$RUN_ID"
SSH_KEY_NAME="e2e-key-$RUN_ID"
FIREWALL_NAME="e2e-fw-$RUN_ID"

echo "==> Ephemeral Teardown: Destroying Hetzner VPS to prevent waste & attack surface."

# Delete server if it exists
if hcloud server describe "$SERVER_NAME" > /dev/null 2>&1; then
    hcloud server delete "$SERVER_NAME"
    echo "Deleted Server: $SERVER_NAME"
fi

# Delete firewall if it exists
if hcloud firewall describe "$FIREWALL_NAME" > /dev/null 2>&1; then
    hcloud firewall delete "$FIREWALL_NAME"
    echo "Deleted Firewall: $FIREWALL_NAME"
fi

# Delete SSH key if it exists
if hcloud ssh-key describe "$SSH_KEY_NAME" > /dev/null 2>&1; then
    hcloud ssh-key delete "$SSH_KEY_NAME"
    echo "Deleted SSH Key: $SSH_KEY_NAME"
fi

echo "==> Clean teardown complete."
