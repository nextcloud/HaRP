#!/bin/sh
# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Redeploy HaRP with Kubernetes backend for local development.
#
# Prerequisites:
#   - kind cluster "nc-exapps" running (see docs/kubernetes-local-setup.md)
#   - kubectl context set to kind-nc-exapps
#   - Nextcloud Docker-Dev running with nginx proxy
#   - nginx vhost configured to proxy /exapps/ to HaRP (see docs)

set -e

# ── Configuration ──────────────────────────────────────────────────────
KIND_CLUSTER="nc-exapps"
KIND_NODE="${KIND_CLUSTER}-control-plane"
K8S_CONTEXT="kind-${KIND_CLUSTER}"
K8S_NAMESPACE="nextcloud-exapps"
K8S_SA="harp-exapps"
NC_DOCKER_NETWORK="master_default"

HP_SHARED_KEY="some_very_secure_password"
NC_INSTANCE_URL="http://nextcloud.local"
# ───────────────────────────────────────────────────────────────────────

echo "==> Obtaining K8s API server URL..."
K8S_API_SERVER=$(kubectl --context "$K8S_CONTEXT" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
echo "    API server: $K8S_API_SERVER"

echo "==> Generating fresh bearer token for SA '$K8S_SA' (valid 1 year)..."
K8S_BEARER_TOKEN=$(kubectl --context "$K8S_CONTEXT" -n "$K8S_NAMESPACE" create token "$K8S_SA" --duration=8760h)
echo "    Token generated (${#K8S_BEARER_TOKEN} chars)"

# ── Ensure kind node can reach the Nextcloud Docker network ───────────
echo "==> Connecting kind node '$KIND_NODE' to Docker network '$NC_DOCKER_NETWORK'..."
if docker network connect "$NC_DOCKER_NETWORK" "$KIND_NODE" 2>/dev/null; then
  echo "    Connected."
else
  echo "    Already connected (or network not found)."
fi

# Detect the nginx proxy IP on NC_DOCKER_NETWORK for pod DNS resolution.
# Pods inside the kind cluster cannot resolve hostnames like "nextcloud.local" that only exist in the host's /etc/hosts.
# Try to inject hostAliases so that ExApp pods can reach Nextcloud.
echo "==> Detecting nginx proxy IP for host aliases..."
PROXY_IP=$(docker inspect master-proxy-1 \
  --format "{{(index .NetworkSettings.Networks \"$NC_DOCKER_NETWORK\").IPAddress}}" 2>/dev/null || true)
K8S_HOST_ALIASES=""
if [ -n "$PROXY_IP" ]; then
  K8S_HOST_ALIASES="nextcloud.local:${PROXY_IP}"
  echo "    nextcloud.local -> $PROXY_IP"
else
  echo "    WARNING: Could not detect proxy IP. ExApp pods may not resolve nextcloud.local."
fi

echo "==> Removing old HaRP container..."
docker container remove --force appapi-harp 2>/dev/null || true

echo "==> Building HaRP image..."
docker build -t nextcloud-appapi-harp:local .

echo "==> Starting HaRP container..."
docker run \
  -e HP_SHARED_KEY="$HP_SHARED_KEY" \
  -e NC_INSTANCE_URL="$NC_INSTANCE_URL" \
  -e HP_LOG_LEVEL="info" \
  -e HP_VERBOSE_START="1" \
  -e HP_K8S_ENABLED="true" \
  -e HP_K8S_API_SERVER="$K8S_API_SERVER" \
  -e HP_K8S_BEARER_TOKEN="$K8S_BEARER_TOKEN" \
  -e HP_K8S_NAMESPACE="$K8S_NAMESPACE" \
  -e HP_K8S_VERIFY_SSL="false" \
  -e HP_K8S_HOST_ALIASES="$K8S_HOST_ALIASES" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)/certs:/certs" \
  --name appapi-harp -h appapi-harp \
  --restart unless-stopped \
  --network=host \
  -d nextcloud-appapi-harp:local

echo "==> HaRP container started. Waiting for health check..."
sleep 5
if docker inspect appapi-harp --format '{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; then
  echo "==> HaRP is healthy!"
else
  echo "==> HaRP still starting... check with: docker ps | grep harp"
fi
