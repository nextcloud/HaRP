#!/bin/sh
# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Redeploy HaRP with Kubernetes backend for local development.
#
# Prerequisites:
#   - kind cluster "nc-exapps" running
#   - kubectl context set to kind-nc-exapps
#   - Nextcloud Docker-Dev running with nginx proxy, published on all host interfaces
#     (IP_BIND=0.0.0.0 in its .env; with the default 127.0.0.1 ExApp pods cannot reach it)
#   - nginx vhost configured to proxy /exapps/ to HaRP (see README)

set -e

# ── Configuration ──────────────────────────────────────────────────────
KIND_CLUSTER="nc-exapps"
KIND_NODE="${KIND_CLUSTER}-control-plane"
K8S_CONTEXT="kind-${KIND_CLUSTER}"
K8S_NAMESPACE="nextcloud-exapps"
K8S_SA="harp-exapps"

HP_SHARED_KEY="some_very_secure_password"
NC_INSTANCE_URL="http://nextcloud.local"
# ───────────────────────────────────────────────────────────────────────

echo "==> Obtaining K8s API server URL..."
K8S_API_SERVER=$(kubectl --context "$K8S_CONTEXT" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
echo "    API server: $K8S_API_SERVER"

echo "==> Generating fresh bearer token for SA '$K8S_SA' (valid 1 year)..."
K8S_BEARER_TOKEN=$(kubectl --context "$K8S_CONTEXT" -n "$K8S_NAMESPACE" create token "$K8S_SA" --duration=8760h)
echo "    Token generated (${#K8S_BEARER_TOKEN} chars)"

# Detect the gateway IP of the kind Docker network for pod DNS resolution.
# Pods inside the kind cluster cannot resolve hostnames like "nextcloud.local" that only exist in the host's /etc/hosts.
# The gateway is the host itself, so an alias to it lets ExApp pods reach Nextcloud through the ports the nginx proxy
# publishes on all interfaces (a proxy bound to 127.0.0.1 only is not reachable this way).
echo "==> Detecting the kind gateway IP for host aliases..."
KIND_HOST_IP=$(docker inspect "$KIND_NODE" \
  --format "{{(index .NetworkSettings.Networks \"kind\").Gateway}}" 2>/dev/null || true)
NC_HOSTNAME="$(echo "$NC_INSTANCE_URL" | awk -F'[/:]' '{print $4}')"
K8S_HOST_ALIASES=""
if [ -z "$NC_HOSTNAME" ]; then
  echo "    WARNING: Could not extract a hostname from NC_INSTANCE_URL='$NC_INSTANCE_URL'."
elif [ "${NC_HOSTNAME#*[!0-9.]}" = "$NC_HOSTNAME" ]; then
  echo "    ${NC_HOSTNAME} is an IP address, no host alias needed."
elif [ -n "$KIND_HOST_IP" ]; then
  K8S_HOST_ALIASES="${NC_HOSTNAME}:${KIND_HOST_IP}"
  echo "    ${NC_HOSTNAME} -> $KIND_HOST_IP"
  if ! docker exec "$KIND_NODE" curl -fsSk -m 5 -o /dev/null \
    --connect-to "${NC_HOSTNAME}::${KIND_HOST_IP}:" "${NC_INSTANCE_URL%/}/status.php"; then
    echo "    WARNING: Nextcloud did not answer on $KIND_HOST_IP from the kind node. Is the proxy published on all interfaces (IP_BIND=0.0.0.0)?"
  fi
else
  echo "    WARNING: Could not detect the kind gateway IP. ExApp pods may not resolve ${NC_HOSTNAME}."
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
