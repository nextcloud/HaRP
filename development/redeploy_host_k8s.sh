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
