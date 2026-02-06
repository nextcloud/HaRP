# AppAPI Emulation Guide (HaRP + Kubernetes backend)

This guide documents the `curl` commands used to emulate AppAPI when testing HaRP’s Kubernetes backend.

## Prerequisites

* HaRP is reachable at: `http://nextcloud.local/exapps`
* HaRP was started with the same shared key as used below (`HP_SHARED_KEY`)
* HaRP has Kubernetes backend enabled (`HP_K8S_ENABLED=true`) and can access the K8s API
* `kubectl` is configured to point to the same cluster HaRP uses
* Optional: `jq` for parsing JSON responses

## Environment variables

```bash
export EXAPPS_URL="http://nextcloud.local/exapps"
export APPAPI_URL="${EXAPPS_URL}/app_api"
export HP_SHARED_KEY="some_very_secure_password"

# Optional: Nextcloud base (only used by ExApp container env in this guide)
export NEXTCLOUD_URL="http://nextcloud.local"
```

> Notes:
>
> * All AppAPI-emulation calls go to `$APPAPI_URL/...` and require the header `harp-shared-key`.
> * You can also hit the agent directly on `http://127.0.0.1:8200/...` for debugging, but that bypasses the HAProxy/AppAPI path and may skip shared-key enforcement depending on your routing.

---

## 1) Check if ExApp is present (K8s Deployment exists)

```bash
curl -sS \
  -H "harp-shared-key: $HP_SHARED_KEY" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{
    "name": "test-deploy",
    "instance_id": ""
  }' \
  "$APPAPI_URL/k8s/exapp/exists"
```

Expected output:

```json
{"exists": true}
```

or

```json
{"exists": false}
```

---

## 2) Create ExApp (PVC + Deployment with replicas=0)

```bash
curl -sS \
  -H "harp-shared-key: $HP_SHARED_KEY" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{
    "name": "test-deploy",
    "instance_id": "",
    "image": "ghcr.io/nextcloud/test-deploy:latest",
    "environment_variables": [
      "APP_ID=test-deploy",
      "APP_DISPLAY_NAME=Test Deploy",
      "APP_VERSION=1.2.1",
      "APP_HOST=0.0.0.0",
      "APP_PORT=23000",
      "NEXTCLOUD_URL='"$NEXTCLOUD_URL"'",
      "APP_SECRET=some-dev-secret",
      "APP_PERSISTENT_STORAGE=/nc_app_test-deploy_data"
    ],
    "resource_limits": { "cpu": "500m", "memory": "512Mi" }
  }' \
  "$APPAPI_URL/k8s/exapp/create"
```

Expected output (example):

```json
{"name":"nc-app-test-deploy"}
```

---

## 3) Start ExApp (scale replicas to 1)

```bash
curl -sS \
  -H "harp-shared-key: $HP_SHARED_KEY" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{
    "name": "test-deploy",
    "instance_id": ""
  }' \
  "$APPAPI_URL/k8s/exapp/start"
```

Expected: HTTP 204.

---

## 4) Wait for ExApp to become Ready

```bash
curl -sS \
  -H "harp-shared-key: $HP_SHARED_KEY" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{
    "name": "test-deploy",
    "instance_id": ""
  }' \
  "$APPAPI_URL/k8s/exapp/wait_for_start"
```

Expected output (example):

```json
{
  "started": true,
  "status": "running",
  "health": "ready",
  "reason": null,
  "message": null
}
```

---

## 5) Expose + register in HaRP

### 5.1 NodePort (default behavior)

**Minimal (uses defaults, may auto-pick a node address):**

```bash
EXPOSE_JSON=$(
  curl -sS \
    -H "harp-shared-key: $HP_SHARED_KEY" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{
      "name": "test-deploy",
      "instance_id": "",
      "port": 23000,
      "expose_type": "nodeport"
    }' \
    "$APPAPI_URL/k8s/exapp/expose"
)

echo "$EXPOSE_JSON"
```

**Recommended (provide a stable host reachable by HaRP):**

```bash
# Example: edge node IP / VIP / L4 LB that forwards NodePort range
UPSTREAM_HOST="172.18.0.2"

EXPOSE_JSON=$(
  curl -sS \
    -H "harp-shared-key: $HP_SHARED_KEY" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{
      "name": "test-deploy",
      "instance_id": "",
      "port": 23000,
      "expose_type": "nodeport",
      "upstream_host": "'"$UPSTREAM_HOST"'"
    }' \
    "$APPAPI_URL/k8s/exapp/expose"
)

echo "$EXPOSE_JSON"
```

### 5.2 ClusterIP (only if HaRP can reach ClusterIP + resolve service DNS)

```bash
EXPOSE_JSON=$(
  curl -sS \
    -H "harp-shared-key: $HP_SHARED_KEY" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{
      "name": "test-deploy",
      "instance_id": "",
      "port": 23000,
      "expose_type": "clusterip"
    }' \
    "$APPAPI_URL/k8s/exapp/expose"
)

echo "$EXPOSE_JSON"
```

### 5.3 Manual (HaRP does not create or inspect any Service)

```bash
EXPOSE_JSON=$(
  curl -sS \
    -H "harp-shared-key: $HP_SHARED_KEY" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{
      "name": "test-deploy",
      "instance_id": "",
      "port": 23000,
      "expose_type": "manual",
      "upstream_host": "exapp-test-deploy.internal",
      "upstream_port": 23000
    }' \
    "$APPAPI_URL/k8s/exapp/expose"
)

echo "$EXPOSE_JSON"
```

---

## 6) Extract exposed host/port for follow-up tests (requires `jq`)

```bash
EXAPP_HOST=$(echo "$EXPOSE_JSON" | jq -r '.host')
EXAPP_PORT=$(echo "$EXPOSE_JSON" | jq -r '.port')

echo "ExApp upstream endpoint: ${EXAPP_HOST}:${EXAPP_PORT}"
```

---

## 7) Check `/heartbeat` via HaRP routing (AppAPI-style direct routing headers)

This checks HaRP’s ability to route to the ExApp given an explicit upstream host/port and AppAPI-style authorization header.

### 7.1 Build `authorization-app-api` value

HaRP typically expects this value to be the **base64 of `user_id:APP_SECRET`** (similar to HTTP Basic without the `Basic ` prefix). For an “anonymous” style request, use `:APP_SECRET`.

```bash
# Option A: anonymous-style
AUTH_APP_API=$(printf '%s' ':some-dev-secret' | base64 | tr -d '\n')

# Option B: user-scoped style (example user "admin")
# AUTH_APP_API=$(printf '%s' 'admin:some-dev-secret' | base64 | tr -d '\n')
```

### 7.2 Call heartbeat

```bash
curl -sS \
  "http://nextcloud.local/exapps/test-deploy/heartbeat" \
  -H "harp-shared-key: $HP_SHARED_KEY" \
  -H "ex-app-version: 1.2.1" \
  -H "ex-app-id: test-deploy" \
  -H "ex-app-host: $EXAPP_HOST" \
  -H "ex-app-port: $EXAPP_PORT" \
  -H "authorization-app-api: $AUTH_APP_API"
```

If this fails with auth-related errors, verify:

* `APP_SECRET` in the ExApp matches what you used here,
* your HaProxy config expectations for `authorization-app-api` (raw vs base64).

---

## 8) Stop and remove (API-based cleanup)

### Stop ExApp (scale replicas to 0)

```bash
curl -sS \
  -H "harp-shared-key: $HP_SHARED_KEY" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{
    "name": "test-deploy",
    "instance_id": ""
  }' \
  "$APPAPI_URL/k8s/exapp/stop"
```

### Remove ExApp (Deployment + optional PVC; Service may be removed depending on HaRP version)

```bash
curl -sS \
  -H "harp-shared-key: $HP_SHARED_KEY" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{
    "name": "test-deploy",
    "instance_id": "",
    "remove_data": true
  }' \
  "$APPAPI_URL/k8s/exapp/remove"
```

---

## Useful `kubectl` commands (debug / manual cleanup)

### Check resources

```bash
kubectl get deploy,svc,pvc -n nextcloud-exapps -o wide | grep -E 'test-deploy|NAME' || true
kubectl get pods -n nextcloud-exapps -o wide
```

### Delete Service (if it was exposed and needs manual cleanup)

```bash
kubectl delete svc nc-app-test-deploy -n nextcloud-exapps
```

### Delete Deployment

```bash
kubectl delete deployment nc-app-test-deploy -n nextcloud-exapps
```

### Delete PVC (data)

PVC name is derived from `nc_app_test-deploy_data` and sanitized for K8s, typically:
`nc-app-test-deploy-data`

```bash
kubectl delete pvc nc-app-test-deploy-data -n nextcloud-exapps
```
