# Local Kubernetes Setup for HaRP + AppAPI Development

Small guide about setting up a local Kubernetes cluster (kind) with HaRP and AppAPI for ExApp development.
After completing these steps you *maybe* will be able to register a K8s deploy daemon in Nextcloud and run `test-deploy`.

## Prerequisites

- Docker installed and running
- Nextcloud Docker-Dev (Julius) running at `https://nextcloud.local`
  - The Nextcloud container is on the `master_default` Docker network
- `kubectl` installed ([install guide](https://kubernetes.io/docs/tasks/tools/))
- `kind` installed ([install guide](https://kind.sigs.k8s.io/docs/user/quick-start/#installation))
- HaRP repository cloned (e.g. `~/nextcloud/HaRP`)

## Architecture Overview

```
Browser / OCC
      |
  Nextcloud (PHP, in Docker container)
      |  OCC commands or API calls
      v
  nginx proxy  ──/exapps/──>  HaRP (host network, port 8780)
                                 |
                                 |  K8s API calls (Deployments, Services, PVCs)
                                 v
                             kind cluster (nc-exapps)
                                 |
                                 v
                           ExApp Pod (e.g. test-deploy)
```

- **HaRP** runs on the host network (`--network=host`) and communicates with:
  - The kind K8s API server (via `https://127.0.0.1:<port>`)
  - ExApp pods via NodePort services (via the kind node IP)
- **Nextcloud** reaches HaRP via the Docker network gateway IP
- **nginx proxy** forwards `/exapps/` requests to HaRP

## Step 1: Create the kind Cluster

```bash
kind create cluster --name nc-exapps
```

Verify:

```bash
kubectl config use-context kind-nc-exapps
kubectl cluster-info
kubectl get nodes -o wide
```

Note the **API server URL** (e.g. `https://127.0.0.1:37151`) and the
**node InternalIP** (e.g. `172.18.0.2`):

```bash
# API server
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'

# Node internal IP
kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'
```

## Step 2: Create Namespace and RBAC

```bash
# Create the ExApps namespace
kubectl create namespace nextcloud-exapps

# Create a ServiceAccount for HaRP
kubectl -n nextcloud-exapps create serviceaccount harp-exapps

# Grant cluster-admin (for development; restrict in production)
kubectl create clusterrolebinding harp-exapps-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=nextcloud-exapps:harp-exapps
```

Generate a bearer token (valid for 1 year):

```bash
kubectl -n nextcloud-exapps create token harp-exapps --duration=8760h
```

> The `redeploy_host_k8s.sh` script generates this token automatically, so you
> don't need to copy it manually.

## Step 3: Configure the nginx Proxy

The Nextcloud Docker-Dev nginx proxy must forward `/exapps/` to HaRP.

Find the gateway IP of the `master_default` Docker network (this is how
containers reach the host):

```bash
docker network inspect master_default \
  --format '{{range .IPAM.Config}}Gateway: {{.Gateway}}{{end}}'
```

Typically this is your host IP like `192.168.21.1` (may vary on your machine).

Edit the nginx vhost file:

```bash
# Path relative to your nextcloud-docker-dev checkout:
# data/nginx/vhost.d/nextcloud.local_location
```

Set the content to:

```nginx
location /exapps/ {
  set $harp_addr <GATEWAY_IP>:8780;
  proxy_pass http://$harp_addr;

  # Forward the true client identity
  proxy_set_header Host              $host;
  proxy_set_header X-Real-IP         $remote_addr;
  proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Replace `<GATEWAY_IP>` with the gateway from above (e.g. `192.168.21.1`).

Reload nginx:

```bash
docker exec master-proxy-1 nginx -s reload
```

## Step 4: Build and Deploy HaRP

From the HaRP repository root:

```bash
cd ~/nextcloud/HaRP
bash development/redeploy_host_k8s.sh
```

The script will:
1. Auto-detect the K8s API server URL
2. Generate a fresh bearer token
3. Build the HaRP Docker image
4. Start HaRP with K8s backend enabled on host network

Wait for HaRP to become healthy:

```bash
docker ps | grep harp
# Should show "(healthy)" after ~15 seconds
```

Check logs if needed:

```bash
docker logs appapi-harp --tail=20
```

## Step 5: Register the K8s Deploy Daemon in Nextcloud

Run this inside the Nextcloud container (replace `<NC_CONTAINER>` with your
container ID or name, and `<GATEWAY_IP>` with the gateway from Step 3):

```bash
docker exec <NC_CONTAINER> php occ app_api:daemon:register \
  k8s_local "Kubernetes Local" "kubernetes-install" \
  "http" "<GATEWAY_IP>:8780" "http://nextcloud.local" \
  --harp \
  --harp_shared_key "some_very_secure_password" \
  --harp_frp_address "<GATEWAY_IP>:8782" \
  --k8s \
  --k8s_expose_type=nodeport \
  --set-default
```

Verify:

```bash
docker exec <NC_CONTAINER> php occ app_api:daemon:list
```

## Step 6: Run Test Deploy

### Via OCC

```bash
docker exec <NC_CONTAINER> php occ app_api:app:register test-deploy k8s_local \
  --info-xml https://raw.githubusercontent.com/nextcloud/test-deploy/main/appinfo/info.xml \
  --test-deploy-mode
```

Expected output:

```
ExApp test-deploy deployed successfully.
ExApp test-deploy successfully registered.
```

### Via API (same as what the Admin UI uses)

```bash
# Start test deploy
curl -X POST -u admin:admin -H "OCS-APIREQUEST: true" -k \
  "https://nextcloud.local/index.php/apps/app_api/daemons/k8s_local/test_deploy"

# Check status
curl -u admin:admin -H "OCS-APIREQUEST: true" -k \
  "https://nextcloud.local/index.php/apps/app_api/daemons/k8s_local/test_deploy/status"

# Stop and clean up
curl -X DELETE -u admin:admin -H "OCS-APIREQUEST: true" -k \
  "https://nextcloud.local/index.php/apps/app_api/daemons/k8s_local/test_deploy"
```

### Verify K8s Resources

```bash
kubectl get deploy,svc,pvc,pods -n nextcloud-exapps -o wide
```

### Unregister

```bash
docker exec <NC_CONTAINER> php occ app_api:app:unregister test-deploy
```

## Cluster Overview

| Component | Value |
|-----------|-------|
| **Type** | kind (Kubernetes in Docker) |
| **Cluster Name** | `nc-exapps` |
| **Node** | `nc-exapps-control-plane` |
| **ExApps Namespace** | `nextcloud-exapps` |
| **ServiceAccount** | `harp-exapps` |

## Monitoring Commands

### Cluster Status

```bash
kubectl cluster-info
kubectl get nodes -o wide
kubectl get pods -n nextcloud-exapps
kubectl get pods -n nextcloud-exapps -w   # watch in real-time
```

### Pod Inspection

```bash
kubectl describe pod <pod-name> -n nextcloud-exapps
kubectl logs <pod-name> -n nextcloud-exapps
kubectl logs -f <pod-name> -n nextcloud-exapps      # follow logs
kubectl logs --previous <pod-name> -n nextcloud-exapps  # after restart
```

### Resources

```bash
kubectl get svc,deploy,pvc -n nextcloud-exapps
kubectl get all -n nextcloud-exapps
```

### HaRP Logs

```bash
docker logs appapi-harp --tail=50
docker logs -f appapi-harp   # follow
```

## Troubleshooting

### HaRP can't reach K8s API

```bash
# Check if kind container is running
docker ps | grep kind

# Verify API server is reachable from host
curl -k https://127.0.0.1:37151/version
```

### Nextcloud can't reach HaRP

```bash
# From inside the Nextcloud container, test connectivity to HaRP:
docker exec <NC_CONTAINER> curl -s http://<GATEWAY_IP>:8780/

# Should return "404 Not Found" (HaRP is responding)
# If connection refused: check HaRP is running and gateway IP is correct
```

### Heartbeat fails after successful deploy

Check HaRP logs for routing errors:

```bash
docker logs appapi-harp --tail=20
```

HaRP lazily resolves the K8s Service upstream on first request after a
restart, so restarting HaRP does **not** require re-deploying ExApps.
If heartbeat still fails, verify the K8s Service exists and is reachable:

```bash
kubectl get svc -n nextcloud-exapps
```

### Pods stuck in Pending

```bash
kubectl describe pod <pod-name> -n nextcloud-exapps
# Check Events section for scheduling or image pull issues
```

### Image pull errors

The kind cluster needs to be able to pull images. For public images (like
`ghcr.io/nextcloud/test-deploy:release`) this should work out of the box.

### Token expired

Regenerate by rerunning the redeploy script:

```bash
cd ~/nextcloud/HaRP
bash development/redeploy_host_k8s.sh
```

### Clean up all ExApp resources

```bash
kubectl delete deploy,svc,pvc -n nextcloud-exapps --all
```

### Reset everything

```bash
# Remove daemon config
docker exec <NC_CONTAINER> php occ app_api:daemon:unregister k8s_local

# Delete kind cluster
kind delete cluster --name nc-exapps

# Remove HaRP container
docker rm -f appapi-harp
```

Then start again from Step 1.
