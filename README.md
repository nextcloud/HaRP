<!--
 - SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 - SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Nextcloud AppAPI HaProxy Reversed Proxy (HaRP)

---

## Overview

HaRP is a **reverse proxy system** designed to simplify the deployment workflow for Nextcloud 32’s AppAPI.

It enables direct communication between clients and ExApps, bypassing the Nextcloud instance to improve performance and reduce the complexity traditionally associated with `DockerSocketProxy` setups.

HaRP provides a flexible and scalable solution for managing ExApps, supporting deployments both locally and on remote servers.

It can be installed alongside Nextcloud or on a separate host, allowing for optimized performance and security.

The system supports simultaneous HTTP and HTTPS communication, enabling trusted networks to use direct HTTP access while securing external or untrusted connections via HTTPS.

In addition, HaRP includes built-in brute-force protection and dynamic routing capabilities, making it well-suited for a wide range of network infrastructures, from simple home setups to large distributed environments.

---

## What Does HaRP Do?

- **Simplifies Deployment:** Replaces more complex setups (such as DockerSocketProxy) with an easy-to-use container.
- **Direct Communication:** Routes requests directly to ExApps, bypassing the Nextcloud instance.
- **Enhanced Security:** Uses brute-force protection and basic authentication to secure all exposed interfaces.
- **Flexible Frontends:** Supports both HTTP and HTTPS for ExApps and Nextcloud control, and FRP (TCP) frontend.
- **Multi-Docker Management:** A single HaRP instance can manage multiple Docker engines.
- **Automated TLS for FRP:** Generates self-signed certificates for FRP communications (unless explicitly disabled).

## How to Install It

### Deploying HaRP

HaRP should be deployed where your reverse proxy (NGINX, Caddy, Traefik, etc.) can reach its `HP_EXAPPS_ADDRESS`. For home installations, you may run it on your Nextcloud instance. Below are a couple of deployment examples using Docker:

#### Basic Docker Deployment

```bash
docker run \
  -e HP_SHARED_KEY="some_very_secure_password" \
  -e NC_INSTANCE_URL="http://nextcloud.local" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v `pwd`/certs:/certs \
  --name appapi-harp -h appapi-harp \
  --restart unless-stopped \
  -p 8780:8780 \
  -p 8782:8782 \
  -d ghcr.io/nextcloud/nextcloud-appapi-harp:release
```

> **Note:** By default, `HP_EXAPPS_ADDRESS` is set to `0.0.0.0:8780` — ensure this port is published to the desired interface (for example, host’s **127.0.0.1:8780**).

#### Using Host Networking

For even faster communication by avoiding internal network routing, you can use host networking:

```bash
docker run \
  -e HP_SHARED_KEY="some_very_secure_password" \
  -e NC_INSTANCE_URL="http://nextcloud.local" \
  -e HP_EXAPPS_ADDRESS="192.168.2.5:8780" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v `pwd`/certs:/certs \
  --name appapi-harp -h appapi-harp \
  --restart unless-stopped \
  --network host \
  -d ghcr.io/nextcloud/nextcloud-appapi-harp:release
```

> **Warning:** Do not forget to change the **HP_SHARED_KEY** value to a secure one!

---

## Configuring Your Reverse Proxy

HaRP requires your reverse proxy to forward traffic from your public domain (e.g., `nextcloud.com/exapps/`) to the HaRP container’s `HP_EXAPPS_ADDRESS`. Below are sample configurations for NGINX, Caddy, and Traefik:

### NGINX Example

```nginx
server {
    listen 80;
    server_name nextcloud.com;

    location /exapps/ {
        proxy_pass http://127.0.0.1:8780/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy Example

```caddyfile
nextcloud.com {
    reverse_proxy /exapps/* 127.0.0.1:8780
}
```

### Traefik Example

```yaml
http:
  routers:
    exapps:
      rule: "PathPrefix(`/exapps/`)"
      service: exapps-service
      entryPoints:
        - web
  services:
    exapps-service:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8780"
```

> **Note:** Replace `127.0.0.1` with the actual IP address of your HaRP container if it is running on a different host.

---

## Environment Variables

HaRP is configured via several environment variables. Here are the key variables and their defaults:

- **`HP_EXAPPS_ADDRESS` / `HP_EXAPPS_HTTPS_ADDRESS`**
  - **Description:** IP:Port for ExApps HTTP/HTTPS frontends.
  - **Default:**
    - `HP_EXAPPS_ADDRESS="0.0.0.0:8780"`
    - `HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781"`
  - **Note:** Must be reachable by your reverse proxy.

- **`HP_FRP_ADDRESS`**
  - **Description:** IP:Port for the FRP (TCP) frontends.
  - **Default:** `HP_FRP_ADDRESS="0.0.0.0:8782"`
  - **Note:** Should be accessible from where your ExApps are running.

- **`HP_SHARED_KEY`** (or **`HP_SHARED_KEY_FILE`**)
  - **Description:** A secret token used for authentication between services.
  - **Requirement:** Must be set at runtime. Use only one of these methods.

- **`NC_INSTANCE_URL`**
  - **Description:** The base URL of your Nextcloud instance.
  - **Requirement:** Must be accessible from the HaRP container.

- **`HP_FRP_DISABLE_TLS`**
  - **Description:** Disables TLS for the FRP service.
  - **Default:** `HP_FRP_DISABLE_TLS="false"`
  - **Advanced:** Use only for specialized setups where TCP TLS termination is managed externally.

- **`HP_LOG_LEVEL`**
  - **Default:** `warning`
  - **Possible Values:** `debug`, `info`, `warning`, `error`

- **`HP_VERBOSE_START`**
  - **Description:** Flag that determines whether to output verbose logging to the console during  container startup.
  - **Default:** `1`

- **`HP_SESSION_LIFETIME`**
  - **Description:** A floating-point value that determines how long the Nextcloud session is retained in HaRP, in seconds. Possible values range from `0` (disable session caching) to `10` seconds.
  - **Default:** `3`

- **Timeout Variables:**
  - **`HP_TIMEOUT_CONNECT`**
    - **Description:** Maximum time allowed for establishing a connection.
    - **Default:** `30s`
  - **`HP_TIMEOUT_CLIENT`**
    - **Description:** Timeout for client-side connections.
    - **Default:** `30s`
  - **`HP_TIMEOUT_SERVER`**
    - **Description:** Timeout for server-side connections. **We do not recommend to change this value.**
    - **Default:** `1800s`

## Connecting Docker Engines

HaRP supports two approaches for connecting Docker Engines:

### 1. Direct Mounting (Local Docker Engine)

If your Docker Engine is running on the same host as **HaRP**, simply mount the Docker socket into the container. This direct method allows HaRP to interact with the Docker Engine immediately:

```bash
-v /var/run/docker.sock:/var/run/docker.sock
```

### 2. Connecting External Docker Engines via FRP

For remote or external Docker Engines - or if you prefer not to mount the Docker socket - you can use an FRP (Fast Reverse Proxy) client to establish a secure connection. Follow these steps:

1. **Retrieve Certificate Files:**
   HaRP automatically generates the necessary FRP certificate files, and places them in its folder `/certs/frp`. You need next files from it to connect external Docker Engine to HaRP:
   - `client.crt`
   - `client.key`
   - `ca.crt`

2. **Create an FRP Client Configuration:**
   With the certificate files in hand, create a configuration file (for example, `frpc.toml`) on the Docker Engine host. Below is a sample configuration:

   ```toml
   # frpc.toml
   serverAddr = "your.harp.server.address"   # Replace with your HP_FRP_ADDRESS host
   serverPort = 8782                         # Default port for FRP

   transport.tls.certFile = "certs/frp/client.crt"
   transport.tls.keyFile = "certs/frp/client.key"
   transport.tls.trustedCaFile = "certs/frp/ca.crt"
   transport.tls.serverName = "harp.nc"

   metadatas.token = "HP_SHARED_KEY"         # HP_SHARED_KEY in quotes

   [[proxies]]
   remotePort = 24001                        # Unique remotePort for each Docker Engine (range: 24001-24099)
   name = "deploy-daemon"                    # Unique name for each Docker Engine
   type = "tcp"
   [proxies.plugin]
   type = "unix_domain_socket"
   unixPath = "/var/run/docker.sock"
   ```

3. **Deploy the FRP Client:**
   Run the FRP client on the host with the Docker Engine using the configuration file. This establishes a secure tunnel between the remote Docker Engine and HaRP. Each connection requires a unique `remotePort` value; HaRP supports up to 99 Docker Engines by assigning a different port in the allowed range.

## Adapting ExApps to use HaRP

> We strongly recommend starting support for `HaRP` in ExApps from the start of Nextcloud `32`, as the old `DSP` way will be deprecated and marked for removal in Nextcloud `35`.
>
> Adding `HaRP` support is fully compatible with the existing `DSP` system, so you won’t need to maintain two separate release types of your ExApp.

1. Copy the `start.sh` script from the `exapps_dev` folder of this repository and set it as the entry point in your ExApp’s `Dockerfile`.
2. After copying `start.sh`, edit its last line so that it runs your ExApp’s main binary (or script).
3. Add the following lines to your `Dockerfile` to automatically include the `FRP client` binaries in your Docker image:

    ```bash
    # Download and install FRP client
    RUN set -ex; \
        ARCH=$(uname -m); \
        if [ "$ARCH" = "aarch64" ]; then \
          FRP_URL="https://raw.githubusercontent.com/nextcloud/HaRP/main/exapps_dev/frp_0.61.1_linux_arm64.tar.gz"; \
        else \
          FRP_URL="https://raw.githubusercontent.com/nextcloud/HaRP/main/exapps_dev/frp_0.61.1_linux_amd64.tar.gz"; \
        fi; \
        echo "Downloading FRP client from $FRP_URL"; \
        curl -L "$FRP_URL" -o /tmp/frp.tar.gz; \
        tar -C /tmp -xzf /tmp/frp.tar.gz; \
        mv /tmp/frp_0.61.1_linux_* /tmp/frp; \
        cp /tmp/frp/frpc /usr/local/bin/frpc; \
        chmod +x /usr/local/bin/frpc; \
        rm -rf /tmp/frp /tmp/frp.tar.gz
    ```

    > **Note:** For `Alpine 3.21` Linux you can just install `FRP` from repo using `apk add frp` command.

That's it!

## Nextcloud 32: Migrating Existing ExApps from DSP to HaRP

> **Note:** All ExApps developed by Nextcloud will support HaRP when Nextcloud 32 is released. We hope that most ExApps from the community will also support it. **Contact us if you need assistance.**

If you've upgraded to Nextcloud 32 and want to switch from using DSP to HaRP, follow these steps:

1. **Install HaRP** on the same Docker Engine that you were using for DSP.
2. **Test Deployment on HaRP** with usual `TestDeploy` button.
3. **Set HaRP as the default deployment daemon** for ExApps.
4. **Remove the ExApps without deleting their data volumes**:
   - **Terminal**: Do not use the `--rm-data` option when removing the app.
   - **From UI**: Do not use the "Delete data when removing" checkbox.
5. **Install the ExApp**: Install removed ExApps, now they will be installed on `HaRP`.
6. **Remove DSP**: Now DSP (Docker Socket Proxy) can be safely removed.

## Contributing

Contributions to HaRP are welcome. Feel free to open issues, discussions or submit pull requests with improvements, bug fixes, or new features.
