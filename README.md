# Nextcloud AppAPI HaProxy Reversed Proxy (HaRP)

**Note:** *Work is still in progress; the first working version is expected in March;*

---

## What is this?

HaRP is a new reverse proxy system for Nextcloud 32’s AppAPI deployment workflow.

It aims to simplify the process of launching ExApps (external applications) and provide faster communication by allowing requests to bypass the Nextcloud instance directly to ExApps!

## What does it do?

Previously, AppAPI primarily used [DockerSocketProxy](https://github.com/nextcloud/docker-socket-proxy).

When deploying ExApps on a remote host, the **setup could become quite complex** for people unfamiliar with networking and proxies.

With **HaRP** we aimed to simplify configuration while maintaining easy migration of current ExApps but with a new operating scheme.

We provide a **HaRP** container that you can run locally or on any remote machine. In AppAPI 32, this will be introduced as a new deployment type: `docker-install-harp`.

### Features of HaRP

- **Supports HTTP and WebSockets**
- **Remote deployment** options (run the container anywhere)
- **High-speed data** transfer between client and ExApp
- **Brute-force protection** on all exposed interfaces
- **Single HaRP** can manage multiple Docker engines

---

## How to Install and Run (ONLY FOR DEVELOPERS)

Below is a brief overview for developers. This process may change in future versions.

### 1. Build the Docker image (if needed):

```bash
docker build -t harp-prod .
```

### 2. **Run the container (HTTP-only example)**

If you want to *only* expose HTTP (no HTTPS), you can **omit** the HTTPS environment variables and port mappings. For example:

```bash
docker run -d \
  -p 8780:8780 \
  -p 8782:8782 \
  -p 8784:8784 \
  -e HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
  -e HP_FRP_ADDRESS="0.0.0.0:8782" \
  -e HP_CONTROL_ADDRESS="0.0.0.0:8784" \
  -e NC_HAPROXY_SHARED_KEY="mysecret" \
  -e NC_INSTANCE_URL="http://nextcloud.local" \
  --name harp-prod \
  harp-prod
```

In this configuration:
- **No TLS certificates** are needed.
- Only ports **8780** (for ExApps HTTP), **8782** (FRP TCP), and **8784** (Nextcloud control interface) are exposed.
- Requests will come in via HTTP.

### 3. **Optionally mount TLS certificates** to enable HTTPS

If you mount your TLS certificate at `/certs/cert.pem` inside the container, the HTTPS frontends will be automatically enabled.
If `cert.pem` is missing, the HTTPS frontends will be automatically disabled.

#### **Run the container (HTTPS-only example)**

```bash
docker run -d \
  -p 8781:8781 \
  -p 8783:8783 \
  -p 8785:8785 \
  -e HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781" \
  -e HP_FRP_HTTPS_ADDRESS="0.0.0.0:8783" \
  -e HP_CONTROL_HTTPS_ADDRESS="0.0.0.0:8785" \
  -e NC_HAPROXY_SHARED_KEY="mysecret" \
  -e NC_INSTANCE_URL="https://nextcloud.local" \
  --name harp-prod \
  -v /path/to/mycerts:/certs \
  harp-prod
```

In this configuration:
- **Mount** the directory containing your certificate (`cert.pem`) at `/certs`.
- Only the HTTPS ports (8781, 8783, 8785) are exposed.

**Note:** **Using both HTTP and HTTPS simultaneously**
You can also **mix and match**. For example, if you only want HTTPS for FRP but plain HTTP for ExApps, then configure:
- `HP_EXAPPS_ADDRESS` (for HTTP)
- `HP_FRP_HTTPS_ADDRESS` (for HTTPS)
…and so forth, depending on your desired setup.

---

## Environment Variables

- **`HP_EXAPPS_ADDRESS`** / **`HP_EXAPPS_HTTPS_ADDRESS`**:
  IP:Port for ExApps HTTP/HTTPS. **Should be reachable by your reverse proxy** (e.g., Nginx or Caddy).
  e.g., `HP_EXAPPS_ADDRESS="0.0.0.0:8780"` or `HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781"`

- **`HP_FRP_ADDRESS`** / **`HP_FRP_HTTPS_ADDRESS`**:
  IP:Port for FRP (TCP) frontends. **Should be reachable from where your ExApps are running.**

- **`HP_CONTROL_ADDRESS`** / **`HP_CONTROL_HTTPS_ADDRESS`**:
  IP:Port for the control interface. **Should be reachable by your Nextcloud instance.**

- **`NC_HAPROXY_SHARED_KEY`**:
  A token used for authentication in the internal service. You can also specify `NC_HAPROXY_SHARED_KEY_FILE` if you prefer to read the key from a file.

- **`NC_INSTANCE_URL`**:
  The base URL of your Nextcloud instance. **This must be a URL reachable by the HaRP container.**

---

## Usage with Nextcloud AppAPI

1. **Set up the HaRP container** using one of the examples above (HTTP-only, HTTPS-only, or mixed).
2. **Specify the HaRP host and port configuration** in the AppAPI 32 settings (e.g., select `docker-install-harp` and fill in the relevant addresses).
3. **Deploy your ExApps** so they connect through HaRP. Requests to ExApps will be automatically proxied and protected from brute-force attacks.

---

![RequestToExApp](https://www.mermaidchart.com/raw/a7557169-9c5c-4458-af73-19ffbdd97596?theme=light&version=v0.1&format=svg)

![Bruteforce](https://www.mermaidchart.com/raw/69417bdf-59af-4b7a-b4e4-b818851f3278?theme=light&version=v0.1&format=svg)

![ExAppSessions](https://www.mermaidchart.com/raw/d0350862-3806-4db9-8d90-b7f154600d8e?theme=light&version=v0.1&format=svg)

---

## Todo

- Detailed integration with Nextcloud 32 (finalization of AppAPI interfaces)
- Documentation for HTTPS/TLS termination setup
- Production-ready recommendations for scaling
