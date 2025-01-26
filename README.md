Nextcloud, AppAPI, ExApps(applications that are docker containers)

For the next version of Nextcloud we will introduce a rule to sysadmins that external reverse proxy (NGINX/Caddy) - should have a rule that all requests of the format "nextcloud.com/exapp/{appid}/..." - are forwarded to our new container with HaProxy and FRP Server and thanks to FRP all ExApps can process requests.

We will call this container with HaProxy and FRP Server: HaRP (HaProxy and FRP) here is our current sources formatted as an MD file:


======================================================================================================
Dockerfile:

# -------------------------------------------------------------------------
# Dockerfile for HaRP (HAProxy + FRP), with Nextcloud Control,
# and flexible (HTTP/HTTPS) frontends for ExApps, FRP, and Control.
#
# Usage example:
#   docker build -t harp-prod .
#   docker run -d \
#     -p 8780:8780 \
#     -p 8781:8781 \
#     -p 8782:8782 \
#     -p 8783:8783 \
#     -p 8784:8784 \
#     -p 8785:8785 \
#     -p 8404:8404 \
#     -e HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
#     -e HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781" \
#     -e HP_FRP_ADDRESS="0.0.0.0:8782" \
#     -e HP_FRP_HTTPS_ADDRESS="0.0.0.0:8783" \
#     -e HP_CONTROL_ADDRESS="0.0.0.0:8784" \
#     -e HP_CONTROL_HTTPS_ADDRESS="0.0.0.0:8785" \
#     -e NC_HAPROXY_SHARED_KEY="mysecret" \
#     --name harp-prod \
#     harp-prod
#
# NOTE:
#  - If you mount /certs/cert.pem into the container, HTTPS frontends will be enabled.
#  - NC_HAPROXY_SHARED_KEY or NC_HAPROXY_SHARED_KEY_FILE must be provided at runtime.
# -------------------------------------------------------------------------

FROM haproxy:3.1.2-alpine3.21

USER root

# Bind addresses for 6 frontends (HTTP + HTTPS for exapps, frp, control).
# If /certs/cert.pem does not exist, HTTPS frontends are disabled automatically.
ENV HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
    HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781" \
    HP_FRP_ADDRESS="0.0.0.0:8782" \
    HP_FRP_HTTPS_ADDRESS="0.0.0.0:8783" \
    HP_CONTROL_ADDRESS="0.0.0.0:8784" \
    HP_CONTROL_HTTPS_ADDRESS="0.0.0.0:8785" \
    HP_TIMEOUT_CONNECT="10s" \
    HP_TIMEOUT_CLIENT="30s" \
    HP_TIMEOUT_SERVER="1800s" \
    NC_INSTANCE_URL=""

# NOTE: We do NOT define NC_HAPROXY_SHARED_KEY or NC_HAPROXY_SHARED_KEY_FILE
# here because they must be provided at runtime for security reasons.

RUN set -ex; \
    apk add --no-cache \
        ca-certificates \
        tzdata \
        bash \
        curl \
        openssl \
        bind-tools \
        nano \
        vim \
        envsubst \
        frp; \
    chmod -R 777 /tmp

# Copy our scripts and templates
COPY --chmod=755 healthcheck.sh /healthcheck.sh
COPY --chmod=775 start.sh /usr/local/bin/start.sh

# Lua scripts folder
#COPY --chmod=775 lua/ /etc/haproxy/lua/

# Main haproxy config template
COPY --chmod=664 haproxy.cfg.template /haproxy.cfg.template

# Set entrypoint to our start.sh
ENTRYPOINT ["start.sh"]
HEALTHCHECK --interval=10s --timeout=10s --retries=9 CMD /healthcheck.sh

LABEL com.centurylinklabs.watchtower.enable="false"



======================================================================================================
start.sh:

#!/bin/sh
set -e

# ----------------------------------------------------------------------------
# start.sh
#  - Generates /haproxy.cfg from haproxy.cfg.template
#  - Reads NC_HAPROXY_SHARED_KEY or NC_HAPROXY_SHARED_KEY_FILE
#  - Comments out HTTPS frontends if no /certs/cert.pem is found
#  - Starts FRP server (frps) on 127.0.0.1:7100 with token = NC_HAPROXY_SHARED_KEY
#  - Launches HAProxy Data Plane API on 127.0.0.1:5555
#  - Finally runs HAProxy in the foreground
# ----------------------------------------------------------------------------

if [ -f "/haproxy.cfg" ]; then
  echo "INFO: /haproxy.cfg already present. Skipping config generation..."
else
  echo "INFO: Creating /haproxy.cfg from haproxy.cfg.template..."

  if [ -n "$NC_HAPROXY_SHARED_KEY_FILE" ] && [ ! -f "$NC_HAPROXY_SHARED_KEY_FILE" ]; then
    echo "ERROR: NC_HAPROXY_SHARED_KEY_FILE is specified but the file does not exist."
    exit 1
  fi

  if [ -n "$NC_HAPROXY_SHARED_KEY" ] && [ -n "$NC_HAPROXY_SHARED_KEY_FILE" ]; then
    echo "ERROR: Only one of NC_HAPROXY_SHARED_KEY or NC_HAPROXY_SHARED_KEY_FILE should be specified."
    exit 1
  fi

  if [ -n "$NC_HAPROXY_SHARED_KEY_FILE" ]; then
    if [ -s "$NC_HAPROXY_SHARED_KEY_FILE" ]; then
      NC_HAPROXY_SHARED_KEY="$(cat "$NC_HAPROXY_SHARED_KEY_FILE")"
    else
      echo "ERROR: NC_HAPROXY_SHARED_KEY_FILE is specified but is empty."
      exit 1
    fi
  elif [ -n "$NC_HAPROXY_SHARED_KEY" ]; then
    NC_HAPROXY_SHARED_KEY="${NC_HAPROXY_SHARED_KEY}"
  else
    echo "ERROR: Either NC_HAPROXY_SHARED_KEY_FILE or NC_HAPROXY_SHARED_KEY must be set."
    exit 1
  fi

  export NC_HAPROXY_SHARED_KEY

  envsubst < /haproxy.cfg.template > /haproxy.cfg

  if [ -f "/certs/cert.pem" ]; then
    echo "INFO: Found /certs/cert.pem, HTTPS frontends remain enabled."
    chmod 644 /certs/cert.pem
  else
    echo "INFO: No /certs/cert.pem found, disabling HTTPS frontends..."
    sed -i "/_HTTPS_FRONTEND_/ s|^|#|g" /haproxy.cfg
  fi

  echo "INFO: Final /haproxy.cfg:"
  cat /haproxy.cfg
fi

cat <<EOF >/tmp/frps.ini
[common]
bind_addr = 127.0.0.1
bind_port = 7100
token = ${NC_HAPROXY_SHARED_KEY}
EOF

echo "INFO: Starting FRP server on 127.0.0.1:7100..."
frps -c /tmp/frps.ini &

cat <<EOF >/tmp/haproxy-dataplaneapi.hcl
haproxy:
  config-file: /haproxy.cfg
  reload-cmd: "kill -USR2 \$(pidof haproxy)"
api:
  address: 127.0.0.1
  port: 5555
runtime:
  stats:
    socket: "127.0.0.1:9999"
EOF

echo "INFO: Starting HAProxy Data Plane API on 127.0.0.1:5555..."
haproxy-dataplaneapi --config-file /tmp/haproxy-dataplaneapi.hcl &
sleep 1

echo "INFO: Starting HAProxy..."
exec haproxy -f /haproxy.cfg -W -db



======================================================================================================
healthcheck.sh:

#!/bin/sh
#
# healthcheck.sh
#   - Validates HAProxy config syntax.
#   - Checks internal FRP port (127.0.0.1:7100).
#   - Checks either 3 or 6 frontends depending on whether /certs/cert.pem exists.
#   - Checks if Data Plane API is listening on 127.0.0.1:5555.
#
# This script returns 0 if all checks pass, 1 otherwise.

# 1) Validate HAProxy config
haproxy -c -f /haproxy.cfg || exit 1

if ! command -v nc >/dev/null 2>&1; then
  echo "ERROR: 'nc' command not found. Install netcat."
  exit 1
fi

# 2) Check internal FRP port
if ! nc -z 127.0.0.1 7100; then
  echo "ERROR: FRP server not responding on 127.0.0.1:7100"
  exit 1
fi

# 2) Check internal Data Plane port
if ! nc -z 127.0.0.1 5555; then
  echo "ERROR: Data Plane API not responding on 127.0.0.1:5555"
  exit 1
fi

# 3) Decide which frontends to check
CERT_PRESENT=0
if [ -f "/certs/cert.pem" ]; then
  CERT_PRESENT=1
fi

# Helper: netcat a given "host:port"
check_port () {
  local fulladdr="$1"
  # If "host" is 0.0.0.0, netcat to 127.0.0.1. Otherwise, use the given host.
  local host_part="$(echo "$fulladdr" | cut -d':' -f1)"
  local port_part="$(echo "$fulladdr" | cut -d':' -f2)"

  if [ -z "$host_part" ] || [ -z "$port_part" ]; then
    echo "WARN: Cannot parse $fulladdr"
    return 0
  fi

  # If host_part is 0.0.0.0, override with 127.0.0.1
  [ "$host_part" = "0.0.0.0" ] && host_part="127.0.0.1"

  if ! nc -z -w 2 "$host_part" "$port_part"; then
    echo "ERROR: HAProxy not listening on $fulladdr"
    exit 1
  fi
}

# Check environment variables for addresses
# We always check the 3 HTTP addresses
check_port "${HP_EXAPPS_ADDRESS:-0.0.0.0:8780}"
check_port "${HP_FRP_ADDRESS:-0.0.0.0:8782}"
check_port "${HP_CONTROL_ADDRESS:-0.0.0.0:8784}"

# If there's a cert, we also check the HTTPS addresses
if [ "$CERT_PRESENT" -eq 1 ]; then
  check_port "${HP_EXAPPS_HTTPS_ADDRESS:-0.0.0.0:8781}"
  check_port "${HP_FRP_HTTPS_ADDRESS:-0.0.0.0:8783}"
  check_port "${HP_CONTROL_HTTPS_ADDRESS:-0.0.0.0:8785}"
fi

echo "OK: All checks passed. FRP, Data Plane API, and HAProxy appear operational."
exit 0




======================================================================================================
haproxy.cfg.template:

###############################################################################
# haproxy.cfg.template
#
# This template is processed by envsubst in start.sh to replace variables:
#   HP_EXAPPS_ADDRESS,
#   HP_EXAPPS_HTTPS_ADDRESS,
#   HP_FRP_ADDRESS,
#   HP_FRP_HTTPS_ADDRESS,
#   HP_CONTROL_ADDRESS,
#   HP_CONTROL_HTTPS_ADDRESS,
#   HP_TIMEOUT_CONNECT,
#   HP_TIMEOUT_CLIENT,
#   HP_TIMEOUT_SERVER,
#   NC_INSTANCE_URL,
#   NC_HAPROXY_SHARED_KEY
#
# If /certs/cert.pem is not found, lines containing "_HTTPS_FRONTEND_" are
# commented out automatically in start.sh.
###############################################################################

global
    log stdout local0 debug
    maxconn 8192
    ca-base /etc/ssl/certs

    # Data Plane / Runtime API socket
    stats socket 127.0.0.1:9999 level admin expose-fd listeners

defaults
    log global
    option httplog
    option dontlognull
    timeout connect ${HP_TIMEOUT_CONNECT}
    timeout client ${HP_TIMEOUT_CLIENT}
    timeout server ${HP_TIMEOUT_SERVER}

###############################################################################
# Basic Auth user for nextcloud_control frontends
###############################################################################
userlist nextcloud_control_users
    user app_api_haproxy_user insecure-password ${NC_HAPROXY_SHARED_KEY}

###############################################################################
# Stats page, bound to 127.0.0.1:8404.
###############################################################################
listen stats
    bind 0.0.0.0:8404
    mode http
    stats enable
    stats uri /
    stats refresh 5s

###############################################################################
# FRONTEND: ex_apps (HTTP)
###############################################################################
frontend ex_apps
    mode http
    bind ${HP_EXAPPS_ADDRESS}

    # Track IP in bk_bruteforce (sc0) and bk_harp_bruteforce (sc1)
    http-request track-sc0 src table bk_bruteforce
    http-request track-sc1 src table bk_harp_bruteforce

    # Define ACLs to check stick table conditions
    acl is_in_bk_bruteforce src -m found table bk_bruteforce
    acl has_excessive_attempts sc1_http_req_rate(gt) 5

    # 1) If IP is in bk_bruteforce, silently drop
    http-request silent-drop if is_in_bk_bruteforce

    # 2) If IP has more than 5 failing attempts in 5 min, silent-drop
    http-request silent-drop if has_excessive_attempts

    default_backend ex_apps_backend

backend ex_apps_backend
    mode http
    server ex_apps_placeholder 127.0.0.1:9000

###############################################################################
# FRONTEND: ex_apps_https (only enabled if /certs/cert.pem exists)
###############################################################################
_HTTPS_FRONTEND_ frontend ex_apps_https
_HTTPS_FRONTEND_     mode http
_HTTPS_FRONTEND_     bind ${HP_EXAPPS_HTTPS_ADDRESS} ssl crt /certs/cert.pem

_HTTPS_FRONTEND_     # Track IP in bk_bruteforce (sc0) and bk_harp_bruteforce (sc1)
_HTTPS_FRONTEND_     http-request track-sc0 src table bk_bruteforce
_HTTPS_FRONTEND_     http-request track-sc1 src table bk_harp_bruteforce

_HTTPS_FRONTEND_     # 1) If IP is in bk_bruteforce, silently drop
_HTTPS_FRONTEND_     http-request silent-drop if { sc0_exists }

_HTTPS_FRONTEND_     # 2) If IP has more than 5 failing attempts in 5 min, silent-drop
_HTTPS_FRONTEND_     http-request silent-drop if { sc1_http_req_rate gt 5 }

_HTTPS_FRONTEND_     default_backend ex_apps_backend

###############################################################################
# FRONTEND: FRP (TCP)
###############################################################################
frontend frp
    option tcplog
    mode tcp
    bind ${HP_FRP_ADDRESS}

    # Track IP in bk_bruteforce (sc0) and bk_harp_bruteforce (sc1)
    tcp-request connection track-sc0 src table bk_bruteforce
    tcp-request connection track-sc1 src table bk_harp_bruteforce

    # Define ACLs to check stick table conditions
    acl is_in_bk_bruteforce src -m found table bk_bruteforce
    acl has_excessive_attempts sc1_http_req_rate(gt) 5

    # 1) If IP is in bk_bruteforce, silently drop
    http-request silent-drop if is_in_bk_bruteforce

    # 2) If IP has more than 5 failing attempts in 5 min, silent-drop
    http-request silent-drop if has_excessive_attempts

    default_backend frp_backend

backend frp_backend
    mode tcp
    # The internal FRP server runs at 127.0.0.1:7100
    server frp_server 127.0.0.1:7100

###############################################################################
# FRONTEND: frp_https (only enabled if /certs/cert.pem exists)
###############################################################################
_HTTPS_FRONTEND_ frontend frp_https
_HTTPS_FRONTEND_     mode tcp
_HTTPS_FRONTEND_     bind ${HP_FRP_HTTPS_ADDRESS} ssl crt /certs/cert.pem

_HTTPS_FRONTEND_     # Track IP in bk_bruteforce (sc0) and bk_harp_bruteforce (sc1)
_HTTPS_FRONTEND_     tcp-request connection track-sc0 src table bk_bruteforce
_HTTPS_FRONTEND_     tcp-request connection track-sc1 src table bk_harp_bruteforce

_HTTPS_FRONTEND_     # 1) If IP is in bk_bruteforce, silently drop
_HTTPS_FRONTEND_     tcp-request connection silent-drop if { sc0_exists }

_HTTPS_FRONTEND_     # 2) If IP has more than 5 failing attempts in 5 min, silent-drop
_HTTPS_FRONTEND_     tcp-request connection silent-drop if { sc1_conn_rate gt 5 }

_HTTPS_FRONTEND_     default_backend frp_backend

###############################################################################
# FRONTEND: nextcloud_control (HTTP)
###############################################################################
frontend nextcloud_control
    mode http
    bind ${HP_CONTROL_ADDRESS}

    # Protect with Basic Auth
    http-request auth realm "Nextcloud Control" if !{ http_auth(nextcloud_control_users) }

    # Track IP in bk_bruteforce (sc0) and bk_harp_bruteforce (sc1)
    http-request track-sc0 src table bk_bruteforce
    http-request track-sc1 src table bk_harp_bruteforce

    # Define ACLs to check stick table conditions
    acl is_in_bk_bruteforce src -m found table bk_bruteforce
    acl has_excessive_attempts sc1_http_req_rate(gt) 5

    # 1) If IP is in bk_bruteforce, silently drop
    http-request silent-drop if is_in_bk_bruteforce

    # 2) If IP has more than 5 failing attempts in 5 min, silent-drop
    http-request silent-drop if has_excessive_attempts

    default_backend dataplane_backend

backend dataplane_backend
    mode http
    server dataplane 127.0.0.1:5555

###############################################################################
# FRONTEND: nextcloud_control_https (only enabled if /certs/cert.pem exists)
###############################################################################
_HTTPS_FRONTEND_ frontend nextcloud_control_https
_HTTPS_FRONTEND_     mode http
_HTTPS_FRONTEND_     bind ${HP_CONTROL_HTTPS_ADDRESS} ssl crt /certs/cert.pem
_HTTPS_FRONTEND_     http-request auth realm "Nextcloud Control" if !{ http_auth(nextcloud_control_users) }

_HTTPS_FRONTEND_     # Track IP in bk_bruteforce (sc0) and bk_harp_bruteforce (sc1)
_HTTPS_FRONTEND_     http-request track-sc0 src table bk_bruteforce
_HTTPS_FRONTEND_     http-request track-sc1 src table bk_harp_bruteforce

_HTTPS_FRONTEND_     # 1) If IP is in bk_bruteforce, silently drop
_HTTPS_FRONTEND_     http-request silent-drop if { sc0_exists }

_HTTPS_FRONTEND_     # 2) If IP has more than 5 failing attempts in 5 min, silently drop
_HTTPS_FRONTEND_     http-request silent-drop if { sc1_http_req_rate gt 5 }

_HTTPS_FRONTEND_     default_backend dataplane_backend


###############################################################################
# These backends are used only for global stick-table definitions, so HAProxy
# can store / manage data for brute-forcing, exapps cache, sessions, etc.
###############################################################################

backend bk_bruteforce
    # This table is managed externally (e.g., by Nextcloud via DataPlane API)
    # to store IPs that should be permanently or temporarily banned.
    stick-table type ip size 1m expire 0 store binary

backend bk_harp_bruteforce
    # This table is managed by HaProxy or externally to count failing attempts.
    # If sc1_http_req_rate (for HTTP) or sc1_conn_rate (for TCP) > 5 in 5 minutes,
    # we drop or reject the request.
    stick-table type ip size 1m expire 144m store gpc0,http_req_rate(5m),conn_rate(5m)

backend bk_exapps_cache
    # This stick table stores information about ExApps tokens and route definitions.
    # The key is an ExApp ID (a string).
    # Used by Lua scripts for routing logic.
    #
    # Nextcloud, through the DataPlane API, may remove records when ExApps information changes.
    #
    # Each record's value is an encoded JSON string in the following format:
    # {
    #   "app_api_token": str,       # Token for authenticating ExApp requests
    #   "routes": [
    #     {
    #       "url": str,            # A regex pattern for matching the URL path, e.g. "^api\/w\/nextcloud\/jobs\/.*"
    #       "verb": str,           # HTTP methods (e.g., "GET", "POST", "PUT", "DELETE").
    #                              # An empty value ("") indicates that all methods (*) are allowed.
    #       "access_level": str,   # One of "ADMIN", "USER", "PUBLIC"
    #       "headers_to_exclude": list[str],
    #                              # A list of header names to exclude when forwarding requests to the ExApp.
    #       "bruteforce_protection": list[int]
    #                              # HTTP status codes for which brute-force protection applies on this route.
    #     }
    #   ]
    # }
    stick-table type string size 1k expire 1440m store string

backend bk_sessions_cache
    # This stick table stores information about users. The key is the Nextcloud "session_passphrase" (a string).
    # Used by Lua scripts for session validation.
    #
    # Nextcloud, through the DataPlane API, may remove records when a session becomes invalid.
    #
    # Each record's value is an encoded JSON string in the following format:
    # {
    #   "user_id": str,       # The Nextcloud user ID.
    #   "access_level": str   # One of "ADMIN", "USER", "PUBLIC"
    # }
    stick-table type string size 100k expire 1440m store string




======================================================================================================

Current task:

we found out that XAProxy does not support custom data in tables (`store string` - does not work) - total work for two days was smashed up.

Therefore, we need to figure out what we will do and how to store `bk_exapps_cache` and `bk_sessions_cache`

1. We want you to add Redis to the container(install it from official Alpine package) - run it in "start.sh"
2. Add check for Redis running in "healthcheck.sh"
3. We will hold "bk_exapps_cache" and "bk_sessions_cache" tables in Redis
4. Using HaProxy SPOE agent for now for test we want just for test that this approach will work a small agent that prints to "log_test.txt" the headers and cookies of each request from "frontend ex_apps_https"
5. SPOE agent should  connect to redis and print to "log_redis.txt" the contents of "bk_sessions_cache" for each input request on "frontend ex_apps_https"

For now redis should be pinned only to "localhost", it should be not available for outside.

This will let us know that the basic concept will work. Please output all the contents of the files that were changed.

**Comments in the files should remain in the same styles as they are.**
