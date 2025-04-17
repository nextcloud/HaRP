#!/bin/sh
# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e

# ----------------------------------------------------------------------------
# start.sh
#  - Generates self-signed certificates for FRP Server and FRP Clients
#  - Generates /haproxy.cfg from haproxy.cfg.template
#  - Reads HP_SHARED_KEY or HP_SHARED_KEY_FILE
#  - Comments out HTTPS frontends if no /certs/cert.pem is found
#  - Starts FRP server (frps) on HP_FRP_ADDRESS
#  - Starts the Python SPOE agent on 127.0.0.1:9600
#  - Launches Python SPOE HTTP Control API on 127.0.0.1:8200
#  - Finally runs HAProxy in the foreground
#
#  NOTE:
#    Certificates are generated in the /certs/frp folder - they are used only by FRP and AppAPI.
#    If HP_FRP_DISABLE_TLS is set to "false"(default), self-signed certificates will be generated:
#      - CA key and certificate (ca.key, ca.crt)
#      - Server key, CSR, and certificate (server.key, server.csr, server.crt)
#      - Client key, CSR, and certificate (client.key, client.csr, client.crt)
#    We do not generate /certs/cert.pem file, as for HaProxy it is admin task to mount generated cert if needed.
# ----------------------------------------------------------------------------

HP_VERBOSE_START=${HP_VERBOSE_START:-1}
log() {
    if [ "$HP_VERBOSE_START" -eq 1 ]; then
        echo "$@"
    fi
}

# Check if the required environment variables are set
if [ -z "$HP_FRP_ADDRESS" ]; then
    echo "ERROR: HP_FRP_ADDRESS is not set."
    exit 1
fi
if [ -z "$NC_INSTANCE_URL" ]; then
    echo "ERROR: NC_INSTANCE_URL is not set."
    exit 1
fi

# Initialize FRP_HOST and FRP_PORT once to avoid parsing HP_FRP_ADDRESS multiple times.
FRP_HOST="$(echo "$HP_FRP_ADDRESS" | cut -d':' -f1)"
FRP_PORT="$(echo "$HP_FRP_ADDRESS" | cut -d':' -f2)"

# ----------------------------------------------------------------------------
# Map HP_LOG_LEVEL (our user-friendly strings) to valid HAProxy log levels
# ----------------------------------------------------------------------------
case "${HP_LOG_LEVEL}" in
  debug)
    HP_LOG_LEVEL_HAPROXY="debug"
    ;;
  info)
    HP_LOG_LEVEL_HAPROXY="info"
    ;;
  warning)
    HP_LOG_LEVEL_HAPROXY="warning"
    ;;
  error)
    HP_LOG_LEVEL_HAPROXY="err"
    ;;
  *)
    echo "WARNING: Unrecognized HP_LOG_LEVEL='${HP_LOG_LEVEL}', defaulting to 'warning'"
    HP_LOG_LEVEL_HAPROXY="warning"
    ;;
esac

export HP_LOG_LEVEL_HAPROXY

# ----------------------------------------------------------------------------
# Generate self-signed certs for FRP unless HP_FRP_DISABLE_TLS=true
# ----------------------------------------------------------------------------
if [ "${HP_FRP_DISABLE_TLS}" != "true" ]; then
    if [ ! -d "/certs/frp" ]; then
        mkdir -p /certs/frp
        log "INFO: /certs/frp directory created."
        log "INFO: Generating self-signed certificates in /certs/frp..."

        # Write OpenSSL configuration for server to /certs/frp/server-openssl.cnf.
        cat > /certs/frp/server-openssl.cnf <<EOF
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = harp.nc

[ req_ext ]
subjectAltName = DNS:harp.nc
EOF

        # Generate CA key and certificate.
        openssl genrsa -out /certs/frp/ca.key 2048
        openssl req -x509 -new -nodes -key /certs/frp/ca.key -subj "/CN=harp.nc" -days 5000 -out /certs/frp/ca.crt

        # Generate server key and CSR.
        openssl genrsa -out /certs/frp/server.key 2048
        openssl req -new -sha256 -key /certs/frp/server.key -subj "/CN=harp.nc" \
            -reqexts req_ext -config /certs/frp/server-openssl.cnf -out /certs/frp/server.csr

        # Sign the server certificate with the CA.
        openssl x509 -req -days 365 -sha256 -in /certs/frp/server.csr \
            -CA /certs/frp/ca.crt -CAkey /certs/frp/ca.key -CAcreateserial \
            -extfile /certs/frp/server-openssl.cnf -extensions req_ext -out /certs/frp/server.crt

        # Generate client key.
        openssl genrsa -out /certs/frp/client.key 2048

        # Write OpenSSL configuration for client to /certs/frp/client-openssl.cnf.
        cat > /certs/frp/client-openssl.cnf <<EOF
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = harp.client.nc

[ req_ext ]
subjectAltName = DNS:harp.client.nc
EOF

        # Generate client CSR & sign with CA.
        openssl req -new -sha256 -key /certs/frp/client.key -subj "/CN=harp.client.nc" \
            -config /certs/frp/client-openssl.cnf -out /certs/frp/client.csr

        openssl x509 -req -days 365 -sha256 -in /certs/frp/client.csr \
            -CA /certs/frp/ca.crt -CAkey /certs/frp/ca.key -CAcreateserial \
            -extfile /certs/frp/client-openssl.cnf -extensions req_ext -out /certs/frp/client.crt

        log "INFO: Certificate generation completed."
    fi
else
    log "INFO: HP_FRP_DISABLE_TLS is set to true. Skipping certificate generation."
fi

# ----------------------------------------------------------------------------
# Generate final /haproxy.cfg if not already present
# ----------------------------------------------------------------------------
if [ -f "/haproxy.cfg" ]; then
  log "INFO: /haproxy.cfg already present. Skipping config generation..."
else
  log "INFO: Creating /haproxy.cfg from haproxy.cfg.template..."

  if [ -n "$HP_SHARED_KEY_FILE" ] && [ ! -f "$HP_SHARED_KEY_FILE" ]; then
    echo "ERROR: HP_SHARED_KEY_FILE is specified but the file does not exist."
    exit 1
  fi

  if [ -n "$HP_SHARED_KEY" ] && [ -n "$HP_SHARED_KEY_FILE" ]; then
    echo "ERROR: Only one of HP_SHARED_KEY or HP_SHARED_KEY_FILE should be specified."
    exit 1
  fi

  if [ -n "$HP_SHARED_KEY_FILE" ]; then
    if [ -s "$HP_SHARED_KEY_FILE" ]; then
      HP_SHARED_KEY="$(cat "$HP_SHARED_KEY_FILE")"
    else
      echo "ERROR: HP_SHARED_KEY_FILE is specified but is empty."
      exit 1
    fi
  elif [ -n "$HP_SHARED_KEY" ]; then
    HP_SHARED_KEY="${HP_SHARED_KEY}"
  else
    echo "ERROR: Either HP_SHARED_KEY_FILE or HP_SHARED_KEY must be set."
    exit 1
  fi

  export HP_SHARED_KEY

  # Use envsubst to render the main configuration.
  envsubst < /haproxy.cfg.template > /haproxy.cfg

  # If we do not have a SSL cert for HAProxy, comment out the HTTPS frontends
  if [ -f "/certs/cert.pem" ]; then
    log "INFO: Found /certs/cert.pem, HTTPS frontends remain enabled."
    sed -i "/_HTTPS_FRONTEND_/ s|_HTTPS_FRONTEND_ ||g" /haproxy.cfg
    chmod 644 /certs/cert.pem
  else
    log "INFO: No /certs/cert.pem found, disabling HTTPS frontends..."
    sed -i "/_HTTPS_FRONTEND_/ s|^|#|g" /haproxy.cfg
  fi
fi

if [ "$HP_VERBOSE_START" -eq 1 ]; then
    log "INFO: Final /haproxy.cfg:"
    cat /haproxy.cfg
fi

# ----------------------------------------------------------------------------
# Prepare FRP configuration
# ----------------------------------------------------------------------------
if [ ! -f "/frps.toml" ]; then
  if [ "${HP_FRP_DISABLE_TLS}" != "true" ]; then
cat <<EOF >/frps.toml
bindAddr = "${FRP_HOST}"
bindPort = ${FRP_PORT}

transport.tls.force = true
transport.tls.certFile = "/certs/frp/server.crt"
transport.tls.keyFile = "/certs/frp/server.key"
transport.tls.trustedCaFile = "/certs/frp/ca.crt"

log.to = "/frps.log"
log.level = "info"
log.maxDays = 3

maxPortsPerClient = 1
allowPorts = [
  { start = 23000, end = 23999 },
  { start = 24000, end = 24099 }
]

[[httpPlugins]]
addr = "127.0.0.1:8200"
path = "/frp_handler"
ops = ["Login"]
EOF
  else
cat <<EOF >/frps.toml
bindAddr = "${FRP_HOST}"
bindPort = ${FRP_PORT}

transport.tls.force = false

log.to = "/frps.log"
log.level = "info"
log.maxDays = 3

maxPortsPerClient = 1
allowPorts = [
  { start = 23000, end = 23999 },
  { start = 24000, end = 24099 }
]

[[httpPlugins]]
addr = "127.0.0.1:8200"
path = "/frp_handler"
ops = ["Login"]
EOF
  fi
  log "INFO: FRP server configuration generated at /frps.toml."
else
  log "INFO: /frps.toml already exists. Skipping FRP server configuration generation..."
fi

# ----------------------------------------------------------------------------
# Prepare FRP client configuration for Docker if /var/run/docker.sock is present
# ----------------------------------------------------------------------------
if [ -e "/var/run/docker.sock" ]; then
  LOCAL_FRP_HOST="$FRP_HOST"
  [ "$LOCAL_FRP_HOST" = "0.0.0.0" ] && LOCAL_FRP_HOST="127.0.0.1"
  if [ ! -f "/frpc-docker.toml" ]; then
    log "INFO: Detected /var/run/docker.sock, generating /frpc-docker.toml configuration file..."
    if [ "${HP_FRP_DISABLE_TLS}" != "true" ]; then
cat <<EOF >/frpc-docker.toml
serverAddr = "${LOCAL_FRP_HOST}"
serverPort = ${FRP_PORT}

transport.tls.enable = true
transport.tls.certFile = "/certs/frp/client.crt"
transport.tls.keyFile = "/certs/frp/client.key"
transport.tls.trustedCaFile = "/certs/frp/ca.crt"
transport.tls.serverName = "harp.nc"

metadatas.token = "${HP_SHARED_KEY}"

[[proxies]]
remotePort = 24000
type = "tcp"
name = "bundled-deploy-daemon"
[proxies.plugin]
type = "unix_domain_socket"
unixPath = "/var/run/docker.sock"
EOF
    else
cat <<EOF >/frpc-docker.toml
serverAddr = "${LOCAL_FRP_HOST}"
serverPort = ${FRP_PORT}

transport.tls.enable = false

metadatas.token = "${HP_SHARED_KEY}"

[[proxies]]
remotePort = 24000
type = "tcp"
name = "bundled-deploy-daemon"
[proxies.plugin]
type = "unix_domain_socket"
unixPath = "/var/run/docker.sock"
EOF
    fi
  else
    log "INFO: /frpc-docker.toml already exists. Skipping generation..."
  fi
fi

log "INFO: Starting Python HaProxy Agent on 127.0.0.1:8200 and 127.0.0.1:9600..."
nohup python3 /usr/local/bin/haproxy_agent.py &

sleep 1s

log "INFO: Starting FRP server on ${HP_FRP_ADDRESS}..."
frps -c /frps.toml &

sleep 1s

if [ -e "/var/run/docker.sock" ]; then
  log "INFO: Starting FRP client for Docker Engine..."
  frpc -c /frpc-docker.toml &
fi

log "INFO: Starting HAProxy..."
exec haproxy -f /haproxy.cfg -W -db
