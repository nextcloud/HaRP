#!/bin/sh
#
# healthcheck.sh
#   - Validates HAProxy config syntax.
#   - Checks internal FRP port (127.0.0.1:7100).
#   - Checks either 3 or 6 frontends depending on whether /certs/cert.pem exists.
#   - Checks if Python SPOE HTTP Control API is listening on 127.0.0.1:8000.
#   - Checks if SPOE Agent is running on 127.0.0.1:9600.
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

# 2b) Check internal SPOE Agent Control API
if ! nc -z 127.0.0.1 8000; then
  echo "ERROR: Data Plane API not responding on 127.0.0.1:8000"
  exit 1
fi

# 2c) Check internal SPOE Agent port
if ! nc -z 127.0.0.1 9600; then
  echo "ERROR: Data Plane API not responding on 127.0.0.1:9600"
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

echo "OK: All checks passed. FRP, HAProxy agent and HAProxy itself appear to be working."
exit 0
