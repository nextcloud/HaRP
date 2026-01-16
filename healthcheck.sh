#!/bin/sh

# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# healthcheck.sh
#   - Validates HAProxy config syntax.
#   - Checks if Python SPOE HTTP Control API is listening on 127.0.0.1:8200.
#   - Checks if SPOE Agent is running on HP_SPOA_ADDRESS (default 127.0.0.1:9600).
#   - Checks FRP port at HP_FRP_ADDRESS.
#   - Checks EXAPPS HTTP frontend, and also the EXAPPS HTTPS frontend if the /certs/cert.pem file exists.
#
# This script returns 0 if all checks pass, 1 otherwise.

# 1) Validate HAProxy config
haproxy -c -f /haproxy.cfg || exit 1

if ! command -v nc >/dev/null 2>&1; then
  echo "ERROR: 'nc' command not found. Install netcat."
  exit 1
fi

# 2) Check SPOE Agent Control API (Python HTTP) on 127.0.0.1:8200
if ! nc -z 127.0.0.1 8200; then
  echo "ERROR: Data Plane API not responding on 127.0.0.1:8200"
  exit 1
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
    echo "ERROR: Service not listening on $fulladdr"
    exit 1
  fi
}

# 3) Check SPOE Agent port
check_port "${HP_SPOA_ADDRESS:-127.0.0.1:9600}"

# 4) Check FRP port
check_port "${HP_FRP_ADDRESS:-0.0.0.0:8782}"

# 5) Decide which frontends to check in HAProxy
CERT_PRESENT=0
if [ -f "/certs/cert.pem" ]; then
  CERT_PRESENT=1
fi

# We always check the EXAPPS HTTP frontend
check_port "${HP_EXAPPS_ADDRESS:-0.0.0.0:8780}"

# If there's a cert, we also check the EXAPPS HTTPS frontend
if [ "$CERT_PRESENT" -eq 1 ]; then
  check_port "${HP_EXAPPS_HTTPS_ADDRESS:-0.0.0.0:8781}"
fi

echo "OK: All checks passed. FRP, HAProxy agent and HAProxy itself appear to be working."
exit 0
