#!/bin/sh

# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# healthcheck.sh
#   - Validates HAProxy config syntax.
#   - Checks if Python SPOE HTTP Control API is listening on 127.0.0.1:8200.
#   - Checks if SPOE Agent is running on HP_SPOA_ADDRESS (default 127.0.0.1:9600).
#   - Checks FRP port at HP_FRP_ADDRESS.
#   - Checks EXAPPS HTTP frontend, and also the EXAPPS HTTPS frontend if haproxy.cfg defines it.
#
# This script returns 0 if all checks pass, 1 otherwise.

# Determine config directory: start.sh uses /haproxy.cfg whenever it exists
if [ -f "/haproxy.cfg" ]; then
  CFG_DIR=""
else
  CFG_DIR="/run/harp"
fi

# 1) Validate HAProxy config
haproxy -c -f "${CFG_DIR}/haproxy.cfg" || exit 1

if ! command -v nc >/dev/null 2>&1; then
  echo "ERROR: 'nc' command not found. Install netcat."
  exit 1
fi

# 2) Check the agent answers HTTP on 127.0.0.1:8200: a wedged agent still accepts TCP,
#    so `nc -z` cannot detect it. The SPOA listener shares the same event loop.
if ! curl -fsS --noproxy '*' --max-time 5 http://127.0.0.1:8200/heartbeat >/dev/null 2>&1; then
  echo "ERROR: HaRP agent is not responding on 127.0.0.1:8200"
  exit 1
fi

# Helper: netcat a given "host:port"
check_port () {
  local fulladdr
  # Strip quotes as start.sh does
  fulladdr="$(echo "$1" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
  # The port follows the last ':'; an IPv6 host may be in brackets
  local host_part="${fulladdr%:*}"
  local port_part="${fulladdr##*:}"
  host_part="${host_part#\[}"
  host_part="${host_part%\]}"

  if [ -z "$host_part" ] || [ -z "$port_part" ]; then
    echo "WARN: Cannot parse $fulladdr"
    return 0
  fi

  # If host_part is 0.0.0.0, override with 127.0.0.1
  [ "$host_part" = "0.0.0.0" ] && host_part="127.0.0.1"

  # A [::] socket answers on ::1, or on 127.0.0.1 when the loopback has no IPv6
  if [ "$host_part" = "::" ]; then
    nc -z -w 2 ::1 "$port_part" 2>/dev/null && return 0
    host_part="127.0.0.1"
  fi

  if ! nc -z -w 2 "$host_part" "$port_part"; then
    echo "ERROR: Service not listening on $fulladdr"
    exit 1
  fi
}

# 3) Check SPOE Agent port
check_port "${HP_SPOA_ADDRESS:-127.0.0.1:9600}"

# 4) Check FRP port
check_port "${HP_FRP_ADDRESS:-0.0.0.0:8782}"

# 5) We always check the EXAPPS HTTP frontend
check_port "${HP_EXAPPS_ADDRESS:-0.0.0.0:8780}"

# The EXAPPS HTTPS frontend only if the config in use defines it
if grep -qE '^[[:space:]]*frontend[[:space:]]+ex_apps_https([[:space:]]|$)' "${CFG_DIR}/haproxy.cfg"; then
  check_port "${HP_EXAPPS_HTTPS_ADDRESS:-0.0.0.0:8781}"
fi

echo "OK: All checks passed. FRP, HAProxy agent and HAProxy itself appear to be working."
exit 0
