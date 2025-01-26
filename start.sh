#!/bin/sh
set -e

# ----------------------------------------------------------------------------
# start.sh
#  - Generates /haproxy.cfg from haproxy.cfg.template
#  - Reads NC_HAPROXY_SHARED_KEY or NC_HAPROXY_SHARED_KEY_FILE
#  - Comments out HTTPS frontends if no /certs/cert.pem is found
#  - Starts FRP server (frps) on 127.0.0.1:7100 with token = NC_HAPROXY_SHARED_KEY
#  - Starts the Python SPOE agent on 127.0.0.1:9600
#  - Launches Python SPOE HTTP Control API on 127.0.0.1:8000
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

echo "INFO: Starting Python HaProxy Agent on 127.0.0.1:8000 and 127.0.0.1:9600..."
#nohup python3 /usr/local/bin/haproxy_agent.py > /haproxy_agent.log 2>&1 &
nohup python3 /usr/local/bin/haproxy_agent.py &

echo "INFO: Starting HAProxy..."
exec haproxy -f /haproxy.cfg -W -db
