#!/bin/bash
set -e

# Check if the configuration file already exists
if [ -f /frpc.toml ]; then
    echo "/frpc.toml already exists, skipping creation."
else
    # Only create a config file if HP_SHARED_KEY is set.
    if [ -n "$HP_SHARED_KEY" ]; then
        echo "HP_SHARED_KEY is set, creating /frpc.toml configuration file..."
        if [ -d "/certs/frp" ]; then
            echo "Found /certs/frp directory. Creating configuration with TLS certificates."
            cat <<EOF > /frpc.toml
serverAddr = "$HP_FRP_ADDRESS"
serverPort = $HP_FRP_PORT
metadatas.token = "$HP_SHARED_KEY"
transport.tls.certFile = "/certs/frp/client.crt"
transport.tls.keyFile = "/certs/frp/client.key"
transport.tls.trustedCaFile = "/certs/frp/ca.crt"
transport.tls.serverName = "harp.nc"

[[proxies]]
name = "$APP_ID"
type = "tcp"
localIP = "127.0.0.1"
localPort = $APP_PORT
remotePort = $APP_PORT
EOF
        else
            echo "Directory /certs/frp not found. Creating configuration without TLS certificates."
            cat <<EOF > /frpc.toml
serverAddr = "$HP_FRP_ADDRESS"
serverPort = $HP_FRP_PORT
metadatas.token = "$HP_SHARED_KEY"

[[proxies]]
name = "$APP_ID"
type = "tcp"
localIP = "127.0.0.1"
localPort = $APP_PORT
remotePort = $APP_PORT
EOF
        fi
    else
        echo "HP_SHARED_KEY is not set. Skipping FRP configuration."
    fi
fi

# If we have a configuration file and the shared key is present, start the FRP client
if [ -f /frpc.toml ] && [ -n "$HP_SHARED_KEY" ]; then
    echo "Starting frpc in the background..."
    frpc -c /frpc.toml &
fi

# Start the main Python application
echo "Starting main application..."
exec python3 main.py
