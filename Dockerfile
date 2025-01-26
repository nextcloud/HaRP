# -------------------------------------------------------------------------
# Dockerfile for HaRP (HAProxy + FRP + Python SPOE agent),
# with Nextcloud Control and flexible (HTTP/HTTPS) frontends for ExApps, FRP, and Control.
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
# NOTES:
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
        git \
        ca-certificates \
        tzdata \
        bash \
        curl \
        openssl \
        bind-tools \
        nano \
        vim \
        envsubst \
        frp \
        python3 \
        py3-pip \
        py3-aiohttp \
        wget \
        tar \
        netcat-openbsd; \
    chmod -R 777 /tmp; \
    wget -O /tmp/dataplaneapi.apk "https://github.com/haproxytech/dataplaneapi/releases/download/v3.0.4/dataplaneapi_3.0.4_linux_amd64.apk"; \
    apk add --no-cache --allow-untrusted /tmp/dataplaneapi.apk; \
    rm /tmp/dataplaneapi.apk

RUN pip install git+https://github.com/cloud-py-api/haproxy-python-spoa.git --break-system-packages && echo "1"

# Copy our scripts and templates
COPY --chmod=755 healthcheck.sh /healthcheck.sh
COPY --chmod=775 start.sh /usr/local/bin/start.sh

# Main haproxy config template
COPY --chmod=664 haproxy.cfg.template /haproxy.cfg.template

# SPOE config
COPY --chmod=664 spoe-agent.conf /etc/haproxy/spoe-agent.conf

# Python SPOE agent
COPY --chmod=755 haproxy_agent.py /usr/local/bin/haproxy_agent.py

ENTRYPOINT ["start.sh"]
HEALTHCHECK --interval=10s --timeout=10s --retries=9 CMD /healthcheck.sh

LABEL com.centurylinklabs.watchtower.enable="false"
