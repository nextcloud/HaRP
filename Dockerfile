# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# -------------------------------------------------------------------------
# Dockerfile for HaRP (HAProxy + FRP + Python SPOE agent),
# with frontends(HTTP/HTTPS) for Nextcloud Control and ExApps.
#
# Usage example:
#   docker build -t harp-prod .
#   docker run -d \
#     -p 8780:8780 \
#     -p 8781:8781 \
#     -p 8782:8782 \
#     -e HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
#     -e HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781" \
#     -e HP_FRP_ADDRESS="0.0.0.0:8782" \
#     -e HP_SHARED_KEY="mysecret" \
#     --name harp-prod \
#     harp-prod
#
# NOTES:
#  - If you mount /certs/cert.pem into the container, HTTPS frontend will be enabled.
#  - HP_SHARED_KEY or HP_SHARED_KEY_FILE must be provided at runtime.
# -------------------------------------------------------------------------

FROM docker.io/library/haproxy:3.2.22-alpine3.24

USER root

# Bind addresses for 2 frontends (HTTP + HTTPS for exapps) and FRP Server.
# If /certs/cert.pem does not exist, EXAPPS HTTPS frontend are disabled automatically.
ENV HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
    HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781" \
    HP_FRP_ADDRESS="0.0.0.0:8782" \
    HP_SPOA_ADDRESS="127.0.0.1:9600" \
    HP_FRP_DISABLE_TLS="false" \
    HP_TIMEOUT_CONNECT="30s" \
    HP_TIMEOUT_CLIENT="30s" \
    HP_TIMEOUT_SERVER="1800s" \
    NC_INSTANCE_URL="" \
    HP_TRUSTED_PROXY_IPS="" \
    HP_LOG_LEVEL="warning"

# NOTE: We do NOT define HP_SHARED_KEY or HP_SHARED_KEY_FILE here
# because they must be provided at runtime for security reasons.

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
    chmod -R 777 /tmp;

# Install the Python SPOA library.
# Pinned to a commit: the single-write frame emission it contains is required for
# HAProxy 3.2+, whose SPOP mux resets connections when a frame arrives split
# across TCP segments. Bump this deliberately together with the library.
RUN pip install --break-system-packages \
        pydantic==2.13.4 \
        git+https://github.com/cloud-py-api/haproxy-python-spoa.git@f00f3f7b1b0f56e10052af6c0d07e81c5195d84d

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
# The haproxy base image sets STOPSIGNAL SIGUSR1 (graceful stop for haproxy as PID 1).
# PID 1 is now the supervising start.sh, and the kernel drops default-disposition
# signals for PID 1, so USR1 would be ignored and `docker stop` would end in SIGKILL.
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=10s --retries=9 CMD /healthcheck.sh

LABEL com.centurylinklabs.watchtower.enable="false"
