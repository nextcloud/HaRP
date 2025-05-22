# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

FROM haproxy:3.1.2-alpine3.21

USER root

# Bind addresses for 2 frontends (HTTP + HTTPS for exapps) and FRP Server.
# If /certs/cert.pem does not exist, EXAPPS HTTPS frontend are disabled automatically.
ENV HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
    HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781" \
    HP_FRP_ADDRESS="0.0.0.0:8782" \
    HP_FRP_DISABLE_TLS="false" \
    HP_TIMEOUT_CONNECT="30s" \
    HP_TIMEOUT_CLIENT="30s" \
    HP_TIMEOUT_SERVER="1800s" \
    NC_INSTANCE_URL="" \
    HP_LOG_LEVEL="warning"

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

# Main haproxy config template
COPY --chmod=664 ./development/debugging/haproxy.cfg /haproxy.cfg

# SPOE config
COPY --chmod=664 spoe-agent.conf /etc/haproxy/spoe-agent.conf

ENTRYPOINT ["haproxy", "-f", "/haproxy.cfg", "-W", "-db"]

LABEL com.centurylinklabs.watchtower.enable="false"
