#!/bin/sh
# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# This file can be used for development for the "manual install" deployment type when FRP is disabled.
# For Julius Docker-Dev, you need to additionally edit the `data/nginx/vhost.d/nextcloud.local_location` file,
# changing `appapi-harp` to `172.17.0.1` and restart the "proxy" container.

docker container remove --force appapi-harp

docker build -t nextcloud-appapi-harp:local .

docker run \
  -e HP_SHARED_KEY="some_very_secure_password" \
  -e NC_INSTANCE_URL="http://nextcloud.local" \
  -e HP_LOG_LEVEL="info" \
  -e HP_VERBOSE_START="1" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v `pwd`/certs:/certs \
  --name appapi-harp -h appapi-harp \
  --restart unless-stopped \
  --network=host \
  -d nextcloud-appapi-harp:local
