#!/bin/sh
# SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e

docker container remove --force appapi-harp || true

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
  --network=master_default \
  -p 8780:8780 \
  -p 8782:8782 \
  -d nextcloud-appapi-harp:local
