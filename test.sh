#!/bin/bash
set -e

docker container remove --force nextcloud-appapi-harp || true

docker build -t nextcloud-appapi-harp .

# with TLS (needs AppAPI support for this)
#docker run --rm \
#  -p 8780:8780 \
#  -p 8782:8782 \
#  -e HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
#  -e HP_FRP_ADDRESS="0.0.0.0:8782" \
#  -e NC_HARP_SHARED_KEY="mysecret" \
#  -e HP_LOG_LEVEL="info" \
#  -e HP_VERBOSE_START="1" \
#  -e NC_INSTANCE_URL="http://nextcloud.local" \
#  -v `pwd`/certs:/certs \
#  -v /var/run/docker.sock:/var/run/docker.sock \
#  --name nextcloud-appapi-harp \
#  --network=master_default \
#  nextcloud-appapi-harp


docker run --rm \
  -p 8780:8780 \
  -p 8781:8781 \
  -p 8782:8782 \
  -e HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
  -e HP_FRP_ADDRESS="0.0.0.0:8782" \
  -e NC_HARP_SHARED_KEY="mysecret" \
  -e HP_LOG_LEVEL="info" \
  -e HP_VERBOSE_START="1" \
  -e NC_INSTANCE_URL="http://nextcloud.local" \
  -e HP_FRP_DISABLE_TLS="true" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --name nextcloud-appapi-harp \
  --network=master_default \
  nextcloud-appapi-harp
