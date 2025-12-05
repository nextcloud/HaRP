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
  -e HP_LOG_LEVEL="debug" \
  -e HP_VERBOSE_START="1" \
  -e HP_K8S_ENABLED="true" \
  -e HP_K8S_API_SERVER="https://127.0.0.1:37151" \
  -e HP_K8S_BEARER_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6InJwSHRRN04wV0RwcHFiVEtJLVdHblpGTllKMGJwc3NZZ2tZYjRrREdhcEkifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzczNTgwODI1LCJpYXQiOjE3NjQ5NDA4MjUsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiOTBmOTE0MjUtMDYxMy00YzM4LTllNmQtN2U2Y2I1Njk4MDhhIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJuZXh0Y2xvdWQtZXhhcHBzIiwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImhhcnAtZXhhcHBzIiwidWlkIjoiMzI2ZTA5NzEtMGIyOC00NzBkLTlmZTUtMDRjMTc0YjE2ODQ2In19LCJuYmYiOjE3NjQ5NDA4MjUsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpuZXh0Y2xvdWQtZXhhcHBzOmhhcnAtZXhhcHBzIn0.TSDUSEe0NuFMhycrK1XHNgBV3-L70qqLfCR2-x0XSSXGSsms1ZzxKbSnsDDCstAGg6-ZtlJroWFZZiFeZ2E2j53z2-Tt4lXM-ZdH7qqhjsxSh5Ya7l3ncMSS0Tw1YPaEsOJmpXCiDH9KE4g-KyLeSJU5Rqonc5fuWJwDd68wpY8SB2qkgbtr250Srk4nYw28MyxhgXwHvOSIrDhqmGR-NPPmSeoa9u9etAD9qjfCPauF0BYDBcVHGKR2kJL5oGw9-tRs6FqBAt5U-y4Jx6y0Q1RPptdbpHGY9KmSGHIqsLrkJl7lgjlZh4mb2wofwypJvBd2hW_dgS1RTrzcTjoYsQ" \
  -e HP_K8S_NAMESPACE="nextcloud-exapps" \
  -e HP_K8S_VERIFY_SSL="false" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v `pwd`/certs:/certs \
  --name appapi-harp -h appapi-harp \
  --restart unless-stopped \
  --network=host \
  -d nextcloud-appapi-harp:local
