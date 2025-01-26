docker container remove --force harp-prod

docker build -t harp-prod .

docker run --rm \
  -p 8780:8780 \
  -p 8781:8781 \
  -p 8782:8782 \
  -p 8783:8783 \
  -p 8784:8784 \
  -p 8785:8785 \
  -p 8404:8404 \
  -e HP_EXAPPS_ADDRESS="0.0.0.0:8780" \
  -e HP_EXAPPS_HTTPS_ADDRESS="0.0.0.0:8781" \
  -e HP_FRP_ADDRESS="0.0.0.0:8782" \
  -e HP_FRP_HTTPS_ADDRESS="0.0.0.0:8783" \
  -e HP_CONTROL_ADDRESS="0.0.0.0:8784" \
  -e HP_CONTROL_HTTPS_ADDRESS="0.0.0.0:8785" \
  -e NC_HAPROXY_SHARED_KEY="mysecret" \
  -e NEXTCLOUD_CONTROL_DEBUG="1" \
  --name harp-prod \
  harp-prod
