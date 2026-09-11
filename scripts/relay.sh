#!/usr/bin/env bash
# scripts/relay.sh -- build the relay image and expose it via a Cloudflare
# quick tunnel, for people who don't want to set up their own TLS/DNS.
#
# v1's version of this script had a broken shebang-adjacent check
# (`if! command -v docker`, missing the space before `!`, which is a syntax
# error in bash), used `cd..` (also a syntax error -- no space before `..`),
# and never told you the resulting tunnel URL doubles as your relay's
# DoH endpoint. Fixed here, plus set -euo pipefail so it stops on the first
# real failure instead of plowing ahead with confusing follow-on errors.
set -euo pipefail

IMAGE_TAG="power-dns:latest"
CONTAINER_NAME="power-dns-relay"
LOG_FILE="${HOME}/power-dns-tunnel.log"

cd "$(dirname "$0")/.."

if ! command -v docker &>/dev/null; then
	echo "Docker is not installed. Installing it now..."
	sudo curl -fsSL -O https://get.docker.com | sh
fi

if ! command -v cloudflared &>/dev/null; then
	echo "cloudflared is not installed. Install it from:"
	echo "  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
	exit 1
fi

echo "Building docker image ..."
docker build -t "$IMAGE_TAG" .

echo "Removing any previous $CONTAINER_NAME container ..."
docker rm -f "$CONTAINER_NAME" &>/dev/null || true

echo "Running power-dns relay container ..."
docker run --name "$CONTAINER_NAME" -p 8000:8000 -d "$IMAGE_TAG"

echo "Starting Cloudflare quick tunnel ..."
nohup cloudflared tunnel --url localhost:8000 --edge-ip-version auto --no-autoupdate --protocol http2 >>"$LOG_FILE" 2>&1 &

echo "Waiting for the tunnel URL ..."
sleep 5
TUNNEL_URL=$(grep -oE 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' "$LOG_FILE" | tail -1 || true)

if [ -z "$TUNNEL_URL" ]; then
	echo "Couldn't find the tunnel URL yet -- check $LOG_FILE and retry in a few seconds."
	exit 1
fi

echo ""
echo "Relay is live. Your client's [relay].url is:"
echo "  ${TUNNEL_URL}/dns-query"
