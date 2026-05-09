#!/bin/bash
set -euo pipefail

# Minimal end-to-end test
# 1) build
# 2) start daemon (15353)
# 3) create network + ipset via prepare-network (which also adds the DNS rerouting iptables rule)
# 4) curl example.com (expect success)
# 5) curl google.com (expect failure)
# 6) cleanup

cargo build

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
DOCKERWALL="$TARGET_DIR/debug/dockerwall"

sudo pkill -9 dockerwall 2>/dev/null || true
sudo rm -f /run/dockerwall.sock 2>/dev/null || true

# (iptables redirect is now handled by the helper)

sudo $DOCKERWALL daemon --dns-listen-addr 0.0.0.0:15353 >/tmp/dockerwall.log 2>&1 &
DAEMON_PID=$!

for i in {1..10}; do
  [ -S /run/dockerwall.sock ] && break || sleep 1
done
if [ ! -S /run/dockerwall.sock ]; then
  echo "daemon control socket not available"
  sudo pkill -9 dockerwall || true
  exit 1
fi

sudo $DOCKERWALL prepare-network test-net "*.example.com"
GW=$(docker network inspect test-net --format '{{(index .IPAM.Config 0).Gateway}}')

# quick curl checks
docker run --rm --network test-net --dns "$GW" curlimages/curl:latest -sS --max-time 10 http://example.com >/dev/null
echo "example.com OK"

if docker run --rm --network test-net --dns "$GW" curlimages/curl:latest -sS --max-time 10 http://google.com >/dev/null; then
  echo "google.com reachable (FAIL)"
  EXIT_CODE=1
else
  echo "google.com blocked as expected"
  EXIT_CODE=0
fi

echo "--- Statistics Report ---"
sudo $DOCKERWALL stats
echo "------------------------"

# cleanup
sudo pkill -9 dockerwall 2>/dev/null || true
sudo docker network rm test-net 2>/dev/null || true

exit $EXIT_CODE
