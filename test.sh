#!/bin/bash
set -euo pipefail

# Minimal end-to-end test
# 1) build
# 2) start daemon (15353)
# 3) add iptables redirect so container DNS -> daemon
# 4) create network + ipset via prepare-network
# 5) curl example.com (expect success)
# 6) curl google.com (expect failure)
# 7) cleanup

cargo build

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
DOCKERWALL="$TARGET_DIR/debug/dockerwall"

sudo pkill -9 dockerwall 2>/dev/null || true
sudo rm -f /run/dockerwall.sock 2>/dev/null || true

# redirect container DNS (UDP/53) to daemon port
sudo iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 15353

sudo $DOCKERWALL daemon --dns-listen-addr 0.0.0.0:15353 >/tmp/dockerwall.log 2>&1 &
DAEMON_PID=$!

for i in {1..10}; do
  [ -S /run/dockerwall.sock ] && break || sleep 1
done
if [ ! -S /run/dockerwall.sock ]; then
  echo "daemon control socket not available"
  sudo pkill -9 dockerwall || true
  sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 15353 2>/dev/null || true
  exit 1
fi

sudo $DOCKERWALL prepare-network test-net "*.example.com"
GW=$(docker network inspect test-net --format '{{(index .IPAM.Config 0).Gateway}}')

# quick curl checks
docker run --rm --network test-net --dns $GW curlimages/curl:latest -sS --max-time 10 http://example.com >/dev/null
echo "example.com OK"

if docker run --rm --network test-net --dns $GW curlimages/curl:latest -sS --max-time 10 http://google.com >/dev/null; then
  echo "google.com reachable (FAIL)"
  EXIT_CODE=1
else
  echo "google.com blocked as expected"
  EXIT_CODE=0
fi

# cleanup
sudo pkill -9 dockerwall 2>/dev/null || true
sudo docker network rm test-net 2>/dev/null || true
sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 15353 2>/dev/null || true

exit $EXIT_CODE
