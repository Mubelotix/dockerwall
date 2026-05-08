#!/bin/bash
set -e

cleanup() {
    echo "Cleaning up..."
    sudo kill $DAEMON_PID 2>/dev/null || true
    sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 15353 2>/dev/null || true
    sudo docker network rm test-net 2>/dev/null || true
}

trap cleanup EXIT

echo "Building..."
cargo build

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
DOCKERWALL="$TARGET_DIR/debug/dockerwall"

echo "Killing any existing dockerwall processes and removing socket..."
sudo pkill -9 dockerwall 2>/dev/null || true
sudo rm -f /run/dockerwall.sock 2>/dev/null || true
sleep 1

echo "Installing iptables redirect: UDP/53 -> 15353 (all interfaces)"
sudo iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 15353

echo "Starting daemon on port 15353 (listening on 0.0.0.0)..."
sudo $DOCKERWALL daemon --dns-listen-addr 0.0.0.0:15353 > /tmp/dockerwall.log 2>&1 &
DAEMON_PID=$!
sleep 3

echo "Waiting for control socket..."
for i in {1..10}; do
    if [ -S /run/dockerwall.sock ]; then
        break
    fi
    sleep 1
done

echo "Preparing network for example.com..."
sudo $DOCKERWALL prepare-network test-net "*.example.com"

# get the gateway IP for the created network so containers can use the host DNS proxy
GW=$(docker network inspect test-net --format '{{(index .IPAM.Config 0).Gateway}}')
echo "Using network gateway as DNS: $GW"

echo "Verifying test-net network created..."
docker network ls | grep -q test-net
echo "✓ test-net network created"

echo "Verifying ipset 'test-net' created..."
sudo ipset list test-net > /dev/null
echo "✓ ipset test-net created"

echo "Testing curl to example.com from container (should succeed)..."
docker run --rm --network test-net --dns $GW curlimages/curl:latest -sS --max-time 10 http://example.com -o /dev/null
echo "✓ example.com accessible"

echo "Testing curl to google.com from container (should fail)..."
if docker run --rm --network test-net --dns $GW curlimages/curl:latest -sS --max-time 10 http://google.com -o /dev/null; then
    echo "✗ google.com accessible (expected inaccessible)"
    exit 1
fi
echo "✓ google.com blocked as expected"
echo "All tests passed!"

echo "All tests passed!"
