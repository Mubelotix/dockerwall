#!/bin/bash
set -euo pipefail

NETWORK="test-rootless-podman"
ALLOWED_DOMAIN="example.com"
BLOCKED_DOMAIN="example.org"
IMAGE="docker.io/curlimages/curl:latest"

cargo build

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
DOCKERWALL="$TARGET_DIR/debug/dockerwall"
CONTROL_SOCKET="/run/dockerwall.sock"
DAEMON_PID=""
SOURCE_IP=""
OUTBOUND_INTERFACE=""
DNS_IP="198.18.0.1"
DNS_PORT="5354"
DNS_ALIAS_WAS_PRESENT=true
OUTPUT_CHAIN_WAS_PRESENT=true

remove_rule() {
  while sudo iptables "$@" >/dev/null 2>&1; do
    :
  done
}

cleanup() {
  if [ -n "$SOURCE_IP" ] && [ -n "$OUTBOUND_INTERFACE" ]; then
    local source_cidr="$SOURCE_IP/32"
    remove_rule -t nat -D POSTROUTING -s "$source_cidr" -o "$OUTBOUND_INTERFACE" -m comment --comment "dockerwall:$NETWORK:masquerade" -j MASQUERADE
    remove_rule -t nat -D OUTPUT -s "$source_cidr" -d "$DNS_IP/32" -p udp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-OUTPUT-udp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -t nat -D OUTPUT -s "$source_cidr" -d "$DNS_IP/32" -p tcp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-OUTPUT-tcp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -t nat -D PREROUTING -s "$source_cidr" -d "$DNS_IP/32" -p udp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-PREROUTING-udp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -t nat -D PREROUTING -s "$source_cidr" -d "$DNS_IP/32" -p tcp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-PREROUTING-tcp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -t nat -D POSTROUTING -s "$source_cidr" -d "$source_cidr" -p udp --sport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-response-snat-udp" -j SNAT --to-source 127.0.0.1
    remove_rule -t nat -D POSTROUTING -s "$source_cidr" -d "$source_cidr" -p tcp --sport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-response-snat-tcp" -j SNAT --to-source 127.0.0.1
    remove_rule -D OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:output-hook" -j DOCKERWALL-OUTPUT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:established" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -d 127.0.0.1/32 -p udp --dport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-udp" -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -d 127.0.0.1/32 -p tcp --dport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-tcp" -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -d "$source_cidr" -p udp --sport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-response-udp" -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -d "$source_cidr" -p tcp --sport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-response-tcp" -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:allow" -m set --match-set "$NETWORK" dst -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:drop" -j DROP
    sudo ip addr del "$source_cidr" dev "$OUTBOUND_INTERFACE" >/dev/null 2>&1 || true
    sudo ipset destroy "$NETWORK" >/dev/null 2>&1 || true
  fi

  if [ -n "$DAEMON_PID" ]; then
    sudo kill "$DAEMON_PID" >/dev/null 2>&1 || true
    sudo rm -f "$CONTROL_SOCKET"
  fi

  if [ "$DNS_ALIAS_WAS_PRESENT" = false ]; then
    sudo ip addr del "$DNS_IP/32" dev lo >/dev/null 2>&1 || true
  fi

  if [ "$OUTPUT_CHAIN_WAS_PRESENT" = false ]; then
    sudo iptables -X DOCKERWALL-OUTPUT >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ "$(podman info --format '{{.Host.Security.Rootless}}')" != true ]; then
  echo "this test requires rootless Podman"
  exit 1
fi

if [ -S "$CONTROL_SOCKET" ]; then
  echo "this test requires no existing Dockerwall daemon"
  exit 1
fi

# Match the system daemon's wildcard listener, which selects the Pasta source IP for replies.
sudo "$DOCKERWALL" daemon --dns-listen-addr "0.0.0.0:$DNS_PORT" >/tmp/dockerwall-rootless.log 2>&1 &
DAEMON_PID=$!

for _ in {1..10}; do
  [ -S "$CONTROL_SOCKET" ] && break || sleep 1
done
if [ ! -S "$CONTROL_SOCKET" ]; then
  echo "daemon control socket not available"
  exit 1
fi

if [[ "$(sudo ip -o -4 addr show dev lo)" == *"$DNS_IP/32"* ]]; then
  DNS_ALIAS_WAS_PRESENT=true
else
  DNS_ALIAS_WAS_PRESENT=false
fi

if sudo iptables -S DOCKERWALL-OUTPUT >/dev/null 2>&1; then
  OUTPUT_CHAIN_WAS_PRESENT=true
else
  OUTPUT_CHAIN_WAS_PRESENT=false
fi

set +e
PREPARE_OUTPUT="$(sudo "$DOCKERWALL" prepare-network --runtime podman "$NETWORK" "*.$ALLOWED_DOMAIN" 2>&1)"
PREPARE_STATUS=$?
set -e
printf '%s\n' "$PREPARE_OUTPUT"
if [ "$PREPARE_STATUS" -ne 0 ]; then
  echo "prepare-network failed"
  exit 1
fi

if [[ "$PREPARE_OUTPUT" =~ rootless[[:space:]]Podman[[:space:]]source[[:space:]]IP:[[:space:]]([0-9.]+) ]]; then
  SOURCE_IP="${BASH_REMATCH[1]}"
else
  echo "prepare-network did not report the pasta source IP"
  exit 1
fi
if [[ "$PREPARE_OUTPUT" =~ rootless[[:space:]]Podman[[:space:]]interface:[[:space:]]([[:alnum:]._-]+) ]]; then
  OUTBOUND_INTERFACE="${BASH_REMATCH[1]}"
else
  echo "prepare-network did not report the outbound interface"
  exit 1
fi

if [ -n "$DAEMON_PID" ]; then
  source_cidr="$SOURCE_IP/32"
  sudo iptables -t nat -C OUTPUT -s "$source_cidr" -d "$DNS_IP/32" -p udp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-OUTPUT-udp" -j REDIRECT --to-ports "$DNS_PORT"
  sudo iptables -t nat -C PREROUTING -s "$source_cidr" -d "$DNS_IP/32" -p udp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-PREROUTING-udp" -j REDIRECT --to-ports "$DNS_PORT"
fi

if ! podman run --rm --network "pasta:--outbound,$SOURCE_IP" --dns "$DNS_IP" "$IMAGE" --ipv4 -sS --max-time 10 "http://$ALLOWED_DOMAIN" >/dev/null; then
  sudo iptables -v -L OUTPUT -n --line-numbers
  sudo iptables -v -L DOCKERWALL-OUTPUT -n --line-numbers
  cat /tmp/dockerwall-rootless.log
  exit 1
fi
echo "$ALLOWED_DOMAIN OK"

if podman run --rm --network "pasta:--outbound,$SOURCE_IP" --dns "$DNS_IP" "$IMAGE" --ipv4 -sS --max-time 10 "http://$BLOCKED_DOMAIN" >/dev/null; then
  echo "$BLOCKED_DOMAIN reachable (FAIL)"
  exit 1
fi

echo "$BLOCKED_DOMAIN blocked as expected"
