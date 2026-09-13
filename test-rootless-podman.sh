#!/bin/bash
set -euo pipefail

NETWORK="test-rootless-podman"
ALLOWED_DOMAIN="example.com"
BLOCKED_DOMAIN="google.com"
IMAGE="docker.io/curlimages/curl:latest"

cargo build

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
DOCKERWALL="$TARGET_DIR/debug/dockerwall"
CONTROL_SOCKET="/run/dockerwall.sock"
DAEMON_PID=""
SOURCE_IP=""
SOURCE_IPV6=""
OUTBOUND_INTERFACE=""
DNS_IP="198.18.0.1"
DNS_PORT="5354"
DNS_ALIAS_WAS_PRESENT=true
OUTPUT_CHAIN_WAS_PRESENT=true
IP6_OUTPUT_CHAIN_WAS_PRESENT=true

remove_rule() {
  while sudo iptables "$@" >/dev/null 2>&1; do
    :
  done
}

remove_rule6() {
  while sudo ip6tables "$@" >/dev/null 2>&1; do
    :
  done
}

report_firewall() {
  sudo iptables -v -L OUTPUT -n --line-numbers
  sudo iptables -v -L DOCKERWALL-OUTPUT -n --line-numbers
  sudo iptables -t nat -v -L POSTROUTING -n --line-numbers
  sudo ip6tables -v -L OUTPUT -n --line-numbers
  sudo ip6tables -v -L DOCKERWALL-OUTPUT -n --line-numbers
  sudo ipset list "$NETWORK"
  sudo ipset list "$NETWORK-v6"
  cat /tmp/dockerwall-rootless.log
}

cleanup() {
  if [ -n "$SOURCE_IP" ] && [ -n "$OUTBOUND_INTERFACE" ]; then
    local source_cidr="$SOURCE_IP/32"
    remove_rule -t nat -D POSTROUTING -s "$source_cidr" -o "$OUTBOUND_INTERFACE" -m comment --comment "dockerwall:$NETWORK:masquerade" -j MASQUERADE
    remove_rule -t nat -D OUTPUT -s "$source_cidr" -d "$DNS_IP/32" -p udp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-OUTPUT-udp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -t nat -D OUTPUT -s "$source_cidr" -d "$DNS_IP/32" -p tcp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-OUTPUT-tcp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -t nat -D PREROUTING -s "$source_cidr" -d "$DNS_IP/32" -p udp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-PREROUTING-udp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -t nat -D PREROUTING -s "$source_cidr" -d "$DNS_IP/32" -p tcp --dport 53 -m comment --comment "dockerwall:$NETWORK:dns-PREROUTING-tcp" -j REDIRECT --to-ports "$DNS_PORT"
    remove_rule -D OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:output-hook" -j DOCKERWALL-OUTPUT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:established" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -d 127.0.0.1/32 -p udp --dport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-udp" -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -d 127.0.0.1/32 -p tcp --dport "$DNS_PORT" -m comment --comment "dockerwall:$NETWORK:dns-tcp" -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:allow" -m set --match-set "$NETWORK" dst -j ACCEPT
    remove_rule -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:drop" -j DROP
    sudo ip addr del "$source_cidr" dev "$OUTBOUND_INTERFACE" >/dev/null 2>&1 || true
    sudo ipset destroy "$NETWORK" >/dev/null 2>&1 || true
  fi

  if [ -n "$SOURCE_IPV6" ] && [ -n "$OUTBOUND_INTERFACE" ]; then
    local source_cidr="$SOURCE_IPV6/128"
    remove_rule6 -D OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:output-hook" -j DOCKERWALL-OUTPUT
    remove_rule6 -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:established" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    remove_rule6 -D DOCKERWALL-OUTPUT -s "$source_cidr" -p ipv6-icmp -m icmp6 --icmpv6-type neighbor-solicitation -m comment --comment "dockerwall:$NETWORK:neighbor-solicitation" -j ACCEPT
    remove_rule6 -D DOCKERWALL-OUTPUT -s "$source_cidr" -p ipv6-icmp -m icmp6 --icmpv6-type neighbor-advertisement -m comment --comment "dockerwall:$NETWORK:neighbor-advertisement" -j ACCEPT
    remove_rule6 -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:allow" -m set --match-set "$NETWORK-v6" dst -j ACCEPT
    remove_rule6 -D DOCKERWALL-OUTPUT -s "$source_cidr" -m comment --comment "dockerwall:$NETWORK:drop" -j DROP
    sudo ip -6 addr del "$SOURCE_IPV6/64" dev "$OUTBOUND_INTERFACE" >/dev/null 2>&1 || true
  fi
  sudo ipset destroy "$NETWORK-v6" >/dev/null 2>&1 || true

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
  if [ "$IP6_OUTPUT_CHAIN_WAS_PRESENT" = false ]; then
    sudo ip6tables -X DOCKERWALL-OUTPUT >/dev/null 2>&1 || true
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
if sudo ip6tables -S DOCKERWALL-OUTPUT >/dev/null 2>&1; then
  IP6_OUTPUT_CHAIN_WAS_PRESENT=true
else
  IP6_OUTPUT_CHAIN_WAS_PRESENT=false
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
if [[ "$PREPARE_OUTPUT" =~ rootless[[:space:]]Podman[[:space:]]source[[:space:]]IPv6:[[:space:]]([0-9a-f:]+) ]]; then
  SOURCE_IPV6="${BASH_REMATCH[1]}"
else
  echo "rootless Podman IPv6 unavailable; skipping IPv6 checks"
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

PODMAN_NETWORK="pasta:--outbound,$SOURCE_IP"
if [ -n "$SOURCE_IPV6" ]; then
  PODMAN_NETWORK+=",--address,$SOURCE_IPV6,--outbound,$SOURCE_IPV6"
fi
if ! podman run --rm --network "$PODMAN_NETWORK" --dns "$DNS_IP" "$IMAGE" --ipv4 -sS --max-time 10 "http://$ALLOWED_DOMAIN" >/dev/null; then
  report_firewall
  exit 1
fi
echo "$ALLOWED_DOMAIN IPv4 OK"

if podman run --rm --network "$PODMAN_NETWORK" --dns "$DNS_IP" "$IMAGE" --ipv4 -sS --max-time 10 "http://$BLOCKED_DOMAIN" >/dev/null; then
  echo "$BLOCKED_DOMAIN IPv4 reachable (FAIL)"
  report_firewall
  exit 1
fi
echo "$BLOCKED_DOMAIN IPv4 blocked as expected"

if [ -n "$SOURCE_IPV6" ]; then
  if ! podman run --rm --network "$PODMAN_NETWORK" --dns "$DNS_IP" "$IMAGE" --ipv6 -sS --max-time 10 "http://$ALLOWED_DOMAIN" >/dev/null; then
    report_firewall
    exit 1
  fi
  echo "$ALLOWED_DOMAIN IPv6 OK"

  if podman run --rm --network "$PODMAN_NETWORK" --dns "$DNS_IP" "$IMAGE" --ipv6 -sS --max-time 10 "http://$BLOCKED_DOMAIN" >/dev/null; then
    echo "$BLOCKED_DOMAIN IPv6 reachable (FAIL)"
    report_firewall
    exit 1
  fi
  echo "$BLOCKED_DOMAIN IPv6 blocked as expected"
fi
