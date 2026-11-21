#!/bin/sh
set -eu
if [ -n "${ONE_PORT_CANARY:-}" ]; then
  iptables -A OUTPUT -d "$ONE_PORT_CANARY" -p tcp --dport 443 -j ACCEPT
  iptables -A OUTPUT -d "$ONE_PORT_CANARY" -p tcp -j REJECT --reject-with tcp-reset
  iptables -A OUTPUT -d "$ONE_PORT_CANARY" -p udp -j REJECT
fi
exec sleep infinity
