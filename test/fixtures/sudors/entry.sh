#!/bin/sh
set -eu
case "${SUDORS:-}" in
writable-link) # the chain's middle link sits in a directory the agent can write, so it could point sudo anywhere
  chmod 0777 /etc/alternatives
  ;;
writable-real) # /etc/alternatives is itself a link, to a directory whose real parent the agent can write
  mkdir -p /opt/alt
  mv /etc/alternatives /opt/alt/alternatives
  ln -s /opt/alt/alternatives /etc/alternatives
  chmod 0777 /opt/alt
  ;;
dangling) # the chain ends nowhere: never absent, never run
  ln -sfn /usr/lib/cargo/bin/sudo-missing /etc/alternatives/sudo
  ;;
esac
exec sleep infinity
