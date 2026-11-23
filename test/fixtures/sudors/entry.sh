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
fowner) # root's links in a sticky directory; the agent, holding only CAP_FOWNER, which passes the sticky bit, moved
  # root's link to su over root's link to sudo, and both stay root's. The probe runs as the agent with that capability.
  mkdir -m 1777 /sticky
  ln -s /usr/lib/cargo/bin/sudo /sticky/sudo
  ln -s /usr/bin/su /sticky/alt
  ln -sfn /sticky/sudo /etc/alternatives/sudo
  setpriv --reuid=agent --regid=agent --init-groups --inh-caps=-all,+fowner --ambient-caps=-all,+fowner \
    mv -T /sticky/alt /sticky/sudo
  mkdir /opt/fowner
  printf '#!/bin/sh\nexec setpriv --reuid=agent --regid=agent --init-groups --inh-caps=-all,+fowner --ambient-caps=-all,+fowner /opt/sandprobe/sandprobe-probe "$@"\n' > /opt/fowner/probe
  chmod 0755 /opt/fowner/probe
  ;;
dirlinks) # nine root-owned directory links on the way to the real sudo: past SBX-2's eight
  i=1
  while [ $i -lt 9 ]; do ln -s /d$((i + 1)) /d$i; i=$((i + 1)); done
  ln -s /usr/lib/cargo/bin /d9
  ln -sfn /d1/sudo /etc/alternatives/sudo
  ;;
owned) # a directory the agent owns, mode 0555, holding root's link to su: the owner can make it writable at any time
  mkdir /opt/own
  ln -s /usr/bin/su /opt/own/sudo
  chown agent:agent /opt/own
  chmod 0555 /opt/own
  ln -sfn /opt/own/sudo /etc/alternatives/sudo
  ;;
esac
exec sleep infinity
