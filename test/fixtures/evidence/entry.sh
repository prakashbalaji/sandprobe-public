#!/bin/sh
set -eu
case "${EVIDENCE:-}" in
peer) # a process of the agent's own user, beside the agent
  setpriv --reuid=agent --regid=agent --clear-groups sleep infinity &
  ;;
hidepid) # other users' processes hidden from the agent (needs SYS_ADMIN, for the box's root only)
  mount -o remount,hidepid=invisible /proc
  ;;
sockets)
  # a stale control socket, world-writable, nothing listening
  perl -MIO::Socket::UNIX -e 'IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => "/run/docker.sock", Listen => 1) or die $!'
  chmod 0666 /run/docker.sock
  # a world-writable control socket whose server turns the agent away by its peer credentials (SO_PEERCRED)
  mkdir -p /run/podman
  AGENT_UID=$(id -u agent) perl -MIO::Socket::UNIX -MSocket=SOL_SOCKET,SO_PEERCRED -e '
    my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => "/run/podman/podman.sock", Listen => 5) or die $!;
    chmod 0666, "/run/podman/podman.sock";
    while (my $c = $s->accept) {
      my (undef, $uid) = unpack("iII", getsockopt($c, SOL_SOCKET, SO_PEERCRED));
      print $c ($uid == $ENV{AGENT_UID} ? "denied\n" : "ok\n");
      close $c;
    }' &
  # a control port on loopback, blocked for the agent by an owner-match rule (needs NET_ADMIN, the box's root only)
  perl -MIO::Socket::INET -e 'my $s = IO::Socket::INET->new(LocalAddr => "127.0.0.1:2375", Listen => 5, ReuseAddr => 1) or die $!; while (my $c = $s->accept) { close $c }' &
  iptables -A OUTPUT -o lo -p tcp --dport 2375 -m owner --uid-owner agent -j REJECT --reject-with tcp-reset
  ;;
owned) # the agent's home is its own at mode 0555 and its startup files are root's and read-only: it can write none
  # of them now, but as the directory's owner it can make the directory writable at any time, and replace them (TWN-4)
  chown root:root /home/agent/.bashrc /home/agent/.profile
  chmod 0444 /home/agent/.bashrc /home/agent/.profile
  rm -f /home/agent/.bash_logout
  # and a credential file of its own at mode 0000: refused now, but its owner can make it readable at any time
  mkdir /home/agent/.aws
  echo sandprobe-fake > /home/agent/.aws/credentials
  chown -R agent:agent /home/agent/.aws
  chmod 0000 /home/agent/.aws/credentials
  chmod 0555 /home/agent
  ;;
ownedlink) # the agent's home reached through root's directory link: /home/agent a link to /review/home, a directory
  # the agent owns at mode 0555, above root's read-only startup files. The kernel traverses the real directory, so its
  # owner can make it writable, whatever the link's own owner (TWN-4)
  mkdir -p /review
  mv /home/agent /review/home
  ln -s /review/home /home/agent
  chown root:root /review/home/.bashrc /review/home/.profile
  chmod 0444 /review/home/.bashrc /review/home/.profile
  rm -f /review/home/.bash_logout
  chmod 0555 /review/home
  ;;
setgid) # the agent holding only CAP_SETGID (the probe launched through setpriv, as the agent): /root searchable only by
  # group 1234, its startup files writable only by that group. Joining it, the agent reaches and writes them
  chown root:1234 /root /root/.bashrc /root/.profile
  chmod 0010 /root
  chmod 0020 /root/.bashrc /root/.profile
  mkdir -p /opt/caps
  printf '#!/bin/sh\nexec setpriv --reuid=agent --regid=agent --init-groups --inh-caps=-all,+setgid --ambient-caps=-all,+setgid /opt/sandprobe/sandprobe-probe "$@"\n' > /opt/caps/probe
  chmod 0755 /opt/caps/probe
  ;;
drs) # the agent holding CAP_DAC_READ_SEARCH permitted, not effective (a copy of the probe with that file capability):
  # its home root's at mode 0000, a startup file in it writable by anyone. Raising the capability, it reaches and writes it
  chown root:root /home/agent /home/agent/.bashrc
  chmod 0666 /home/agent/.bashrc
  chmod 0000 /home/agent
  mkdir -p /opt/caps
  cp /opt/sandprobe/sandprobe-probe /opt/caps/probe
  setcap cap_dac_read_search+p /opt/caps/probe
  ;;
stickylink) # the agent's home reached through its own link in root's sticky directory: /home/agent is root's link
  # to /review-sticky/home, the agent's link to /review-home, root's at mode 0555 above root's read-only startup
  # files. The kernel lets the agent rename its own entry in a sticky directory, so it can redirect the path (TWN-4)
  mkdir -m 1777 /review-sticky
  mkdir /review-home
  printf '' > /review-home/.bashrc
  printf '' > /review-home/.profile
  chmod 0444 /review-home/.bashrc /review-home/.profile
  chmod 0555 /review-home
  ln -s /review-home /review-sticky/home
  chown -h agent:agent /review-sticky/home
  rm -rf /home/agent
  ln -s /review-sticky/home /home/agent
  ;;
dotdot) # the code review's: the home is root's link to /review/real/dir, root's at 0555, whose startup and credential
  # files are root's links to ../ names. The kernel resolves each from the real directory, /review/real, never from
  # /home beside the home's link, where a decoy of the opposite access waits: .bashrc reaches a file anyone may write
  # (the decoy is read-only); .netrc one no one may read (the decoy is readable); .git-credentials one anyone may read
  # (the decoy is closed)
  mkdir -p /review/real/dir
  printf '' > /review/real/target
  chmod 0666 /review/real/target
  printf '' > /home/target
  chmod 0444 /home/target
  echo sandprobe-fake > /review/real/netrc-real
  chmod 0000 /review/real/netrc-real
  echo sandprobe-fake > /home/netrc-real
  chmod 0444 /home/netrc-real
  echo sandprobe-fake > /review/real/gitcred-real
  chmod 0444 /review/real/gitcred-real
  echo sandprobe-fake > /home/gitcred-real
  chmod 0000 /home/gitcred-real
  ln -s ../target /review/real/dir/.bashrc
  ln -s ../netrc-real /review/real/dir/.netrc
  ln -s ../gitcred-real /review/real/dir/.git-credentials
  chmod 0555 /review/real/dir
  rm -rf /home/agent
  ln -s /review/real/dir /home/agent
  ;;
ninelinks) # eight directory links lead to the home, and .bashrc and .netrc are links of their own: nine in all, past
  # SBX-2's eight, so neither can be judged
  mkdir -p /review/h
  printf '' > /review/rc-real
  chmod 0444 /review/rc-real
  echo sandprobe-fake > /review/netrc-real
  chmod 0444 /review/netrc-real
  ln -s /review/rc-real /review/h/.bashrc
  ln -s /review/netrc-real /review/h/.netrc
  chmod 0555 /review/h
  i=1
  while [ $i -lt 7 ]; do ln -s /hop$((i + 1)) /hop$i; i=$((i + 1)); done
  ln -s /review/h /hop7
  rm -rf /home/agent
  ln -s /hop1 /home/agent
  ;;
filecaps) # AMP-3: no setuid-root file left in the system binary directories, and outside them a copy of cat whose
  # file capabilities are cap_dac_override+ep. An agent holding no capability, with NoNewPrivs 0 and a bounding set
  # that keeps CAP_DAC_OVERRIDE, gains it by running the copy: the kernel grants the file's permitted set ANDed with
  # the bounding set. The probe never runs it; the test does, as the agent, to show the kernel grants it
  for d in /usr/bin/ /usr/sbin/ /bin/ /sbin/ /usr/local/bin/ /usr/local/sbin/; do
    [ -d "$d" ] && find "$d" -maxdepth 1 -type f -user root -perm -4000 -exec chmod u-s {} +
  done
  mkdir -p /opt/filecaps
  cp /usr/bin/cat /opt/filecaps/cat
  setcap cap_dac_override+ep /opt/filecaps/cat
  ;;
esac
exec sleep infinity
