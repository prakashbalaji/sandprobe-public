# sudors: AMP-1 against sudo-rs as Ubuntu installs it (Tests): /usr/bin/sudo a link to /etc/alternatives/sudo, a link
# to the root-owned setuid /usr/lib/cargo/bin/sudo. SUDORS picks a case the root entrypoint sets up; with none, the
# layout is as shipped.
FROM ubuntu:26.04
RUN apt-get update && apt-get install -y --no-install-recommends sudo-rs && rm -rf /var/lib/apt/lists/*
RUN test "$(readlink /usr/bin/sudo)" = /etc/alternatives/sudo \
 && test "$(readlink /etc/alternatives/sudo)" = /usr/lib/cargo/bin/sudo \
 && test -u /usr/lib/cargo/bin/sudo
# agent: NOPASSWD for every command; plain: no rule at all
RUN useradd -m -s /bin/bash agent && useradd -m -s /bin/bash plain \
 && echo 'agent ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/agent && chmod 0440 /etc/sudoers.d/agent
COPY entry.sh /entry.sh
CMD ["/entry.sh"]
