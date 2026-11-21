# holes: every hole the checks built so far should find. Fake secrets hold only sandprobe-fake (Tests).
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash agent \
 && echo 'agent ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/agent && chmod 0440 /etc/sudoers.d/agent
# SEC-3: a non-empty file, an empty one, one behind a relative symlink, and a Kubernetes-style token symlink chain
RUN mkdir -p /home/agent/.aws /home/agent/.config/kube /home/agent/.kube \
 && echo sandprobe-fake > /home/agent/.aws/credentials \
 && : > /home/agent/.netrc \
 && echo sandprobe-fake > /home/agent/.config/kube/config \
 && ln -s ../.config/kube/config /home/agent/.kube/config \
 && chown -R agent:agent /home/agent \
 && sa=/var/run/secrets/kubernetes.io/serviceaccount \
 && mkdir -p $sa/..2026_11_09 \
 && echo sandprobe-fake > $sa/..2026_11_09/token \
 && ln -s ..2026_11_09 $sa/..data \
 && ln -s ..data/token $sa/token
# PER-1: a root-owned 0444 ~/.bashrc in an agent-writable home (replaceable), and a writable /etc/profile.d
RUN chown root:root /home/agent/.bashrc && chmod 0444 /home/agent/.bashrc && chmod 0777 /etc/profile.d
# PER-5: where the fixture mounts the persistent volume it creates for the run; the agent owns it, so the volume does
RUN mkdir -p /home/agent/persist && chown agent:agent /home/agent/persist
# SEC-1
ENV FAKE_API_TOKEN=sandprobe-fake
# AMP-4: a root stub socket at /var/run/docker.sock, mode 0666; it accepts and does nothing
CMD ["perl", "-MIO::Socket::UNIX", "-e", "unlink '/run/docker.sock'; my $s = IO::Socket::UNIX->new(Type => IO::Socket::UNIX::SOCK_STREAM(), Local => '/run/docker.sock', Listen => 5) or die $!; chmod 0666, '/run/docker.sock'; sleep 3600 while 1"]
