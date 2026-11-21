# net: the network fixture's box. With ONE_PORT_CANARY set (and NET_ADMIN, which the agent's commands never get), only
# tcp/443 to the canary leaves; every other TCP port to it is refused with a reset, and UDP to it is rejected.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash agent
COPY entry.sh /entry.sh
CMD ["/entry.sh"]
