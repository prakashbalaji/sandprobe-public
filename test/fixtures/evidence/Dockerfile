# evidence: each finding with the evidence class it earns (Tests). EVIDENCE picks the case; the root entrypoint sets it
# up, and the agent's commands get no capabilities whatever the box was given.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables libcap2-bin && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash agent
COPY entry.sh /entry.sh
CMD ["/entry.sh"]
