# reset: PER-5 against resets that go wrong (Tests). Mount points for the volumes the fixture creates: two the agent
# owns, and one it can't write, so its marker is refused.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends inotify-tools && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash agent \
 && mkdir -p /home/agent/persist /home/agent/persist2 /home/agent/locked \
 && chown agent:agent /home/agent/persist /home/agent/persist2 && chmod 0755 /home/agent/locked
CMD ["sleep", "infinity"]
