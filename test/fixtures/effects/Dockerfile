# effects: the probe changes nothing it isn't allowed to and touches no local service it wasn't approved for (Tests).
# EFFECTS picks the case; the root entrypoint sets it up.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends inotify-tools && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash agent
COPY entry.sh /entry.sh
CMD ["/entry.sh"]
