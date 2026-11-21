# hardened: the same app with the post's fixes applied to the box. No key is in the box: a broker outside it holds
# them and makes the API calls. The dev server runs as its own user, the agent has no Docker socket, and the run
# options (demo/main.go) make the root read-only, drop every capability, set no-new-privileges and cut the network.
FROM debian:trixie-slim
RUN useradd -m -s /bin/bash agent && useradd -r -M -s /usr/sbin/nologin app
COPY --chown=root:root app/ /home/agent/booking-app/
COPY devserver.pl /opt/app/
WORKDIR /home/agent/booking-app
USER app
CMD ["perl", "/opt/app/devserver.pl"]
