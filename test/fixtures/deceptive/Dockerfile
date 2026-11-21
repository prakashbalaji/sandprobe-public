# deceptive: a box trying to fool the probe (Tests). DECEPTIVE picks the case; the root entrypoint sets it up. Fake
# secrets hold only sandprobe-fake.
FROM debian:trixie-slim AS lib
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
# a preload library whose connect always fails, as a box might plant to fake refusals
RUN printf '%s\n' '#include <errno.h>' '#include <sys/socket.h>' \
    'int connect(int s, const struct sockaddr *a, socklen_t l) { errno = ECONNREFUSED; return -1; }' > /f.c \
 && gcc -shared -fPIC -o /failconnect.so /f.c

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends sudo iptables inotify-tools && rm -rf /var/lib/apt/lists/*
COPY --from=lib /failconnect.so /usr/lib/failconnect.so
RUN useradd -m -s /bin/bash agent \
 && echo 'agent ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/agent && chmod 0440 /etc/sudoers.d/agent
COPY entry.sh /entry.sh
CMD ["/entry.sh"]
