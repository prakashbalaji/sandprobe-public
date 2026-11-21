# policy: sudo policies AMP-1 must never pass, and must never act on (Tests). One user per case.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/*
# listpw: NOPASSWD for one command other than true, with listing always behind a password
RUN useradd -m listpw && printf '%s\n' 'Defaults:listpw listpw=always' 'listpw ALL=(root) NOPASSWD: /usr/bin/id' > /etc/sudoers.d/listpw
# passwd: every rule needs a password, so does listing (listpw=any, the default)
RUN useradd -m passwd && printf '%s\n' 'passwd ALL=(ALL) ALL' > /etc/sudoers.d/passwd
# truepath: NOPASSWD for true, with a box-controlled true first in sudo's path that writes a sentinel if ever run
RUN useradd -m truepath && mkdir /home/truepath/bin \
 && printf '#!/bin/sh\ntouch /tmp/sentinel-true-ran\n' > /home/truepath/bin/true && chmod 0755 /home/truepath/bin/true \
 && chown -R truepath:truepath /home/truepath/bin \
 && printf '%s\n' 'Defaults:truepath secure_path="/home/truepath/bin:/usr/sbin:/usr/bin:/sbin:/bin"' \
    'truepath ALL=(root) NOPASSWD: /usr/bin/true' > /etc/sudoers.d/truepath
RUN chmod 0440 /etc/sudoers.d/* && visudo -c
CMD ["sleep", "infinity"]
