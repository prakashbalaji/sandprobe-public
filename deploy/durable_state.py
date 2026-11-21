#!/usr/bin/env python3
"""Opt-in durable metadata state for the managed EKS lifecycle (RUN-1)."""
import os
from pathlib import Path
import re
import stat
import sys


def write(mode, path, entries):
    if mode not in {"init", "append"} or not entries:
        raise ValueError()
    if any(not re.fullmatch(r"[a-z0-9_]+=[^\r\n]{1,2048}", entry) for entry in entries):
        raise ValueError()
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_CREAT | os.O_EXCL if mode == "init" else os.O_APPEND
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "ab") as output:
        info = os.fstat(output.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError()
        output.write(("\n".join(entries) + "\n").encode())
        output.flush()
        os.fsync(output.fileno())
    parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


if __name__ == "__main__":
    try:
        if sys.argv[1] == "resolved":
            fd = os.open(sys.argv[2], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "r") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise ValueError()
                pending = set()
                for line in source:
                    key, sep, value = line.rstrip("\n").partition("=")
                    if key == "create_pending":
                        if not sep or not value or value in pending: raise ValueError()
                        pending.add(value)
                    elif key == "create_resolved":
                        if value not in pending: raise ValueError()
                        pending.remove(value)
                if pending: raise ValueError()
        else:
            write(sys.argv[1], sys.argv[2], sys.argv[3:])
    except Exception:
        print("durable state update failed", file=sys.stderr)
        sys.exit(1)
