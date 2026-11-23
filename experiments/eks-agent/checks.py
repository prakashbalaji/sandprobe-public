"""RUN-4: bounded synthetic observations, never an authoritative security pass."""
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys

PROPERTIES = ("identity", "protected_file", "workspace", "image_root", "receiver_egress")


def receiver_attempt(address, nonce):
    try:
        ip = ipaddress.IPv4Address(address)
        if (not any(ip in ipaddress.ip_network(n) for n in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
                or not re.fullmatch(r"[a-f0-9]{48}", nonce)):
            return "unknown"
        with socket.create_connection((address, 8080), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(nonce.encode() + b"\n")
            return "reported_delivery" if connection.recv(128).strip() == nonce.encode() else "unknown"
    except OSError as failure:
        if failure.errno in (errno.EACCES, errno.EPERM, errno.ECONNREFUSED):
            return "reported_refusal"
        return "unknown"
    except ValueError:
        return "unknown"


def observe(address, nonce):
    result = {key: "unknown" for key in PROPERTIES}
    try:
        fields = {}
        with open("/proc/self/status", encoding="utf-8") as status:
            for line in status.read(65537).splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    fields[key] = value.strip()
        safe = (os.getuid() == 10001 and os.getgid() == 10001
                and all(int(fields[key], 16) == 0 for key in ["CapEff", "CapPrm", "CapInh", "CapBnd"])
                and fields["NoNewPrivs"] == "1" and fields["Seccomp"] == "2")
        result["identity"] = "reported_restricted" if safe else "reported_violation"
    except (OSError, ValueError, KeyError):
        pass
    try:
        # Synthetic image-owned file only; never read its contents.
        fd = os.open("/opt/sandprobe/protected-marker", os.O_RDONLY | os.O_NOFOLLOW)
        os.close(fd)
        result["protected_file"] = "reported_open"
    except OSError as failure:
        if failure.errno in (errno.EACCES, errno.EPERM):
            result["protected_file"] = "reported_refusal"
    try:
        path = Path("/workspace/allowed-marker")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write("synthetic workspace marker\n")
        result["workspace"] = "reported_writable"
    except OSError:
        pass
    try:
        path = "/opt/sandprobe/write-fixture"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.unlink(path)
        result["image_root"] = "reported_writable"
    except OSError as failure:
        if failure.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            result["image_root"] = "reported_refusal"
    result["receiver_egress"] = receiver_attempt(address, nonce)
    return result


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--control":
        print(json.dumps({"control": receiver_attempt(sys.argv[2], sys.argv[3])}))
    else:
        sys.exit(2)
