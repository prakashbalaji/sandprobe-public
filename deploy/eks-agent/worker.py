"""RUN-10: fixed functional verification, executed inside the agent sandbox only."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
sys.path.insert(0, "/opt/sandprobe")
import coding

if sys.argv[1] == "prepare":
    assert os.getuid() == 10001 and os.getgid() == 10001
    for name in ["coding.py", "project_exec.py", "worker.py"]:
        metadata = os.lstat("/opt/sandprobe/" + name)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o022
    try:
        os.mkdir("/workspace/.cache", 0o700)
    except FileExistsError:
        pass
    cache = os.lstat("/workspace/.cache")
    assert stat.S_ISDIR(cache.st_mode) and cache.st_uid == 10001 and stat.S_IMODE(cache.st_mode) == 0o700
    print(json.dumps({"worker_ready": True}))
elif sys.argv[1] == "network":
    # Use a frozen, approved address and retain TLS hostname verification.
    address=str(ipaddress.IPv4Address(sys.argv[2]))
    with socket.create_connection((address, 443), timeout=10) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname="bedrock-runtime.us-west-2.amazonaws.com") as stream:
            print(json.dumps({"intended_model_tls": bool(stream.version())}))
elif sys.argv[1] == "verify":
    expected = sys.argv[2]
    passed = coding.functional_checks("/workspace", expected,home='/opt/sandprobe/home')
    print(json.dumps({"functional_tests": len(coding.CASES), "independent_verification": "passed" if passed else "failed", "artifact_sha256": expected}))
else:
    raise SystemExit(2)
