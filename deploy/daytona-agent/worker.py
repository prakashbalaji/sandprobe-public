"""RUN-10: fixed functional verification, executed inside the agent sandbox only."""
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys
sys.path.insert(0, "/opt/sandprobe")
import coding

if sys.argv[1] == "network":
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
