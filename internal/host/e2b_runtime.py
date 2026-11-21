"""PRV-8 runtime transport. Read one private request; never emit SDK errors."""
import base64
import importlib.metadata
import json
import logging
import sys

def main():
    request = json.load(sys.stdin)
    version = importlib.metadata.version("e2b")
    if version != "2.63.0":
        raise ValueError("unsupported SDK")
    if request["op"] == "check":
        print(json.dumps({"version": version}))
        return
    from e2b import Sandbox
    from e2b.connection_config import ConnectionConfig
    from packaging.version import Version
    headers = {
        "X-Access-Token": request["access_token"],
        "E2b-Sandbox-Id": request["sandbox_id"],
        "E2b-Sandbox-Port": "49983",
    }
    # Constructor only binds runtime transport; connect() would extend the timeout.
    sandbox = Sandbox(
        sandbox_id=request["sandbox_id"],
        sandbox_domain=request["domain"] or None,
        envd_version=Version(request["envd_version"]),
        envd_access_token=request["access_token"],
        connection_config=ConnectionConfig(
            domain="e2b.app", api_url="https://api.e2b.app",
            request_timeout=100, extra_sandbox_headers=headers,
        ),
    )
    if request["op"] == "upload":
        sandbox.files.write(
            request["path"], base64.b64decode(request["data"], validate=True),
            user="user", request_timeout=100,
        )
        sys.stdout.write("{}")
    elif request["op"] == "exec":
        output = []
        received = 0
        def consume(chunk, keep):
            nonlocal received
            received += len(chunk.encode("utf-8"))
            if received > 1024 * 1024:
                raise ValueError("output too large")
            if keep:
                output.append(chunk)
        result = sandbox.commands.run(
            request["command"], user="user",
            envs={"SANDPROBE_TWIN": "1"}, retain_output=False,
            on_stdout=lambda chunk: consume(chunk, True),
            on_stderr=lambda chunk: consume(chunk, False),
            timeout=95, request_timeout=100,
        )
        if result.exit_code != 0:
            raise ValueError("command failed")
        sys.stdout.write("".join(output))
    else:
        raise ValueError("unsupported operation")

if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        main()
    except Exception:
        # Values can appear in SDK request/response exceptions. Never interpolate.
        sys.stderr.write("E2B runtime operation failed\n")
        sys.exit(1)
