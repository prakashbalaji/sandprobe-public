#!/usr/bin/env python3
"""PRV-9: create one empty test project, journal first, never retry or delete it.
No deployments, environment secrets or git integrations are created.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def save(path, state):
    fd, name = tempfile.mkstemp(prefix=".vercel-project-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(state, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def key_from(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("token file unavailable") from None
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("token file must be owner-only regular file")
        raw = source.read(8193)
    key = raw.strip()
    if not key or len(raw) > 8192 or any(c <= 32 or c >= 127 for c in key):
        raise ValueError("token malformed")
    return key.decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--name", default="sandprobe")
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"team_[A-Za-z0-9_-]{1,120}", args.team) or not re.fullmatch(r"sandprobe(?:-[a-z0-9]{1,32})?", args.name):
        raise ValueError("invalid dedicated project selectors")
    key = key_from(args.key_file)
    path = args.state.absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("unsafe journal directory")
    # Exclusive intent record: existing/ambiguous creates cannot be retried/adopted.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as output:
        state = {"team_id": args.team, "requested_name": args.name, "status": "intent", "residual": "empty project retained; no deployments"}
        json.dump(state, output)
        output.flush()
        os.fsync(output.fileno())
    opener = urllib.request.build_opener(NoRedirect())

    def request(method, route, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request("https://api.vercel.com" + route + "?teamId=" + args.team, data=data, method=method, headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=30) as response:
                raw = response.read(1048577)
        except urllib.error.HTTPError as error:
            raise ValueError("Vercel HTTP " + str(error.code)) from None
        except Exception:
            raise ValueError("Vercel transport failed; inspect intent journal, never retry create") from None
        if len(raw) > 1048576:
            raise ValueError("oversized project response")
        try:
            return json.loads(raw)
        except Exception:
            raise ValueError("malformed project response") from None

    result = request("POST", "/v11/projects", {"name": args.name, "framework": None})
    project = result.get("id", "")
    if not isinstance(project, str) or not re.fullmatch(r"prj_[A-Za-z0-9_-]{1,120}", project):
        raise ValueError("project create ID unresolved; preserve intent")
    # Persist returned immutable ID before validating optional fields or another call.
    state.update(project_id=project, status="created-unverified")
    save(path, state)
    if result.get("accountId") != args.team or result.get("name") != args.name:
        raise ValueError("created project scope mismatch; preserve returned ID")
    verified = request("GET", "/v9/projects/" + project)
    if verified.get("id") != project or verified.get("accountId") != args.team or verified.get("name") != args.name:
        raise ValueError("project verification mismatch")
    state["status"] = "verified-empty-project-retained"
    save(path, state)
    print(json.dumps({"project_id": project, "team_id": args.team, "status": state["status"]}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Only our fixed validation messages and HTTP status escape; no response body/key.
        print("project setup stopped: " + (str(error) if isinstance(error, ValueError) else "local setup failure; inspect private journal"), file=__import__("sys").stderr)
        raise SystemExit(1)
