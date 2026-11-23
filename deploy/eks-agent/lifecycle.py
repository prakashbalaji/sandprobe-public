"""RUN-1: private durable journal and bounded, sanitized command boundary."""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import signal
import subprocess
import tempfile
import time
from process_group import run_quiescent, QuiescenceError


class Failure(Exception):
    pass


def private_file(path, flags, create=False):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_CREAT if create else 0), 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise Failure("unsafe_state_file")
    return fd


def directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Failure("unsafe_state_directory")
    return path


class Journal:
    def __init__(self, root, run_id, create=False):
        if not re.fullmatch(r"[0-9a-f]{16}", run_id):
            raise Failure("invalid_run_identity")
        self.root = directory(root)
        self.folder = directory(self.root / run_id)
        self.path = self.folder / "state.json"
        self.lock = private_file(self.folder / "lock", os.O_RDWR, create=True)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if create:
                fd = private_file(self.path, os.O_WRONLY | os.O_EXCL, create=True)
                os.close(fd)
                self.data = {"schema": "sandprobe.agent-state/1", "run_id": run_id, "resources": {}, "phase": "new"}
                self.save()
            else:
                fd = private_file(self.path, os.O_RDONLY)
                with os.fdopen(fd, "rb") as stream:
                    raw = stream.read((1 << 20) + 1)
                if len(raw) > 1 << 20:
                    raise Failure("invalid_state")
                from coding import strict
                self.data = strict(raw.decode(), 1 << 20)
                if (self.data.get("schema") != "sandprobe.agent-state/1" or self.data.get("run_id") != run_id
                        or not isinstance(self.data.get("resources"), dict)):
                    raise Failure("invalid_state")
        except Exception:
            os.close(self.lock)
            raise

    def save(self):
        fd, name = tempfile.mkstemp(prefix="state-", dir=self.folder)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(self.data, stream, sort_keys=True, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            parent = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def intent(self, key, **fields):
        if key in self.data["resources"]:
            raise Failure("resource_already_recorded")
        self.data["resources"][key] = dict(fields, status="creating")
        self.save()

    def recorded(self, key, **fields):
        self.data["resources"][key].update(fields, status="created")
        self.save()

    def close(self):
        os.close(self.lock)


class Commands:
    def __init__(self, seconds=3600):
        self.deadline = time.monotonic() + seconds

    def call(self, args, payload=None, env=None, timeout=60, limit=1 << 20, pass_fds=(), quiesce_group=False):
        self.last_group_quiescent = False
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Failure("run_deadline")
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            process = None
            try:
                if quiesce_group:
                    if payload is not None or pass_fds:
                        raise Failure("unsupported_quiescent_command")
                    def confirmed():
                        self.last_group_quiescent = True
                    returncode = run_quiescent(args, env, min(timeout, remaining), output, errors, confirmed)
                else:
                    process = subprocess.Popen(args, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                        stdout=output, stderr=errors, env=env, start_new_session=True, pass_fds=pass_fds)
                    process.communicate(payload, timeout=min(timeout, remaining))
                    returncode = process.returncode
            except BaseException as error:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                if isinstance(error, QuiescenceError):
                    raise Failure("command_quiescence_unconfirmed") from None
                raise Failure("command_unavailable_or_timed_out") from None
            if returncode:
                errors.seek(0)
                error = errors.read(8192)
                if (Path(args[0]).name == "aws" and "ec2" in args and "describe-volumes" in args
                        and re.search(rb"An error occurred \(InvalidVolume\.NotFound\) when calling", error)):
                    raise Failure("volume_not_found")
                if re.search(rb"An error occurred \((NoSuchEntity|RepositoryNotFoundException|ResourceNotFoundException)\) when calling", error):
                    raise Failure("resource_not_found")
                # CMD-1: fixed categories only; never return raw stderr/credentials.
                if Path(args[0]).name == "kubectl":
                    lower = error.lower()
                    if b"getting credentials" in lower or b"exec: executable aws failed" in lower:
                        raise Failure("kubernetes_authentication_failed")
                    if b"i/o timeout" in lower or b"context deadline exceeded" in lower or b"request timed out" in lower:
                        raise Failure("kubernetes_request_timeout")
                    if b"serviceunavailable" in lower or b"server is currently unable" in lower:
                        raise Failure("kubernetes_api_unavailable")
                raise Failure("command_failed")
            output.seek(0)
            raw = output.read(limit + 1)
            if len(raw) > limit:
                raise Failure("command_output_too_large")
            return raw
