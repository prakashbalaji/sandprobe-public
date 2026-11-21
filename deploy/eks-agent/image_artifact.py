"""IMG-1/2: bounded, attempt-bound CI image transport without a local daemon."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time
import zipfile

from coding import strict
from lifecycle import Failure

MAX_ARCHIVE = 512 << 20
MAX_DOWNLOAD = MAX_ARCHIVE + (1 << 20)
WORKFLOW = ".github/workflows/networked-agent.yml"
REPOSITORY = "summationai/sandprobe"


def artifact_name(source, attempt):
    if (not isinstance(source, str) or not re.fullmatch(r"[a-f0-9]{40}", source)
            or type(attempt) is not int or not 1 <= attempt <= 1000):
        raise Failure("invalid_image_source_or_attempt")
    return f"sandprobe-agent-image-{source}-attempt-{attempt}"


def validate_run(data, source, run_id):
    attempt = data.get("run_attempt") if isinstance(data, dict) else None
    artifact_name(source, attempt)
    expected = {"status": "completed", "conclusion": "success", "event": "push", "head_branch": "main",
                "head_sha": source, "path": WORKFLOW, "repository": REPOSITORY, "head_repository": REPOSITORY,
                "run_attempt": attempt, "id": int(run_id)}
    if type(data.get("id")) is not int or data != expected:
        raise Failure("successful_matching_main_image_run_required")
    return attempt


def select_artifact(data, source, run_id, attempt):
    if (not isinstance(data, dict) or type(data.get("total_count")) is not int
            or not 1 <= data["total_count"] <= 100 or not isinstance(data.get("artifacts"), list)):
        raise Failure("invalid_image_artifact_listing")
    matches = [a for a in data["artifacts"] if a.get("name") == artifact_name(source, attempt)]
    if len(matches) != 1:
        raise Failure("exact_image_artifact_required")
    item = matches[0]
    provenance = item.get("workflow_run", {})
    if (type(item.get("id")) is not int or item["id"] <= 0 or item.get("expired") is not False
            or type(item.get("size_in_bytes")) is not int or not 0 < item["size_in_bytes"] <= MAX_DOWNLOAD
            or not isinstance(item.get("digest"), str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", item["digest"])
            or type(provenance.get("id")) is not int or provenance.get("id") != int(run_id) or provenance.get("head_sha") != source
            or provenance.get("head_branch") != "main"):
        raise Failure("unverified_or_expired_image_artifact")
    return {key: item[key] for key in ["id", "size_in_bytes", "digest"]}


def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    info = os.fstat(stream.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or info.st_mode & 0o022 or info.st_size > limit):
        stream.close()
        raise Failure("unsafe_or_oversized_image_artifact")
    return stream


def open_verified(folder, source, attempt):
    folder = Path(folder)
    artifact_name(source, attempt)
    if folder.is_symlink() or not folder.is_dir() or {p.name for p in folder.iterdir()} != {"metadata.json", "task-image.tar"}:
        raise Failure("unexpected_image_artifact_files")
    with regular(folder/"metadata.json", 8192) as stream:
        metadata = strict(stream.read(8193).decode(), 8192)
    if (not isinstance(metadata, dict) or set(metadata) != {"schema", "source_commit", "run_attempt", "archive_sha256", "archive_size", "image_id", "platform"}
            or metadata.get("schema") != "sandprobe.image-artifact/1" or metadata.get("source_commit") != source
            or type(metadata.get("run_attempt")) is not int or metadata.get("run_attempt") != attempt or metadata.get("platform") != "linux/amd64"
            or type(metadata.get("archive_size")) is not int or not 0 < metadata["archive_size"] <= MAX_ARCHIVE
            or not isinstance(metadata.get("archive_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", metadata["archive_sha256"])
            or not isinstance(metadata.get("image_id"), str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", metadata["image_id"])):
        raise Failure("invalid_image_artifact_metadata")
    stream = regular(folder/"task-image.tar", MAX_ARCHIVE)
    try:
        digest, size = hashlib.sha256(), 0
        while chunk := stream.read(1 << 20):
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise Failure("image_archive_too_large")
            digest.update(chunk)
        if size != metadata["archive_size"] or digest.hexdigest() != metadata["archive_sha256"]:
            raise Failure("image_archive_integrity_mismatch")
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            members, canonical_names = [], set()
            for member in archive:
                path = PurePosixPath(member.name)
                if (len(members) >= 256 or path.is_absolute() or ".." in path.parts or "\\" in member.name
                        or not (member.isfile() or member.isdir()) or str(path) in canonical_names
                        or member.size < 0 or member.size > MAX_ARCHIVE):
                    raise Failure("unsafe_or_duplicate_tar_member")
                members.append(member)
                canonical_names.add(str(path))
            by_name = {m.name: m for m in members}
            manifest_entry = by_name.get("manifest.json")
            if not manifest_entry or not manifest_entry.isfile() or manifest_entry.size > 65536:
                raise Failure("invalid_docker_archive_manifest")
            manifest = strict(archive.extractfile(manifest_entry).read(65537).decode(), 65536)
            if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
                raise Failure("single_image_archive_required")
            config_name = manifest[0].get("Config")
            if not isinstance(config_name, str) or not re.fullmatch(r"(?:blobs/sha256/[a-f0-9]{64}|[a-f0-9]{64}\.json)", config_name):
                raise Failure("invalid_image_config_path")
            config_entry = by_name.get(config_name)
            layers = manifest[0].get("Layers")
            if (not config_entry or not config_entry.isfile() or config_entry.size > 1 << 20
                    or not isinstance(layers, list) or not layers or len(layers) > 128
                    or any(not isinstance(n, str) or n not in by_name or not by_name[n].isfile() for n in layers)):
                raise Failure("invalid_image_config_or_layers")
            raw = archive.extractfile(config_entry).read((1 << 20)+1)
            if "sha256:" + hashlib.sha256(raw).hexdigest() != metadata["image_id"]:
                raise Failure("image_config_identity_mismatch")
            config = strict(raw.decode(), 1 << 20)
            if config.get("os") != "linux" or config.get("architecture") != "amd64":
                raise Failure("linux_amd64_image_required")
        stream.seek(0)
        return metadata, stream # Keep the verified descriptor for Skopeo.
    except BaseException:
        stream.close()
        raise


def verify(folder, source, attempt):
    metadata, stream = open_verified(folder, source, attempt)
    stream.close()
    return metadata


def checked_archive_path(stream, folder, metadata):
    """IMG-5: detect path/content changes; the host user remains trusted."""
    folder = Path(folder).absolute()
    for parent in (folder, folder.parent):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise Failure("unsafe_image_transport_directory")
    path = folder / "task-image.tar"
    named, opened = path.lstat(), os.fstat(stream.fileno())
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if (not stat.S_ISREG(named.st_mode) or named.st_uid != os.getuid() or named.st_nlink != 1
            or stat.S_IMODE(named.st_mode) != 0o400 or fingerprint(named) != fingerprint(opened)
            or named.st_size != metadata["archive_size"]):
        raise Failure("image_transport_identity_changed")
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        digest.update(chunk)
    stream.seek(0)
    if (digest.hexdigest() != metadata["archive_sha256"]
            or fingerprint(os.fstat(stream.fileno())) != fingerprint(opened)
            or fingerprint(path.lstat()) != fingerprint(named)):
        raise Failure("image_transport_content_changed")
    return str(path)


@contextmanager
def archive_transport(stream, folder, metadata, platform=None):
    platform = sys.platform if platform is None else platform
    if platform == "darwin":
        path = checked_archive_path(stream, folder, metadata)
        before = os.fstat(stream.fileno())
        try:
            yield "docker-archive:" + path, ()
        finally:
            checked_archive_path(stream, folder, metadata)
            after = os.fstat(stream.fileno())
            if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                raise Failure("image_transport_timestamps_changed")
    else:
        stream.seek(0)
        descriptor = stream.fileno()
        yield f"docker-archive:/dev/fd/{descriptor}", (descriptor,)


def validate_destination(raw, image_id):
    """IMG-5: destination must reference the CI-verified image config."""
    manifest = strict(raw.decode(), 1 << 20)
    if (not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2
            or manifest.get("mediaType") not in {"application/vnd.docker.distribution.manifest.v2+json",
                                                "application/vnd.oci.image.manifest.v1+json"}
            or not isinstance(manifest.get("config"), dict) or manifest["config"].get("digest") != image_id
            or not isinstance(manifest.get("layers"), list) or not manifest["layers"]):
        raise Failure("destination_image_config_mismatch")


def download(artifact, folder, deadline, env):
    """Stream an authenticated immutable artifact ID; never unpack with gh."""
    folder = Path(folder)
    archive_path = folder/"download.zip"
    fd = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    process = None
    try:
        with os.fdopen(fd, "wb") as output:
            process = subprocess.Popen(["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            digest, size = hashlib.sha256(), 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Failure("image_download_timeout")
                    if not selector.select(min(remaining, 5)):
                        continue
                    chunk = os.read(process.stdout.fileno(), 1 << 20)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_DOWNLOAD or size > artifact["size_in_bytes"]:
                        raise Failure("image_download_too_large")
                    output.write(chunk)
                    digest.update(chunk)
            if process.wait(timeout=max(0.1, deadline-time.monotonic())):
                raise Failure("image_download_failed")
            if size != artifact["size_in_bytes"] or "sha256:"+digest.hexdigest() != artifact["digest"]:
                raise Failure("image_download_digest_mismatch")
        with regular(archive_path, MAX_DOWNLOAD) as stream, zipfile.ZipFile(stream) as bundle:
            entries = bundle.infolist()
            if len(entries) != 2 or {e.filename for e in entries} != {"metadata.json", "task-image.tar"}:
                raise Failure("unexpected_image_zip_entries")
            for entry in entries:
                maximum = 8192 if entry.filename == "metadata.json" else MAX_ARCHIVE
                mode = entry.external_attr >> 16
                if (entry.flag_bits & 1 or entry.is_dir() or entry.file_size > maximum
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                    raise Failure("unsafe_image_zip_entry")
                target = os.open(folder/entry.filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(target, "wb") as output, bundle.open(entry) as payload:
                    size = 0
                    while chunk := payload.read(1 << 20):
                        size += len(chunk)
                        if time.monotonic() > deadline or size > maximum or size > entry.file_size:
                            raise Failure("image_unpacked_size_or_time_limit")
                        output.write(chunk)
                    if size != entry.file_size:
                        raise Failure("image_zip_size_mismatch")
        archive_path.unlink()
    finally:
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            process.stdout.close()


def create(folder, source, attempt):
    artifact_name(source, attempt)
    folder = Path(folder)
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    image = subprocess.check_output(["docker", "image", "inspect", "sandprobe-agent-local", "--format", "{{.Id}}"], stderr=subprocess.DEVNULL, timeout=30).decode().strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise Failure("invalid_built_image_identity")
    subprocess.run(["docker", "save", "sandprobe-agent-local", "--output", str(folder/"task-image.tar")],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180, check=True)
    digest = hashlib.sha256()
    with regular(folder/"task-image.tar", MAX_ARCHIVE) as stream:
        size = os.fstat(stream.fileno()).st_size
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    metadata = {"schema": "sandprobe.image-artifact/1", "source_commit": source, "run_attempt": attempt,
                "archive_sha256": digest.hexdigest(), "archive_size": size, "image_id": image, "platform": "linux/amd64"}
    fd = os.open(folder/"metadata.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(metadata, output, sort_keys=True)
    return verify(folder, source, attempt)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["create", "verify"])
    parser.add_argument("folder")
    parser.add_argument("source")
    parser.add_argument("attempt", type=int)
    args = parser.parse_args()
    try:
        result = create(args.folder, args.source, args.attempt) if args.command == "create" else verify(args.folder, args.source, args.attempt)
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print("image artifact verification failed", file=sys.stderr)
        sys.exit(2)
