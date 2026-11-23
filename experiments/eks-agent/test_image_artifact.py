import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import warnings
import zipfile

import image_artifact as image
from lifecycle import Failure

SOURCE = "a"*40


def fixture(folder, *, platform="amd64", duplicate=False, link=False, extra=None, multi=False, missing_layer=False):
    folder = Path(folder)
    config = json.dumps({"os":"linux","architecture":platform}).encode()
    identity = hashlib.sha256(config).hexdigest()
    name = identity+".json"
    manifest = [{"Config":name,"Layers":["layer.tar"],"RepoTags":["sandprobe-agent-local:latest"]}]
    with tarfile.open(folder/"task-image.tar","w") as archive:
        def add(path, data):
            entry = tarfile.TarInfo(path)
            entry.size = len(data)
            archive.addfile(entry,io.BytesIO(data))
        add("manifest.json",json.dumps(manifest*2 if multi else manifest).encode())
        if duplicate:
            add("manifest.json",b"[]")
        if link:
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/outside"
            archive.addfile(entry)
        else:
            add(name,config)
        if not missing_layer:
            add("layer.tar",b"synthetic-layer-data")
        if extra:
            add(extra,b"x")
    raw=(folder/"task-image.tar").read_bytes()
    metadata={"schema":"sandprobe.image-artifact/1","source_commit":SOURCE,"run_attempt":1,
              "archive_sha256":hashlib.sha256(raw).hexdigest(),"archive_size":len(raw),
              "image_id":"sha256:"+identity,"platform":"linux/amd64"}
    (folder/"metadata.json").write_text(json.dumps(metadata))
    return metadata


def run_metadata():
    return {"status":"completed","conclusion":"success","event":"push","head_branch":"main",
            "head_sha":SOURCE,"path":image.WORKFLOW,"repository":image.REPOSITORY,
            "head_repository":image.REPOSITORY,"run_attempt":1,"id":123}


class ArtifactTests(unittest.TestCase):
    def test_darwin_transport_and_path_content_guards(self):
        for change in [None, "replace", "symlink", "content"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                folder=Path(root)/"image";folder.mkdir(mode=0o700)
                metadata=fixture(folder)
                _,stream=image.open_verified(folder,SOURCE,1)
                os.fchmod(stream.fileno(),0o400)
                path=folder/"task-image.tar"
                try:
                    def operation():
                        with image.archive_transport(stream,folder,metadata,"darwin") as (source,fds):
                            self.assertEqual(source,"docker-archive:"+str(path.absolute()))
                            self.assertEqual(fds,())
                            if change=="replace":
                                other=folder/"replacement";other.write_bytes(b"wrong");other.replace(path)
                            elif change=="symlink":
                                path.unlink();path.symlink_to("/outside")
                            elif change=="content":
                                os.fchmod(stream.fileno(),0o600)
                                with path.open("r+b") as out:out.write(b"wrong")
                                os.fchmod(stream.fileno(),0o400)
                    if change:
                        with self.assertRaises((Failure,OSError)):operation()
                    else:
                        operation()
                        with image.archive_transport(stream,folder,metadata,"linux") as (source,fds):
                            self.assertEqual(source,f"docker-archive:/dev/fd/{stream.fileno()}")
                            self.assertEqual(fds,(stream.fileno(),))
                finally:stream.close()

    def test_destination_config_must_match_ci_identity(self):
        identity="sha256:"+"a"*64
        valid={"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
               "config":{"digest":identity},"layers":[{}]}
        image.validate_destination(json.dumps(valid).encode(),identity)
        for edit in [{"config":{"digest":"sha256:"+"b"*64}},{"mediaType":"application/vnd.oci.image.index.v1+json"},
                     {"layers":[]},{"schemaVersion":1}]:
            with self.subTest(edit=edit),self.assertRaises(Failure):
                image.validate_destination(json.dumps(dict(valid,**edit)).encode(),identity)

    def test_exact_successful_main_workflow_and_attempt(self):
        self.assertEqual(image.validate_run(run_metadata(),SOURCE,"123"),1)
        for edit in [{"event":"pull_request"},{"head_branch":"feature"},{"head_sha":"b"*40},
                     {"head_repository":"other/repo"},{"path":"other.yml"},{"conclusion":"failure"},
                     {"run_attempt":True},{"id":True},{"extra":"field"}]:
            with self.subTest(edit=edit),self.assertRaises(Failure):
                image.validate_run(dict(run_metadata(),**edit),SOURCE,"123")
        artifact={"id":42,"name":image.artifact_name(SOURCE,1),"expired":False,
                  "size_in_bytes":100,"digest":"sha256:"+"c"*64,
                  "workflow_run":{"id":123,"head_sha":SOURCE,"head_branch":"main"}}
        data={"total_count":1,"artifacts":[artifact]}
        self.assertEqual(image.select_artifact(data,SOURCE,"123",1)["id"],42)
        for edit in [{"expired":True},{"name":image.artifact_name(SOURCE,2)},{"digest":None},
                     {"size_in_bytes":image.MAX_DOWNLOAD+1},{"workflow_run":{"id":122,"head_sha":SOURCE,"head_branch":"main"}}]:
            with self.subTest(edit=edit),self.assertRaises(Failure):
                image.select_artifact({"total_count":1,"artifacts":[dict(artifact,**edit)]},SOURCE,"123",1)

    def test_integrity_config_platform_members_and_bound_descriptor(self):
        with tempfile.TemporaryDirectory() as folder:
            metadata=fixture(folder)
            self.assertEqual(image.verify(folder,SOURCE,1),metadata)
            verified, stream=image.open_verified(folder,SOURCE,1)
            original=(Path(folder)/"task-image.tar").read_bytes()
            replacement=Path(folder)/"replacement"
            replacement.write_bytes(b"wrong")
            replacement.replace(Path(folder)/"task-image.tar")
            self.assertEqual(stream.read(),original)
            stream.close()
        for flags in [{"platform":"arm64"},{"duplicate":True},{"link":True},{"extra":"../outside"},
                      {"extra":"/absolute"},{"multi":True},{"missing_layer":True}]:
            with self.subTest(flags=flags),tempfile.TemporaryDirectory() as folder:
                fixture(folder,**flags)
                with self.assertRaises(Failure):
                    image.verify(folder,SOURCE,1)
        for edit in [{"source_commit":"b"*40},{"image_id":"sha256:"+"f"*64},
                     {"archive_sha256":"0"*64},{"archive_size":image.MAX_ARCHIVE+1},
                     {"run_attempt":True},{"extra":True}]:
            with self.subTest(edit=edit),tempfile.TemporaryDirectory() as folder:
                metadata=fixture(folder)
                (Path(folder)/"metadata.json").write_text(json.dumps(dict(metadata,**edit)))
                with self.assertRaises(Failure):
                    image.verify(folder,SOURCE,1)

    def test_nonregular_metadata_and_extra_files_rejected(self):
        for kind in ["symlink","fifo","extra"]:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                fixture(folder)
                path=Path(folder)/"metadata.json"
                if kind=="extra":
                    (Path(folder)/"extra").write_text("x")
                else:
                    path.unlink()
                    path.symlink_to("other") if kind=="symlink" else os.mkfifo(path,0o600)
                with self.assertRaises((OSError,Failure)):
                    image.verify(folder,SOURCE,1)

    def test_bounded_download_and_no_generic_zip_extraction(self):
        for malformed in [False,True]:
            with self.subTest(malformed=malformed),tempfile.TemporaryDirectory() as source,tempfile.TemporaryDirectory() as target:
                fixture(source)
                payload=io.BytesIO()
                with zipfile.ZipFile(payload,"w",compression=zipfile.ZIP_DEFLATED) as bundle:
                    bundle.writestr("metadata.json",(Path(source)/"metadata.json").read_bytes())
                    bundle.writestr("../outside" if malformed else "task-image.tar",(Path(source)/"task-image.tar").read_bytes())
                data=payload.getvalue()
                read,write=os.pipe()
                os.write(write,data)
                os.close(write)
                process=Mock(stdout=os.fdopen(read,"rb"),pid=12345)
                process.wait.return_value=0
                process.poll.return_value=0
                artifact={"id":42,"size_in_bytes":len(data),"digest":"sha256:"+hashlib.sha256(data).hexdigest()}
                with patch.dict(os.environ,{"GH_HOST":"other.invalid"}), patch("image_artifact.subprocess.Popen",return_value=process) as start:
                    if malformed:
                        with self.assertRaises(Failure):
                            image.download(artifact,target,time.monotonic()+10,os.environ.copy())
                    else:
                        image.download(artifact,target,time.monotonic()+10,os.environ.copy())
                        self.assertEqual(image.verify(target,SOURCE,1)["source_commit"],SOURCE)
                    command=start.call_args.args[0]
                    self.assertEqual(command[command.index("--hostname")+1],"github.com")

    def test_stream_limit_applies_before_writing_oversized_download(self):
        with tempfile.TemporaryDirectory() as target:
            data=b"x"*100
            read,write=os.pipe()
            os.write(write,data)
            os.close(write)
            process=Mock(stdout=os.fdopen(read,"rb"),pid=12345)
            process.poll.return_value=0
            artifact={"id":42,"size_in_bytes":10,"digest":"sha256:"+"a"*64}
            with patch("image_artifact.subprocess.Popen",return_value=process),self.assertRaises(Failure):
                image.download(artifact,target,time.monotonic()+10,os.environ.copy())
            self.assertLessEqual((Path(target)/"download.zip").stat().st_size,10)
