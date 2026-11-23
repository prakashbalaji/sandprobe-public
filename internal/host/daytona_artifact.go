package host

// RUN-23: the coding workspace/cache stay local. Native object-backed storage
// receives a bounded non-secret artifact as the agent, without chmod/chown.
import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"sandprobe/internal/strictjson"
)

type DaytonaArtifactProof struct {
	AgentUID    uint32 `json:"agent_uid"`
	AgentGID    uint32 `json:"agent_gid"`
	RootUID     uint32 `json:"root_uid"`
	RootGID     uint32 `json:"root_gid"`
	RootMode    uint32 `json:"root_mode"`
	Directory   bool   `json:"directory"`
	Verified    bool   `json:"verified"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	FailureKind string `json:"failure_kind"`
}

func (b *DaytonaBox) VerifyArtifactStorage(ctx context.Context, run, label string, data []byte) (DaytonaArtifactProof, error) {
	var proof DaytonaArtifactProof
	bad := errors.New("persistent artifact storage unverified")
	if b.journal.Volume == nil || b.journal.Volume.MountPath != "/persist" || !agentRun.MatchString(run) || (label != "preflight" && label != "workload-result") || len(data) == 0 || len(data) > 4096 {
		return proof, bad
	}
	script := `import base64,errno,hashlib,json,os,stat,sys
r={"agent_uid":os.getuid(),"agent_gid":os.getgid(),"root_uid":0,"root_gid":0,"root_mode":0,"directory":False,"verified":False,"bytes":0,"sha256":"","failure_kind":"root_unavailable"}
try:
 s=os.stat("/persist",follow_symlinks=False)
 r.update(root_uid=s.st_uid,root_gid=s.st_gid,root_mode=stat.S_IMODE(s.st_mode),directory=stat.S_ISDIR(s.st_mode))
 if not r["directory"]:raise OSError(errno.ENOTDIR,"root")
 d=os.open("/persist",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  r["failure_kind"]="write_unavailable"
  data=base64.b64decode(sys.argv[2],validate=True)
  with os.fdopen(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d),"wb") as f:f.write(data)
  r["failure_kind"]="readback_unavailable"
  with os.fdopen(os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d),"rb") as f:actual=f.read(len(data)+1)
  if actual==data:r.update(verified=True,bytes=len(data),sha256=hashlib.sha256(actual).hexdigest(),failure_kind="passed")
 finally:os.close(d)
except OSError:pass
print(json.dumps(r,separators=(",",":")))`
	raw, err := b.WorkloadCommand(ctx, "python3 -I -c "+daytonaQuote(script)+" "+daytonaQuote(label+"-"+run+".json")+" "+daytonaQuote(base64.StdEncoding.EncodeToString(data)))
	if err != nil {
		return proof, bad
	}
	if strictjson.Decode(raw, 4096, &proof) != nil || proof.AgentUID != 10001 || proof.AgentGID != 10001 || proof.RootMode > 07777 {
		return DaytonaArtifactProof{}, bad
	}
	if !proof.Verified {
		if proof.FailureKind != "root_unavailable" && proof.FailureKind != "write_unavailable" && proof.FailureKind != "readback_unavailable" {
			return DaytonaArtifactProof{}, bad
		}
		return proof, bad
	}
	digest := sha256.Sum256(data)
	if !proof.Directory || proof.Bytes != len(data) || proof.SHA256 != hex.EncodeToString(digest[:]) || proof.FailureKind != "passed" {
		return DaytonaArtifactProof{}, bad
	}
	return proof, nil
}
