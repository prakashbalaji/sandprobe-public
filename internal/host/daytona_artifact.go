package host

// RUN-23: the coding workspace/cache stay local. Native object-backed storage
// receives a bounded non-secret artifact as the agent, without chmod/chown.
import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"sandprobe/internal/strictjson"
)

//go:embed workload_artifact.py
var workloadArtifactProgram string

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
	raw, err := b.WorkloadCommand(ctx, "python3 -I -c "+daytonaQuote(workloadArtifactProgram)+" "+daytonaQuote(label+"-"+run+".json")+" "+daytonaQuote(base64.StdEncoding.EncodeToString(data)))
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
