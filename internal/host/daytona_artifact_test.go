package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestArtifactStorageRequiresAgentReadbackOfExactBoundedData(t *testing.T) {
	for _, mutation := range []string{"", "digest", "principal", "write-refused"} {
		t.Run(mutation, func(t *testing.T) {
			b, info := workloadDaytonaFixture(t)
			b.journal.Volume = &daytonaVolumeMount{ID: testDaytonaVolumeID, MountPath: "/persist"}
			b.volume = &DaytonaVolume{client: b.client, journal: daytonaVolumeJournal{ID: testDaytonaVolumeID, Organization: "org", MountPath: "/persist", Phase: "ready"}}
			data := []byte(`{"synthetic":true}`)
			sum := sha256.Sum256(data)
			proof := DaytonaArtifactProof{AgentUID: 10001, AgentGID: 10001, RootUID: 0, RootGID: 0, RootMode: 0777, Directory: true, Verified: true, Bytes: len(data), SHA256: hex.EncodeToString(sum[:]), FailureKind: "passed"}
			switch mutation {
			case "digest":
				proof.SHA256 = "wrong"
			case "principal":
				proof.AgentUID = 0
			case "write-refused":
				proof.Verified = false
				proof.SHA256 = ""
				proof.Bytes = 0
				proof.FailureKind = "write_unavailable"
			}
			b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
				if in["op"] == "lookup" {
					value := info()
					value["volumes"] = 1
					value["volume_bindings"] = []daytonaVolumeMount{*b.journal.Volume}
					return json.Marshal(value)
				}
				if in["op"] != "exec" {
					t.Fatal("unexpected operation")
				}
				raw, _ := json.Marshal(proof)
				return json.Marshal(map[string]any{"id": b.ID(), "stdout": string(raw), "exit_code": 0})
			}
			got, err := b.VerifyArtifactStorage(context.Background(), "aaaaaaaaaaaaaaaa", "preflight", data)
			if (mutation == "") != (err == nil) {
				t.Fatal("artifact proof incorrectly accepted", got, err)
			}
			if mutation == "write-refused" && got.FailureKind != "write_unavailable" {
				t.Fatal("safe failure metadata lost")
			}
		})
	}
}
