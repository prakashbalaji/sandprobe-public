package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testDaytonaVolumeID = "12345678-1234-1234-1234-123456789abc"

// RUN-24: an independently proven rejection is not a fabricated sandbox ID or
// deletion. Missing/contradictory proof retains both intent and storage.
func TestDaytonaRejectedConsumerRecovery(t *testing.T) {
	for _, fault := range []string{"", "transport", "not-refused", "digest"} {
		t.Run(fault, func(t *testing.T) {
			c, dir, deleted, _ := volumeFixture(t)
			v, err := c.CreateDaytonaVolume(context.Background(), dir, "/persist")
			if err != nil {
				t.Fatal(err)
			}
			j := daytonaJournal{Nonce: "n" + strings.Repeat("a", 24), Name: "sandprobe-" + strings.Repeat("b", 24), Requested: time.Now().UTC().Add(-3 * time.Minute), SnapshotID: testDaytonaVolumeID, NetworkAllowList: "52.94.0.1/32", Volume: &daytonaVolumeMount{ID: v.ID(), MountPath: "/persist"}}
			path := filepath.Join(dir, "daytona-"+j.Nonce+".state")
			raw, _ := json.Marshal(j)
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = v.consumerIntent(path); err != nil {
				t.Fatal(err)
			}
			base := c.runtime
			c.runtime = func(ctx context.Context, in map[string]any) ([]byte, error) {
				if in["op"] != "rejected_create" {
					return base(ctx, in)
				}
				if in["name"] != j.Name || in["nonce"] != j.Nonce || in["organization"] != v.journal.Organization || in["snapshot_id"] != j.SnapshotID || in["network_allow_list"] != j.NetworkAllowList || in["requested"] != j.Requested.Format(time.RFC3339Nano) {
					t.Fatal("refusal not bound to original intent")
				}
				if fault == "transport" {
					return nil, errors.New("fixed unavailable audit")
				}
				digest := strings.Repeat("c", 64)
				if fault == "digest" {
					digest = "invalid"
				}
				return json.Marshal(map[string]any{"refused": fault != "not-refused", "evidence_sha256": digest})
			}
			result, err := c.CleanupDaytonaPersistentState(context.Background(), v.StatePath())
			if fault != "" {
				if err == nil || result.Confirmed || *deleted {
					t.Fatal("unproven refusal released storage")
				}
				return
			}
			if err != nil || !result.Confirmed || !*deleted || len(result.BoxIDs) != 0 {
				t.Fatal("refusal recovery failed or invented ID", err)
			}
			v, err = c.RecoverDaytonaVolume(v.StatePath())
			if err != nil || len(v.journal.Consumers) != 1 {
				t.Fatal("durable refusal missing", err)
			}
			consumer := v.journal.Consumers[0]
			if consumer.RefusalSHA256 != strings.Repeat("c", 64) || consumer.ID != "" || consumer.Gone {
				t.Fatal("refusal was mislabeled deletion")
			}
			if _, err = os.Stat(path); err != nil {
				t.Fatal("failed create intent was removed")
			}
			// Contradictory local state cannot bypass the original-ID guard.
			v.journal.Consumers[0].ID = testDaytonaVolumeID
			if err = v.save(); err != nil {
				t.Fatal(err)
			}
			if _, err = c.RecoverDaytonaVolume(v.StatePath()); err == nil {
				t.Fatal("contradictory refused/created consumer accepted")
			}
		})
	}
}

func volumeFixture(t *testing.T) (*DaytonaClient, string, *bool, *[]string) {
	t.Helper()
	client, _ := NewDaytonaClient("fixture-key", "")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	deleted, calls := false, []string{}
	name, born := "", time.Now().UTC().Format(time.RFC3339Nano)
	client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
		op := in["op"].(string)
		calls = append(calls, op)
		var out any
		switch op {
		case "rejected_create":
			return nil, errors.New("fixture has no authenticated refusal evidence")
		case "volume_create":
			name = in["name"].(string)
			raw, err := os.ReadFile(filepath.Join(dir, "workspace-volume.state"))
			var j daytonaVolumeJournal
			if err != nil || json.Unmarshal(raw, &j) != nil || j.Phase != "create_intent" || j.ID != "" || j.Name != name {
				t.Fatal("create preceded durable exclusive intent")
			}
			out = map[string]any{"id": testDaytonaVolumeID, "ignored_optional_metadata": map[string]any{"untrusted": true}}
		case "volume_lookup":
			raw, _ := os.ReadFile(filepath.Join(dir, "workspace-volume.state"))
			var j daytonaVolumeJournal
			if json.Unmarshal(raw, &j) != nil || j.ID != testDaytonaVolumeID || in["volume_id"] != j.ID {
				t.Fatal("volume ID not durable or lookup guessed")
			}
			out = map[string]any{"id": testDaytonaVolumeID, "name": name, "organization": "fixture-org", "born": born, "state": "ready"}
			if deleted {
				out = map[string]any{"id": testDaytonaVolumeID, "absent": true}
			}
		case "volume_delete":
			if in["volume_id"] != testDaytonaVolumeID || in["name"] != name || in["born"] != born || in["organization"] != "fixture-org" {
				t.Fatal("volume delete not bound to original identity")
			}
			deleted = true
			out = map[string]any{"id": testDaytonaVolumeID, "deleted_request": true}
		default:
			t.Fatalf("unexpected operation %s", op)
		}
		return json.Marshal(out)
	}
	return client, dir, &deleted, &calls
}

func TestDaytonaVolumeDurableCreateConsumersAndCleanup(t *testing.T) {
	c, dir, deleted, calls := volumeFixture(t)
	v, err := c.CreateDaytonaVolume(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID() != testDaytonaVolumeID || v.CleanupConfirmed() {
		t.Fatal("incorrect initial lifecycle")
	}
	if err = v.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	consumerPath := filepath.Join(dir, "daytona-n"+strings.Repeat("a", 24)+".state")
	if err = v.consumerIntent(consumerPath); err != nil {
		t.Fatal(err)
	}
	count := len(*calls)
	if v.Destroy(context.Background()) == nil || len(*calls) != count {
		t.Fatal("unknown create consumer did not block deletion")
	}
	box := &DaytonaBox{state: consumerPath, journal: daytonaJournal{ID: "22345678-1234-1234-1234-123456789abc"}}
	if err = v.consumerCreated(consumerPath, box.ID()); err != nil {
		t.Fatal(err)
	}
	if v.Destroy(context.Background()) == nil || *deleted {
		t.Fatal("live consumer did not block deletion")
	}
	if v.consumerGone(box) == nil {
		t.Fatal("consumer was retired without provider cleanup proof")
	}
	box.CleanupProof = "provider lookup404"
	if err = v.consumerGone(box); err != nil {
		t.Fatal(err)
	}
	v, err = c.RecoverDaytonaVolume(v.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !*deleted || !v.CleanupConfirmed() {
		t.Fatal("cleanup not confirmed")
	}
	if _, err = os.Stat(v.StatePath()); err != nil {
		t.Fatal("cleanup proof journal was removed")
	}
	v, err = c.RecoverDaytonaVolume(v.StatePath())
	if err != nil || !v.CleanupConfirmed() {
		t.Fatal("cleanup proof cannot be recovered", err)
	}
	count = len(*calls)
	if err = v.Destroy(context.Background()); err != nil || len(*calls) != count {
		t.Fatal("confirmed cleanup was repeated", err)
	}
}

func TestDaytonaVolumeAmbiguousCreateNeverRetriesOrDiscovers(t *testing.T) {
	c, dir, _, _ := volumeFixture(t)
	calls := 0
	c.runtime = func(context.Context, map[string]any) ([]byte, error) {
		calls++
		return nil, errors.New("fixed failure")
	}
	v, err := c.CreateDaytonaVolume(context.Background(), dir)
	if err == nil || v == nil || v.ID() != "" || calls != 1 {
		t.Fatal("ambiguous create lost its intent")
	}
	if v.Destroy(context.Background()) == nil || calls != 1 {
		t.Fatal("cleanup guessed an unknown ID")
	}
	if _, err = c.CreateDaytonaVolume(context.Background(), dir); err == nil || calls != 1 {
		t.Fatal("create was retried")
	}
	v, err = c.RecoverDaytonaVolume(v.StatePath())
	if err != nil || v.ID() != "" || v.Destroy(context.Background()) == nil || calls != 1 {
		t.Fatal("recovery adopted or retried a resource", err)
	}
}

func TestDaytonaVolumeOwnershipDriftBlocksDelete(t *testing.T) {
	for _, field := range []string{"id", "name", "born", "organization"} {
		t.Run(field, func(t *testing.T) {
			c, dir, _, _ := volumeFixture(t)
			v, err := c.CreateDaytonaVolume(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			base := c.runtime
			deletes := 0
			c.runtime = func(ctx context.Context, in map[string]any) ([]byte, error) {
				if in["op"] == "volume_delete" {
					deletes++
				}
				raw, e := base(ctx, in)
				if in["op"] == "volume_lookup" {
					var value map[string]any
					json.Unmarshal(raw, &value)
					value[field] = "replacement"
					raw, _ = json.Marshal(value)
				}
				return raw, e
			}
			if v.Verify(context.Background()) == nil || v.Destroy(context.Background()) == nil || deletes != 0 {
				t.Fatal("changed ownership authorized use/delete")
			}
		})
	}
}

func TestDaytonaVolumeRecoveryRejectsUnsafeOrContradictoryJournal(t *testing.T) {
	c, dir, _, _ := volumeFixture(t)
	v, err := c.CreateDaytonaVolume(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(v.StatePath())
	for _, edit := range []func(map[string]any){
		func(j map[string]any) { j["Phase"] = "invented" },
		func(j map[string]any) { j["ID"] = "named-volume" },
		func(j map[string]any) { j["Phase"] = "create_intent" },
		func(j map[string]any) { j["Born"] = "" },
		func(j map[string]any) { j["unknown"] = "ignored?" },
	} {
		var j map[string]any
		json.Unmarshal(original, &j)
		edit(j)
		raw, _ := json.Marshal(j)
		if err = os.WriteFile(v.StatePath(), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = c.RecoverDaytonaVolume(v.StatePath()); err == nil {
			t.Fatal("unsafe recovery accepted")
		}
	}
	os.WriteFile(v.StatePath(), original, 0600)
	os.Chmod(v.StatePath(), 0644)
	if _, err = c.RecoverDaytonaVolume(v.StatePath()); err == nil {
		t.Fatal("world-readable state accepted")
	}
}

func TestDaytonaPersistentBoxJournalsMountAndRejectsDrift(t *testing.T) {
	c, dir, deleted, _ := volumeFixture(t)
	v, err := c.CreateDaytonaVolume(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	base := c.runtime
	boxID := "22345678-1234-1234-1234-123456789abc"
	born := time.Now().UTC().Format(time.RFC3339Nano)
	name, nonce := "", ""
	boxDeleted := false
	c.runtime = func(ctx context.Context, in map[string]any) ([]byte, error) {
		switch in["op"] {
		case "create":
			name, nonce = in["name"].(string), in["nonce"].(string)
			mount, ok := in["volume_binding"].(*daytonaVolumeMount)
			if !ok || mount.ID != v.ID() || mount.MountPath != "/workspace" || mount.Subpath != "" {
				t.Fatal("unbound persistent workspace")
			}
			var journal daytonaVolumeJournal
			raw, _ := os.ReadFile(v.path)
			json.Unmarshal(raw, &journal)
			if len(journal.Consumers) != 1 || journal.Consumers[0].ID != "" {
				t.Fatal("sandbox create preceded mount intent")
			}
			return json.Marshal(map[string]any{"id": boxID})
		case "lookup":
			if in["id"] != boxID {
				t.Fatal("lookup guessed box ID")
			}
			var journal daytonaVolumeJournal
			raw, _ := os.ReadFile(v.path)
			json.Unmarshal(raw, &journal)
			if len(journal.Consumers) != 1 || journal.Consumers[0].ID != boxID {
				t.Fatal("box ID not journaled before metadata lookup")
			}
			if boxDeleted {
				return json.Marshal(map[string]any{"absent": true})
			}
			return json.Marshal(map[string]any{"id": boxID, "name": name, "born": born, "organization": "fixture-org", "labels": map[string]string{"sandprobe_run": nonce}, "state": "started", "desired_state": "started", "user": "root", "public": false, "auto_delete": 0, "auto_stop": 15, "auto_pause": 0, "volumes": 1, "volume_bindings": []daytonaVolumeMount{{ID: v.ID(), MountPath: "/workspace"}}, "snapshot_id": testDaytonaVolumeID, "network_allow_list": "52.94.0.1/32", "network_block_all": false})
		case "delete":
			if in["id"] != boxID || in["nonce"] != nonce {
				t.Fatal("unbound box deletion")
			}
			boxDeleted = true
			return json.Marshal(map[string]any{"id": boxID, "deleted_request": true})
		}
		return base(ctx, in)
	}
	b, err := c.CreateDaytonaWorkload(context.Background(), dir, testDaytonaVolumeID, "52.94.0.1/32", v)
	if err != nil {
		t.Fatal(err)
	}
	info, err := b.lookup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*daytonaInfo){
		func(d *daytonaInfo) { d.VolumeBindings[0].ID = "32345678-1234-1234-1234-123456789abc" },
		func(d *daytonaInfo) { d.VolumeBindings[0].MountPath = "/other" },
		func(d *daytonaInfo) { d.VolumeBindings[0].Subpath = "other" },
		func(d *daytonaInfo) { d.Organization = "another-org" },
	} {
		changed := info
		changed.VolumeBindings = append([]daytonaVolumeMount(nil), info.VolumeBindings...)
		edit(&changed)
		if b.match(changed) == nil {
			t.Fatal("changed volume mount accepted")
		}
	}
	if v.Destroy(context.Background()) == nil || *deleted {
		t.Fatal("attached workspace was deleted")
	}
	if err = b.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !v.journal.Consumers[0].Gone {
		t.Fatal("box deletion proof not retained with volume")
	}
	if err = v.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDaytonaVolumeDeleteRequestIsNotCleanupProof(t *testing.T) {
	c, dir, _, _ := volumeFixture(t)
	v, err := c.CreateDaytonaVolume(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	base := c.runtime
	c.runtime = func(ctx context.Context, in map[string]any) ([]byte, error) {
		raw, err := base(ctx, in)
		if in["op"] == "volume_delete" {
			return []byte(`{"id":"22345678-1234-1234-1234-123456789abc","deleted_request":true}`), nil
		}
		return raw, err
	}
	if v.Destroy(context.Background()) == nil || v.CleanupConfirmed() {
		t.Fatal("incorrect delete response became cleanup proof")
	}
	v, err = c.RecoverDaytonaVolume(v.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Destroy(context.Background()); err != nil || !v.CleanupConfirmed() {
		t.Fatal("exact-ID absence did not settle ambiguous delete", err)
	}
}

func TestDaytonaVolumeTerminalDeletedMetadataKeepsCreationBinding(t *testing.T) {
	for _, drift := range []string{"", "born", "organization"} {
		t.Run(drift, func(t *testing.T) {
			c, dir, _, _ := volumeFixture(t)
			v, err := c.CreateDaytonaVolume(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			c.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
				if in["op"] != "volume_lookup" {
					t.Fatal("terminal metadata caused another delete")
				}
				value := map[string]any{"id": v.ID(), "name": "provider-deleted-tombstone", "born": v.journal.Born, "organization": v.journal.Organization, "state": "deleted"}
				if drift != "" {
					value[drift] = "different-creation"
				}
				return json.Marshal(value)
			}
			err = v.Destroy(context.Background())
			if (drift == "") != (err == nil && v.CleanupConfirmed()) {
				t.Fatal("terminal deletion identity was misclassified", err)
			}
		})
	}
}
