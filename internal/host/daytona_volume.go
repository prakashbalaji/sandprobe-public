package host

// RUN-23: a volume belongs to this run only through its exclusive create journal.
// Names and labels never establish ownership; cleanup uses the returned ID.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"sandprobe/internal/strictjson"
)

type daytonaVolumeInfo struct {
	ID, Name, Organization, Born, State string
	Absent                              bool
}

type daytonaVolumeJournal struct {
	Schema, Name, ID, Born, Organization, Phase string
	Requested                                   time.Time
	Consumers                                   []daytonaVolumeConsumer
}

type daytonaVolumeConsumer struct {
	Journal string
	ID      string
	Gone    bool
}

// DaytonaVolume holds only storage created by this run. It is not an existing
// volume attachment API. An unresolved create retains its journal and blocks reuse.
type DaytonaVolume struct {
	client  *DaytonaClient
	path    string
	journal daytonaVolumeJournal
}

var daytonaVolumeName = regexp.MustCompile(`^sandprobe-volume-[a-f0-9]{24}$`)
var daytonaConsumerName = regexp.MustCompile(`^daytona-n[a-f0-9]{24}\.state$`)

func (v *DaytonaVolume) ID() string             { return v.journal.ID }
func (v *DaytonaVolume) StatePath() string      { return v.path }
func (v *DaytonaVolume) CleanupConfirmed() bool { return v.journal.Phase == "cleaned" }

func (v *DaytonaVolume) save() error {
	data, err := json.Marshal(v.journal)
	if err != nil {
		return errors.New("Daytona volume journal encoding failed")
	}
	f, err := os.CreateTemp(filepath.Dir(v.path), ".daytona-volume-")
	if err != nil {
		return errors.New("Daytona volume journal update failed")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(f.Name(), v.path) != nil {
		return errors.New("Daytona volume journal update failed")
	}
	return syncDaytonaDirectory(filepath.Dir(v.path))
}

func privateDaytonaVolumeDirectory(dir string) error {
	if os.MkdirAll(dir, 0700) != nil {
		return errors.New("Daytona volume directory unavailable")
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("Daytona volume directory unsafe")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return errors.New("Daytona volume directory not owned")
	}
	return nil
}

// RecoverDaytonaVolume resumes only a recorded volume, never a create or name
// discovery. An ID-less intent is recoverable as evidence, but cannot be deleted.
func (c *DaytonaClient) RecoverDaytonaVolume(path string) (*DaytonaVolume, error) {
	if filepath.Base(path) != "workspace-volume.state" {
		return nil, errors.New("Daytona volume journal path invalid")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("Daytona volume journal unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Daytona volume journal unsafe")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, errors.New("Daytona volume journal not owned")
	}
	if err = privateDaytonaVolumeDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	var j daytonaVolumeJournal
	if err != nil || strictjson.Decode(raw, 65536, &j) != nil || j.Schema != "sandprobe.daytona-volume-state/1" || !daytonaVolumeName.MatchString(j.Name) || j.Requested.IsZero() {
		return nil, errors.New("Daytona volume journal invalid")
	}
	if j.Phase == "create_intent" {
		if j.ID != "" || j.Born != "" || j.Organization != "" || len(j.Consumers) != 0 {
			return nil, errors.New("Daytona volume intent invalid")
		}
	} else {
		if !daytonaID.MatchString(j.ID) {
			return nil, errors.New("Daytona volume original ID unavailable")
		}
		switch j.Phase {
		case "created", "ready", "delete_intent", "cleaned":
		default:
			return nil, errors.New("Daytona volume phase invalid")
		}
		if j.Born != "" {
			born, e := time.Parse(time.RFC3339Nano, j.Born)
			if e != nil || born.Before(j.Requested.Add(-time.Minute)) || born.After(j.Requested.Add(2*time.Minute)) || j.Organization == "" {
				return nil, errors.New("Daytona volume creation identity invalid")
			}
		} else if j.Organization != "" || j.Phase == "ready" || j.Phase == "delete_intent" {
			return nil, errors.New("Daytona volume creation identity missing")
		}
	}
	if len(j.Consumers) > 2 || (len(j.Consumers) > 0 && (j.Born == "" || j.Phase == "created")) {
		return nil, errors.New("Daytona volume consumer limit")
	}
	paths, ids := map[string]bool{}, map[string]bool{}
	for _, consumer := range j.Consumers {
		if filepath.Dir(consumer.Journal) != filepath.Dir(path) || !daytonaConsumerName.MatchString(filepath.Base(consumer.Journal)) || paths[consumer.Journal] || (consumer.ID != "" && (!daytonaID.MatchString(consumer.ID) || ids[consumer.ID])) || (consumer.Gone && consumer.ID == "") || ((j.Phase == "cleaned" || j.Phase == "delete_intent") && !consumer.Gone) {
			return nil, errors.New("Daytona volume consumer record invalid")
		}
		paths[consumer.Journal], ids[consumer.ID] = true, true
	}
	return &DaytonaVolume{client: c, path: path, journal: j}, nil
}

func (c *DaytonaClient) CreateDaytonaVolume(ctx context.Context, dir string) (*DaytonaVolume, error) {
	if err := privateDaytonaVolumeDirectory(dir); err != nil {
		return nil, err
	}
	v := &DaytonaVolume{client: c, path: filepath.Join(dir, "workspace-volume.state"),
		journal: daytonaVolumeJournal{Schema: "sandprobe.daytona-volume-state/1", Name: token("sandprobe-volume-"), Requested: time.Now().UTC(), Phase: "create_intent"}}
	f, err := os.OpenFile(v.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("Daytona volume intent already exists or cannot be written")
	}
	data, _ := json.Marshal(v.journal)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || syncDaytonaDirectory(dir) != nil {
		return v, errors.New("Daytona volume intent not durable")
	}
	var created struct{ ID string }
	if err = c.call(ctx, "volume_create", map[string]any{"name": v.journal.Name}, &created); err != nil {
		return v, err
	}
	if !daytonaID.MatchString(created.ID) {
		return v, errors.New("Daytona volume create ID unavailable; retain intent")
	}
	v.journal.ID, v.journal.Phase = created.ID, "created"
	if err = v.save(); err != nil {
		return v, err
	}
	for {
		info, err := v.lookup(ctx)
		if err != nil {
			return v, err
		}
		if err = v.bind(info); err != nil {
			return v, err
		}
		switch info.State {
		case "ready":
			v.journal.Phase = "ready"
			return v, v.save()
		case "creating", "pending_create":
		default:
			return v, errors.New("Daytona volume is not ready")
		}
		select {
		case <-ctx.Done():
			return v, errors.New("Daytona volume readiness deadline")
		case <-time.After(time.Second):
		}
	}
}

func (v *DaytonaVolume) lookup(ctx context.Context) (daytonaVolumeInfo, error) {
	var info daytonaVolumeInfo
	if !daytonaID.MatchString(v.ID()) {
		return info, errors.New("Daytona volume create unresolved; no guessed lookup")
	}
	err := v.client.call(ctx, "volume_lookup", map[string]any{"volume_id": v.ID()}, &info)
	if err == nil && info.ID != v.ID() {
		err = errors.New("Daytona volume lookup identity changed")
	}
	return info, err
}

func (v *DaytonaVolume) bind(info daytonaVolumeInfo) error {
	if info.Absent || info.ID != v.ID() || info.Name != v.journal.Name || info.Organization == "" {
		return errors.New("Daytona volume ownership mismatch")
	}
	if v.journal.Born != "" {
		if info.Born != v.journal.Born || info.Organization != v.journal.Organization {
			return errors.New("Daytona volume creation identity changed")
		}
		return nil
	}
	born, err := time.Parse(time.RFC3339Nano, info.Born)
	if err != nil || born.Before(v.journal.Requested.Add(-time.Minute)) || born.After(v.journal.Requested.Add(2*time.Minute)) {
		return errors.New("Daytona volume creation timestamp unavailable")
	}
	v.journal.Born, v.journal.Organization = info.Born, info.Organization
	return v.save()
}

func (v *DaytonaVolume) Verify(ctx context.Context) error {
	if v.journal.Phase != "ready" {
		return errors.New("Daytona volume is not active")
	}
	info, err := v.lookup(ctx)
	if err != nil {
		return err
	}
	if err = v.bind(info); err != nil {
		return err
	}
	if info.State != "ready" {
		return errors.New("Daytona volume state changed")
	}
	return nil
}

// Register the sandbox intent before its create request. A lost create response
// leaves an unresolved consumer and therefore prevents deleting its storage.
func (v *DaytonaVolume) consumerIntent(path string) error {
	if v.journal.Phase != "ready" || filepath.Dir(path) != filepath.Dir(v.path) || !daytonaConsumerName.MatchString(filepath.Base(path)) || len(v.journal.Consumers) >= 2 {
		return errors.New("Daytona volume consumer intent invalid")
	}
	for _, c := range v.journal.Consumers {
		if c.Journal == path {
			return errors.New("Daytona volume consumer intent already exists")
		}
		if c.ID == "" || !c.Gone {
			return errors.New("Daytona volume previous consumer deletion unconfirmed")
		}
	}
	v.journal.Consumers = append(v.journal.Consumers, daytonaVolumeConsumer{Journal: path})
	return v.save()
}

func (v *DaytonaVolume) consumerCreated(path, id string) error {
	if !daytonaID.MatchString(id) {
		return errors.New("Daytona volume consumer ID unavailable")
	}
	for _, c := range v.journal.Consumers {
		if c.ID == id {
			return errors.New("Daytona volume consumer ID reused")
		}
	}
	for i, c := range v.journal.Consumers {
		if c.Journal == path && c.ID == "" {
			v.journal.Consumers[i].ID = id
			return v.save()
		}
	}
	return errors.New("Daytona volume consumer has no original intent")
}

func (v *DaytonaVolume) consumerGone(b *DaytonaBox) error {
	if b.CleanupProof != "provider lookup404" && b.CleanupProof != "provider state=destroyed/desiredState=destroyed; terminal metadata may remain" {
		return errors.New("Daytona volume consumer deletion unconfirmed")
	}
	path := b.state
	if b.volumeConsumer != "" {
		path = b.volumeConsumer
	}
	for i, c := range v.journal.Consumers {
		if c.Journal == path && c.ID == b.ID() && c.ID != "" {
			v.journal.Consumers[i].Gone = true
			return v.save()
		}
	}
	return errors.New("Daytona volume consumer identity changed")
}

// Destroy confirms absence through the exact original ID. A successful DELETE
// request alone is insufficient. The confirmed journal remains as recovery proof.
// Callers must first confirm every sandbox that mounted it has been deleted.
func (v *DaytonaVolume) Destroy(ctx context.Context) error {
	if !daytonaID.MatchString(v.ID()) {
		return errors.New("Daytona volume create unresolved; retain intent")
	}
	if v.journal.Phase == "cleaned" {
		return nil
	}
	for _, c := range v.journal.Consumers {
		if c.ID == "" || !c.Gone {
			return errors.New("Daytona volume still has an unresolved sandbox consumer")
		}
	}
	info, err := v.lookup(ctx)
	if err != nil {
		return err
	}
	if info.Absent {
		v.journal.Phase = "cleaned"
		return v.save()
	}
	if err = v.bind(info); err != nil {
		return err
	}
	v.journal.Phase = "delete_intent"
	if err = v.save(); err != nil {
		return err
	}
	var deleted struct {
		ID        string
		Requested bool `json:"deleted_request"`
		Absent    bool
	}
	if err = v.client.call(ctx, "volume_delete", map[string]any{"volume_id": v.ID(), "name": v.journal.Name, "born": v.journal.Born, "organization": v.journal.Organization}, &deleted); err != nil {
		return err
	}
	if deleted.ID != v.ID() || (!deleted.Requested && !deleted.Absent) {
		return errors.New("Daytona volume deletion response invalid")
	}
	for {
		info, err = v.lookup(ctx)
		if err != nil {
			return err
		}
		if info.Absent {
			v.journal.Phase = "cleaned"
			return v.save()
		}
		if err = v.bind(info); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("Daytona volume deletion unconfirmed")
		case <-time.After(time.Second):
		}
	}
}
