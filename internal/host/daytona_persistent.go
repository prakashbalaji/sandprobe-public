package host

// RUN-23: other checks observe the original workload box. Only PER-5 recreates
// it afterwards, through the same generic TWN-3 marker/reset/recheck engine.
import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"sandprobe/internal/obs"
)

type DaytonaPersistentBox struct {
	original, current              *DaytonaBox
	boxes                          []*DaytonaBox
	volume                         *DaytonaVolume
	binary                         []byte
	configuration                  DaytonaWorkloadConfiguration
	fixture                        DaytonaFixture
	resetStarted, originalVerified bool
}

type DaytonaPersistentCleanup struct {
	BoxIDs           []string `json:"box_ids"`
	BoxesConfirmed   bool     `json:"boxes_confirmed"`
	StorageConfirmed bool     `json:"storage_confirmed"`
	Confirmed        bool     `json:"confirmed"`
}

func (p *DaytonaPersistentBox) BoxIDs() []string {
	ids := make([]string, 0, len(p.boxes))
	for _, box := range p.boxes {
		if box.ID() == "" {
			rejected := false
			for _, consumer := range p.volume.journal.Consumers {
				if consumer.Journal == box.state && consumer.RefusalSHA256 != "" {
					rejected = true
				}
			}
			if rejected {
				continue
			}
		}
		ids = append(ids, box.ID())
	}
	return ids
}

// CleanupDaytonaPersistentState recovers every consumer before releasing storage.
// A missing or ID-less live consumer journal is uncertainty, never box absence.
func (c *DaytonaClient) CleanupDaytonaPersistentState(ctx context.Context, path string) (DaytonaPersistentCleanup, error) {
	result := DaytonaPersistentCleanup{BoxIDs: []string{}}
	v, err := c.RecoverDaytonaVolume(path)
	if err != nil {
		return result, err
	}
	for _, consumer := range v.journal.Consumers {
		if consumer.ID != "" {
			result.BoxIDs = append(result.BoxIDs, consumer.ID)
		}
		if consumer.Gone || consumer.RefusalSHA256 != "" {
			continue
		}
		if _, err = os.Lstat(consumer.Journal); err != nil {
			return result, errors.New("persistent consumer journal missing; absence unproven")
		}
		id, _, cleanupErr := c.CleanupDaytonaState(ctx, consumer.Journal)
		if id != "" && consumer.ID == "" {
			result.BoxIDs = append(result.BoxIDs, id)
		}
		if cleanupErr != nil {
			return result, cleanupErr
		}
	}
	v, err = c.RecoverDaytonaVolume(path)
	if err != nil {
		return result, err
	}
	for _, consumer := range v.journal.Consumers {
		if consumer.RefusalSHA256 != "" {
			continue
		}
		if consumer.ID == "" || !consumer.Gone {
			return result, errors.New("persistent consumer deletion unconfirmed")
		}
	}
	result.BoxesConfirmed = true
	if err = v.Destroy(ctx); err != nil {
		return result, err
	}
	result.StorageConfirmed = v.CleanupConfirmed()
	result.Confirmed = result.BoxesConfirmed && result.StorageConfirmed
	return result, nil
}

func NewDaytonaPersistentBox(ctx context.Context, b *DaytonaBox, binary []byte) (*DaytonaPersistentBox, error) {
	if b == nil || b.volume == nil || b.journal.Volume == nil || b.probePrefix != daytonaDrop || len(binary) == 0 || len(binary) > 16<<20 || (b.Arch != "amd64" && b.Arch != "arm64") {
		return nil, errors.New("persistent workload is not prepared")
	}
	if err := b.volume.Verify(ctx); err != nil {
		return nil, err
	}
	configuration, err := b.WorkloadConfiguration(ctx)
	if err != nil {
		return nil, err
	}
	fixture, err := b.WorkloadFixture(ctx)
	if err != nil {
		return nil, err
	}
	return &DaytonaPersistentBox{original: b, current: b, boxes: []*DaytonaBox{b}, volume: b.volume, binary: append([]byte(nil), binary...), configuration: configuration, fixture: fixture}, nil
}

func (p *DaytonaPersistentBox) ID() string { return p.current.ID() }
func (p *DaytonaPersistentBox) Probe(ctx context.Context, args []string, input []byte) ([]byte, error) {
	return p.current.Probe(ctx, args, input)
}

func (p *DaytonaPersistentBox) binding() obs.Volume {
	v := p.original.journal.Volume
	return obs.Volume{ID: v.ID, MountPath: v.MountPath, Subpath: v.Subpath}
}

func (p *DaytonaPersistentBox) Storage(ctx context.Context) (Storage, error) {
	if p.resetStarted {
		return Storage{}, errors.New("persistent reset already attempted")
	}
	if err := p.volume.Verify(ctx); err != nil {
		return Storage{}, err
	}
	configuration, err := p.original.WorkloadConfiguration(ctx)
	if err != nil || configuration != p.configuration {
		return Storage{}, errors.New("persistent workload configuration changed before collection")
	}
	return Storage{Model: "recreate", Volumes: []obs.Volume{p.binding()}}, nil
}

// VerifyOriginalAfterCollection also covers an unattempted reset (for example a
// failed mark). After recreation, the pre-delete check is the original's proof;
// the replacement must never supply evidence for its predecessor's other checks.
func (p *DaytonaPersistentBox) VerifyOriginalAfterCollection(ctx context.Context) error {
	if p.resetStarted && p.originalVerified {
		return nil
	}
	return p.verifyOriginal(ctx)
}

func (p *DaytonaPersistentBox) verifyOriginal(ctx context.Context) error {
	configuration, err := p.original.WorkloadConfiguration(ctx)
	if err != nil || configuration != p.configuration {
		return errors.New("original persistent workload configuration changed")
	}
	fixture, err := p.original.WorkloadFixture(ctx)
	if err != nil || fixture != p.fixture {
		return errors.New("original persistent workload fixture changed")
	}
	p.originalVerified = true
	return nil
}

func (p *DaytonaPersistentBox) Reset(ctx context.Context) (Box, *obs.ResetEvidence, error) {
	ev := &obs.ResetEvidence{Model: "recreate", OperationID: token("recreate-"), BoxBefore: p.original.ID(), Volumes: map[string][2]obs.Volume{}}
	if p.resetStarted {
		return p, ev, errors.New("persistent reset cannot be repeated")
	}
	p.resetStarted = true
	p.originalVerified = false
	if err := p.verifyOriginal(ctx); err != nil {
		return p, ev, err
	}
	if err := p.volume.Verify(ctx); err != nil {
		return p, ev, err
	}
	before := p.binding()
	if err := p.original.Destroy(ctx); err != nil {
		return p, ev, errors.New("original sandbox deletion unconfirmed before recreation")
	}
	if err := p.original.ConfirmWorkloadGone(ctx); err != nil {
		return p, ev, err
	}
	next, err := p.original.client.CreateDaytonaWorkload(ctx, filepath.Dir(p.volume.StatePath()), p.original.journal.SnapshotID, p.original.journal.NetworkAllowList, p.volume)
	if next != nil {
		p.boxes = append(p.boxes, next)
		p.current = next
		ev.BoxAfter = next.ID()
	}
	if err != nil {
		return p, ev, err
	}
	if next.ID() == p.original.ID() {
		return p, ev, errors.New("recreation did not return a new sandbox ID")
	}
	if err = next.DetectArch(ctx); err != nil {
		return p, ev, err
	}
	if next.Arch != p.original.Arch {
		return p, ev, errors.New("replacement architecture changed")
	}
	configuration, err := next.WorkloadConfiguration(ctx)
	if err != nil {
		return p, ev, err
	}
	configuration.ID = p.configuration.ID
	if configuration != p.configuration {
		return p, ev, errors.New("replacement workload configuration changed")
	}
	if err = next.prepareWorkload(ctx, before.MountPath == "/workspace"); err != nil {
		return p, ev, err
	}
	if err = next.Upload(ctx, p.binary); err != nil {
		return p, ev, err
	}
	if err = next.WorkloadProbeReady(ctx); err != nil {
		return p, ev, err
	}
	// The replacement has a new root filesystem: validate its protected fixture
	// structurally, without equating its device/inode hash to the original's.
	_, err = next.WorkloadFixture(ctx)
	if err != nil {
		return p, ev, errors.New("replacement protected home invalid")
	}
	if err = p.volume.Verify(ctx); err != nil {
		return p, ev, err
	}
	ev.Volumes[before.MountPath] = [2]obs.Volume{before, {ID: next.journal.Volume.ID, MountPath: next.journal.Volume.MountPath, Subpath: next.journal.Volume.Subpath}}
	ev.Done = true
	return p, ev, nil
}

// Teardown includes partially-created replacements. The durable volume ledger
// independently blocks deletion while any consumer's fate is unresolved.
func (p *DaytonaPersistentBox) Teardown(ctx context.Context, volumes []obs.Volume) map[string]bool {
	gone := map[string]bool{"": true, p.volume.ID(): false}
	for _, box := range p.boxes {
		if box.ID() == "" {
			if _, _, err := box.client.CleanupDaytonaState(ctx, box.state); err != nil {
				gone[""] = false
			}
			continue
		}
		if box.Destroy(ctx) != nil || box.ConfirmWorkloadGone(ctx) != nil {
			gone[""] = false
		}
	}
	if !gone[""] || len(volumes) != 1 || volumes[0] != p.binding() {
		return gone
	}
	// Reconciliation updates the durable consumer ledger, not a guessed ID.
	v, err := p.original.client.RecoverDaytonaVolume(p.volume.StatePath())
	if err != nil || v.ID() != p.volume.ID() {
		return gone
	}
	p.volume.journal = v.journal
	if p.volume.Destroy(ctx) == nil {
		gone[p.volume.ID()] = p.volume.CleanupConfirmed()
	}
	return gone
}
