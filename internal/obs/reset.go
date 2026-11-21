package obs

// PER-5 and TWN-3: what crosses the box boundary for the marks, the reset and the recheck.

const (
	MarkSchema    = "sandprobe.mark/1"
	RecheckSchema = "sandprobe.recheck/1"
	MarkerPrefix  = ".sandprobe-" // a marker is <root>/.sandprobe-<run id>, holding only the run id (SBX-1)
)

// Root is a storage root the agent can write, from the survey's read-only inventory: nothing is created to find it.
// Its device and inode let the mark confirm the directory is still the one surveyed; they are never its identity
// across a reset (TWN-3).
type Root struct {
	Path   string   `json:"path"`
	Kinds  []string `json:"kinds"` // home, wd or mount: one directory can be several
	Dev    uint64   `json:"dev"`
	Ino    uint64   `json:"ino"`
	FSType string   `json:"fstype,omitempty"` // an observation, never proof
	Source string   `json:"source,omitempty"` // an observation, never proof
}

// PlannedMark is one PER-5 marker: its root, the marker's path in it, and the root directory the survey saw. Volume is
// set when the root is a volume Sandprobe created (recreate).
type PlannedMark struct {
	Root   string  `json:"root"`
	Path   string  `json:"path"` // <root>/.sandprobe-<run id>
	Dev    uint64  `json:"dev"`
	Ino    uint64  `json:"ino"`
	Volume *Volume `json:"volume,omitempty"`
}

// Volume is a persistent volume Sandprobe created for the run, by its provider identity (TWN-3).
type Volume struct {
	ID        string `json:"id"`         // immutable
	MountPath string `json:"mount_path"` // where the provider mounts it
	Subpath   string `json:"subpath"`    // the provider-declared subpath within it
}

// MarkInput is what the host hands `sandprobe-probe -mark`; RecheckInput what it hands `-recheck`.
type MarkInput struct {
	RunID string        `json:"run_id"`
	Nonce string        `json:"nonce"`
	BoxID string        `json:"box_id"`
	Marks []PlannedMark `json:"marks"`
}

type RecheckInput struct {
	RunID   string   `json:"run_id"`
	Nonce   string   `json:"nonce"`
	BoxID   string   `json:"box_id"`
	Marks   []Placed `json:"marks"`
	Startup []string `json:"startup"` // PER-1 to PER-4's planned targets, for their write observations
}

// MarkDoc is the probe's report of the marks it placed.
type MarkDoc struct {
	Schema string   `json:"schema"`
	RunID  string   `json:"run_id"`
	Nonce  string   `json:"nonce"`
	BoxID  string   `json:"box_id"`
	BootID string   `json:"boot_id"`
	Marks  []Placed `json:"marks"`
}

// Placed is one marker as the mark left it: placed or why not, and the marker's inode and length.
type Placed struct {
	Root   string `json:"root"`
	Path   string `json:"path"`
	Placed bool   `json:"placed"`
	Ino    uint64 `json:"ino,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Why    string `json:"why,omitempty"`
}

// RecheckDoc is the probe's report after the reset: each marker survived, absent or unknown, and the write
// observations of PER-1 to PER-4's targets, for the host to judge severity.
type RecheckDoc struct {
	Schema  string      `json:"schema"`
	RunID   string      `json:"run_id"`
	Nonce   string      `json:"nonce"`
	BoxID   string      `json:"box_id"`
	BootID  string      `json:"boot_id"`
	Marks   []Rechecked `json:"marks"`
	Startup []Startup   `json:"startup"`
}

type Rechecked struct {
	Root  string `json:"root"`
	State string `json:"state"` // survived, absent or unknown
	Why   string `json:"why,omitempty"`
}

// Startup is one PER-1 to PER-4 target as the recheck saw it: its planned name, the path it resolved to, and whether
// the agent can write or replace it (found) or not.
type Startup struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

// ResetEvidence is the reset as the provider reported it to the host, never the box (TWN-3), with the probe's mark
// and recheck documents for the grader to parse.
type ResetEvidence struct {
	Model                       string               // restore or recreate
	OperationID                 string               // the reset operation the host issued
	Checkpoint                  string               // restore: the checkpoint it names
	Done                        bool                 // the provider reported that operation done
	BoxBefore, BoxAfter         string               // provider IDs
	RestoreBefore, RestoreAfter string               // restore: the provider's restore IDs
	RootIdentity                map[string][2]string // restore: per root, the provider-backed filesystem identity before and after
	Volumes                     map[string][2]Volume // recreate: per root, the volume before and after
	Mark, Recheck               []byte               // the probe's documents; nil when that step didn't run
	Cleanup                     []Cleanup            // each marker's fate
}

// Cleanup is what became of one marker: gone with its box or volume once the provider confirmed the deletion, or an
// unresolved item. A marker is never removed by name (SBX-1).
type Cleanup struct {
	Path      string
	Confirmed bool   // the mark reported the marker's identity
	Gone      bool   // its box or volume was deleted, the provider confirming it
	How       string // what was deleted, by ID, or why the marker may remain
}

// ParseMark and ParseRecheck read the probe's documents under ParseDoc's rules.
func ParseMark(b []byte) (*MarkDoc, error) {
	var d MarkDoc
	if err := strict(b, &d); err != nil {
		return nil, err
	}
	if d.Schema != MarkSchema {
		return nil, errSchema(d.Schema, MarkSchema)
	}
	return &d, nil
}

func ParseRecheck(b []byte) (*RecheckDoc, error) {
	var d RecheckDoc
	if err := strict(b, &d); err != nil {
		return nil, err
	}
	if d.Schema != RecheckSchema {
		return nil, errSchema(d.Schema, RecheckSchema)
	}
	return &d, nil
}
