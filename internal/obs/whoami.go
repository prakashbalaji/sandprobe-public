package obs

// WhoAmISchema is the identity-only preflight's answer (PRV-15). It runs no check.
const WhoAmISchema = "sandprobe.whoami/1"

// WhoAmI is who the probe runs as and what the host asked about, before anything else runs in the box (PRV-15).
type WhoAmI struct {
	Schema  string `json:"schema"`
	UIDs    [4]int `json:"uids"`               // real, effective, saved-set and filesystem, from the kernel's Uid: line
	Name    string `json:"name,omitempty"`     // the user the host asked about (-as)
	NameUID *int   `json:"name_uid,omitempty"` // that user's uid in the box's own passwd database; absent if it has none
	TempDir string `json:"temp_dir"`           // the box's temporary directory, resolved once, absolute
}
