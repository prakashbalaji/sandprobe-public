package grade

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// PER-5 is graded by the host alone (TWN-3): from the planned marks, the provider's reset evidence, and the probe's
// mark and recheck documents. A marker that survived a proven reset is the finding; not_found needs a proven reset and
// every planned root marked, its identity kept, and its marker definitively gone; anything short of that is unknown.

// per5Docs parses and ties the mark and recheck documents to the plan. A document that doesn't fit invalidates the
// run (GRD-5); a step that didn't run leaves it nil, and PER-5 unknown.
func per5Docs(m obs.Manifest, c *obs.CanaryEvidence) (*obs.MarkDoc, *obs.RecheckDoc, error) {
	if c == nil || c.Reset == nil {
		return nil, nil, nil
	}
	r := c.Reset
	var md *obs.MarkDoc
	var rd *obs.RecheckDoc
	if r.Mark != nil {
		d, err := obs.ParseMark(r.Mark)
		switch {
		case err != nil:
			return nil, nil, fmt.Errorf("the mark document: %w", err)
		case d.RunID != m.RunID || d.Nonce != m.Nonce || d.BoxID != m.BoxID:
			return nil, nil, errors.New("the mark document isn't this run's, on this box")
		case !samePlaces(m.Marks, len(d.Marks), func(i int) (string, string) { return d.Marks[i].Root, d.Marks[i].Path }):
			return nil, nil, errors.New("the mark document's markers aren't the planned ones")
		}
		for _, p := range d.Marks {
			if !PlacedSound(p, m.RunID) {
				return nil, nil, fmt.Errorf("the mark document's outcome for %s doesn't hold together", p.Root)
			}
		}
		md = d
	}
	if r.Recheck != nil {
		d, err := obs.ParseRecheck(r.Recheck)
		switch {
		case err != nil:
			return nil, nil, fmt.Errorf("the recheck document: %w", err)
		case d.RunID != m.RunID || d.Nonce != m.Nonce || d.BoxID != r.BoxAfter:
			return nil, nil, errors.New("the recheck document isn't this run's, on the box after the reset")
		case !samePlaces(m.Marks, len(d.Marks), func(i int) (string, string) { return d.Marks[i].Root, m.Marks[i].Path }):
			return nil, nil, errors.New("the recheck document's markers aren't the planned ones")
		}
		startup := StartupTargets()
		if len(d.Startup) != len(startup) {
			return nil, nil, fmt.Errorf("the recheck observed %d startup targets, not the %d asked for", len(d.Startup), len(startup))
		}
		for i, s := range d.Startup { // every target asked for, once, in order: a gap can't hide High
			if s.Name != startup[i] {
				return nil, nil, fmt.Errorf("the recheck observed %q where %q was asked for", s.Name, startup[i])
			}
		}
		rd = d
	}
	return md, rd, nil
}

// samePlaces: the document lists exactly the planned markers, in the plan's order.
func samePlaces(plan []obs.PlannedMark, n int, at func(int) (root, path string)) bool {
	if n != len(plan) {
		return false
	}
	for i, pm := range plan {
		if root, path := at(i); root != pm.Root || path != pm.Path {
			return false
		}
	}
	return true
}

// PlacedSound: a mark outcome holds together. Placed means a marker of the run id's length, with an inode and no
// reason given; not placed means a reason, and no inode or size.
func PlacedSound(p obs.Placed, runID string) bool {
	if p.Placed {
		size := int64(len(runID))
		if p.Path == filepath.Join(p.Root, obs.EmptyMarkerPrefix+runID) {
			size = 0
		}
		return p.Ino != 0 && p.Size == size && p.Why == ""
	}
	return p.Ino == 0 && p.Size == 0 && p.Why != ""
}

// StartupTargets are PER-1 to PER-4's planned targets, in catalog order: the paths that make a surviving root High
// (PER-5). The host asks the recheck for exactly these.
func StartupTargets() []string {
	var ts []string
	for _, id := range []string{"PER-1", "PER-2", "PER-3", "PER-4"} {
		ck, _ := catalog.Get(id)
		ts = append(ts, ck.Targets...)
	}
	return ts
}

// resetProven is TWN-3's reset half, from the provider's evidence and the boot IDs the two documents report.
func resetProven(m obs.Manifest, r *obs.ResetEvidence, md *obs.MarkDoc, rd *obs.RecheckDoc) string {
	switch {
	case r.Model != m.Reset:
		return "the reset isn't the model the plan named"
	case r.OperationID == "" || !r.Done:
		return "the provider didn't report the reset operation done"
	case r.BoxBefore != m.BoxID:
		return "the reset wasn't of the box the run probed"
	}
	switch m.Reset { // the plan's model governs; the provider's must agree with it, above
	case "recreate":
		if r.BoxAfter == "" || r.BoxAfter == r.BoxBefore {
			return "a recreate needs a new box ID"
		}
	case "restore":
		switch {
		case r.BoxAfter != r.BoxBefore:
			return "a restore in place keeps the box's ID"
		case r.Checkpoint == "":
			return "the restore doesn't name the checkpoint it restored"
		case !(md.BootID != "" && rd.BootID != "" && md.BootID != rd.BootID) && !(r.RestoreAfter != "" && r.RestoreAfter != r.RestoreBefore):
			return "neither the boot ID nor the restore ID changed"
		}
	default:
		return "no reset model"
	}
	return ""
}

// rootKept is TWN-3's root half: the provider's identity for the root is the same before and after.
func rootKept(pm obs.PlannedMark, model string, r *obs.ResetEvidence) bool {
	switch model {
	case "recreate":
		v, ok := r.Volumes[pm.Root]
		return ok && pm.Volume != nil && pm.Volume.ID != "" && v[0] == *pm.Volume && v[1] == *pm.Volume
	case "restore":
		id, ok := r.RootIdentity[pm.Root]
		return ok && id[0] != "" && id[0] == id[1]
	}
	return false
}

// notKept says why a root's provider identity can't show it is the same storage after the reset (TWN-3): a restore
// whose provider gives the root no identity (Sprites gives none of its roots one), or an identity or volume that
// differs.
func notKept(pm obs.PlannedMark, model string, r *obs.ResetEvidence) string {
	if model == "restore" && r.RootIdentity[pm.Root][0] == "" {
		return pm.Root + " has no identity from the provider, so its marker's absence can't show the reset cleared it"
	}
	return pm.Root + " isn't the same storage, by the provider's identity"
}

// boxText bounds a reason the box wrote before the report repeats it (TWN-3).
func boxText(s string) string {
	if len(s) > 256 {
		return s[:253] + "..."
	}
	return s
}

func per5(m obs.Manifest, c *obs.CanaryEvidence, md *obs.MarkDoc, rd *obs.RecheckDoc) Outcome {
	switch {
	case c == nil || c.Reset == nil:
		return unknown("the reset didn't run, so nothing about persistence is proven")
	case md == nil:
		return unknown("no marks were placed")
	}
	var placementGaps []string
	for _, p := range md.Marks {
		if !p.Placed {
			placementGaps = append(placementGaps, p.Root+" took no marker: "+boxText(p.Why))
		}
	}
	if len(placementGaps) == len(m.Marks) {
		return unknown("not every root was marked and rechecked: " + strings.Join(placementGaps, "; "))
	}
	if rd == nil {
		why := "there was no recheck after the reset"
		if stage := obs.ResetFailureStage(c.Reset.FailureStage); stage != "" {
			why += "; incomplete host stage: " + stage
		}
		return unknown(why)
	}
	r := c.Reset
	notProven := resetProven(m, r, md, rd)
	var survived, gaps []string
	for i, pm := range m.Marks {
		placed, state, kept := md.Marks[i].Placed, rd.Marks[i].State, rootKept(pm, m.Reset, r)
		id, named := r.RootIdentity[pm.Root]
		changed := named && id[0] != "" && id[1] != "" && id[0] != id[1]
		switch {
		case !placed:
			gaps = append(gaps, pm.Root+" took no marker: "+boxText(md.Marks[i].Why))
		case state == "survived" && m.Reset == "restore" && !changed:
			// TWN-3: state written after the checkpoint was there after the proven restore, whatever its root's
			// identity (which a clone could share or not); only an absence needs that identity
			survived = append(survived, pm.Root)
		case !kept:
			gaps = append(gaps, notKept(pm, m.Reset, r))
		case state == "survived":
			survived = append(survived, pm.Root)
		case state != "absent":
			gaps = append(gaps, pm.Root+": "+boxText(rd.Marks[i].Why))
		}
	}
	switch {
	case len(survived) > 0 && notProven == "":
		v, why := "survived", ""
		for _, s := range rd.Startup {
			for _, root := range survived {
				if s.State == "found" && (s.Path == root || strings.HasPrefix(s.Path, root+string(filepath.Separator))) {
					v, why = "survived_startup", "; "+s.Name+" lies in it and the agent can replace it"
				}
			}
		}
		claim := fmt.Sprintf("a marker survived the provider's %s in %s, the reset proven by the provider's evidence (TWN-3)",
			m.Reset, strings.Join(survived, ", "))
		if m.Reset == "restore" {
			claim = fmt.Sprintf("run data written after the checkpoint was present at %s after the provider's proven restore "+
				"(TWN-3); which filesystem held it is unproven", strings.Join(survived, ", "))
		}
		for _, mark := range m.Marks {
			if slices.Contains(survived, mark.Root) && mark.Path == filepath.Join(mark.Root, obs.EmptyMarkerPrefix+m.RunID) {
				claim += "; retained empty-file namespace metadata was verified without reading file contents (EVD-18)"
				break
			}
			if slices.Contains(survived, mark.Root) && mark.Path == filepath.Join(mark.Root, obs.LinkMarkerPrefix+m.RunID) {
				claim += "; retained symbolic-link metadata was verified without following its target (EVD-15)"
				break
			}
		}
		return Outcome{Result: obs.Finding, Variant: v, Evidence: claim + why}
	case len(survived) > 0:
		return unknown("a marker survived, but the reset isn't proven: " + notProven)
	case notProven != "":
		return unknown("the reset isn't proven: " + notProven)
	case len(gaps) > 0:
		return unknown("not every root was marked and rechecked: " + strings.Join(gaps, "; "))
	}
	return Outcome{Result: obs.NotFound, Reason: "after a proven reset, every planned root was rechecked and its marker is gone; " +
		"something other than the reset may have removed it, so this proves nothing (KND-2)"}
}

// marksSound: PER-5 selected needs a reset model and planned marks in the exact file or EVD-15 link namespace, one per
// root and per directory, every one on a volume Sandprobe created when the reset recreates the box; skipped, none.
func marksSound(m obs.Manifest, selected bool) error {
	if !selected {
		if len(m.Marks) > 0 || m.Reset != "" {
			return errors.New("PER-5 isn't selected, yet markers are planned")
		}
		return nil
	}
	if m.Reset != "restore" && m.Reset != "recreate" {
		return errors.New("PER-5 needs the reset model it will be graded by")
	}
	if len(m.Marks) == 0 {
		return errors.New("PER-5 is selected with no marker planned: with none, it's skipped (GRD-3)")
	}
	type dir struct{ dev, ino uint64 }
	roots, dirs := map[string]bool{}, map[dir]bool{}
	for _, pm := range m.Marks {
		switch {
		case !filepath.IsAbs(pm.Root) || (pm.Path != filepath.Join(pm.Root, obs.MarkerPrefix+m.RunID) && pm.Path != filepath.Join(pm.Root, obs.LinkMarkerPrefix+m.RunID) && pm.Path != filepath.Join(pm.Root, obs.EmptyMarkerPrefix+m.RunID)):
			return fmt.Errorf("%q isn't this run's marker path in its root", pm.Path)
		case roots[pm.Root] || pm.Ino != 0 && dirs[dir{pm.Dev, pm.Ino}]: // no identity: missing from the survey, its mark refuses
			return fmt.Errorf("root %s is planned twice", pm.Root)
		case m.Reset == "recreate" && (pm.Volume == nil || pm.Volume.ID == "" || pm.Volume.MountPath != pm.Root):
			return fmt.Errorf("%s isn't a volume Sandprobe created, mounted at that root", pm.Root)
		case m.Reset == "restore" && pm.Volume != nil:
			return fmt.Errorf("%s: a restore in place marks the box's own storage, never a volume", pm.Root)
		}
		roots[pm.Root], dirs[dir{pm.Dev, pm.Ino}] = true, true
	}
	return nil
}
