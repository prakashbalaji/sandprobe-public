package analysis

import (
	"sandprobe/internal/obs"
	"sandprobe/internal/strictjson"
)

// LoadPrerequisites shares ANL-1's regular-file/symlink checks. EVD-22 refuses
// oversized, unknown-field, duplicate-key, partial and unsupported sidecars.
func LoadPrerequisites(path string) (*obs.MeasurementPrerequisites, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, ErrInput
	}
	var p obs.MeasurementPrerequisites
	if strictjson.Decode(raw, 16384, &p) != nil || !p.Valid() {
		return nil, ErrInput
	}
	return &p, nil
}
