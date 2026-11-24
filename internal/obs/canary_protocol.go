package obs

import (
	"errors"
	"sandprobe/internal/canary"
	"slices"
)

// EVD-10: only an explicit, known protocol may change the existing TCP/80 payload.
func ValidCanaryTCP80Protocol(value string) bool { return value == "" || value == canary.HTTPMarkerV1 }
func ValidateCanaryTCP80Protocol(m Manifest) error {
	if !ValidCanaryTCP80Protocol(m.CanaryTCP80Protocol) || (m.CanaryTCP80Protocol != "" && (m.NoCanary || !slices.Contains(m.Selected, "EGR-5.80"))) {
		return errors.New("invalid canary TCP/80 protocol declaration")
	}
	return nil
}
