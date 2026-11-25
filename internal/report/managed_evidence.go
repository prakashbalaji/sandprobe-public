package report

import "sandprobe/internal/obs"

// ManagedEvidenceSchema versions the private raw-evidence envelope, independently of OUT-1 (EVD-20).
const ManagedEvidenceSchema = "sandprobe.managed-evidence/2"

type ManagedEvidence struct {
	Schema       string             `json:"schema"`
	Report       Doc                `json:"report"`
	Observations string             `json:"observations"`
	Evidence     obs.CanaryEvidence `json:"evidence"`
	Input        obs.Input          `json:"input"`
	HTML         string             `json:"html,omitempty"`
}

func NewManagedEvidence(d Doc, observations string, evidence obs.CanaryEvidence, input obs.Input, html string) ManagedEvidence {
	return ManagedEvidence{ManagedEvidenceSchema, d, observations, evidence, input, html}
}
