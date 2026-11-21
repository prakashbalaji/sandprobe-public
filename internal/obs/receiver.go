package obs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"time"
)

const ReceiverBindingSchema = "sandprobe.receiver-binding/1"
const ReceiverAttemptSchema = "sandprobe.receiver-attempt/1"
const ReceiverEvidenceSchema = "sandprobe.receiver-calibration/1"

// MEAS-1: this declaration stays on the host. Only Nonces[1] enters the guest.
type ReceiverBinding struct {
	Schema       string   `json:"schema"`
	ManagedRunID string   `json:"managed_run_id"`
	BoxID        string   `json:"box_id"`
	RunID        string   `json:"run_id"`
	ReceiverID   string   `json:"receiver_id"`
	Address      string   `json:"address"`
	Domain       string   `json:"domain"`
	Port         int      `json:"port"`
	Pin          string   `json:"pin"`
	Scope        string   `json:"scope"`
	Nonces       []string `json:"nonces"`
}
type ReceiverProbeInput struct {
	Schema  string `json:"schema"`
	RunID   string `json:"run_id"`
	BoxID   string `json:"box_id"`
	Nonce   string `json:"nonce"`
	Address string `json:"address"`
	Domain  string `json:"domain"`
	Port    int    `json:"port"`
	Pin     string `json:"pin"`
}
type ReceiverProbeDoc struct {
	Schema  string  `json:"schema"`
	RunID   string  `json:"run_id"`
	BoxID   string  `json:"box_id"`
	Nonce   string  `json:"nonce"`
	UID     int     `json:"uid"`
	GID     int     `json:"gid"`
	Attempt Attempt `json:"attempt"`
}
type ReceiverCollection struct {
	OK          bool      `json:"ok"`
	ReceiverID  string    `json:"receiver_id"`
	RunID       string    `json:"run_id"`
	Pin         string    `json:"pin"`
	Received    []string  `json:"received"`
	Overloaded  bool      `json:"overloaded"`
	CollectedAt time.Time `json:"collected_at"`
}
type WorkloadStopProof struct {
	BoxID     string    `json:"box_id"`
	Confirmed bool      `json:"confirmed"`
	Method    string    `json:"method"`
	At        time.Time `json:"at"`
}
type ReceiverCalibration struct {
	Schema        string              `json:"schema"`
	BindingSHA256 string              `json:"binding_sha256"`
	Before        ReceiverCollection  `json:"before"`
	BeforeSent    bool                `json:"before_sent"`
	AttemptAt     time.Time           `json:"attempt_at"`
	Attempt       *ReceiverProbeDoc   `json:"attempt,omitempty"`
	During        *ReceiverCollection `json:"during,omitempty"`
	Stop          WorkloadStopProof   `json:"stop"`
	After         ReceiverCollection  `json:"after"`
	AfterSent     bool                `json:"after_sent"`
}

var receiverNonce = regexp.MustCompile(`^[a-f0-9]{48}$`)
var receiverRun = regexp.MustCompile(`^[a-z][a-z0-9]{8,63}$`)
var receiverDomain = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$`)

func ValidReceiverTarget(address, domain, pin string, port int) bool {
	ip, err := netip.ParseAddr(address)
	return err == nil && ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() &&
		receiverDomain.MatchString(domain) && workloadHex.MatchString(pin) && port > 0 && port <= 65535
}
func ValidateReceiverBinding(b ReceiverBinding) error {
	if b.Schema != ReceiverBindingSchema || !workloadRun.MatchString(b.ManagedRunID) || b.BoxID == "" || len(b.BoxID) > 128 ||
		!receiverRun.MatchString(b.RunID) || b.ReceiverID == "" || len(b.ReceiverID) > 256 ||
		!ValidReceiverTarget(b.Address, b.Domain, b.Pin, b.Port) || len(b.Nonces) != 3 {
		return errors.New("invalid receiver binding")
	}
	ip, _ := netip.ParseAddr(b.Address)
	private := ip.IsPrivate() || ip.IsLoopback()
	if (b.Scope != "owned_public_endpoint" && b.Scope != "owned_private_endpoint") || private != (b.Scope == "owned_private_endpoint") {
		return errors.New("invalid receiver scope")
	}
	seen := map[string]bool{}
	for _, n := range b.Nonces {
		if !receiverNonce.MatchString(n) || seen[n] {
			return errors.New("invalid receiver nonces")
		}
		seen[n] = true
	}
	return nil
}
func ReceiverBindingHash(b ReceiverBinding) (string, error) {
	if err := ValidateReceiverBinding(b); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func ValidateReceiverProbeInput(in ReceiverProbeInput) error {
	if in.Schema != ReceiverAttemptSchema || !receiverRun.MatchString(in.RunID) || in.BoxID == "" || len(in.BoxID) > 128 ||
		!receiverNonce.MatchString(in.Nonce) || !ValidReceiverTarget(in.Address, in.Domain, in.Pin, in.Port) {
		return errors.New("invalid receiver attempt")
	}
	return nil
}
