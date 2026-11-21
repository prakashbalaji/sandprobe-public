package obs

import (
	"slices"
	"strings"
	"testing"
)

func receiverBindingFixture() ReceiverBinding {
	return ReceiverBinding{Schema: ReceiverBindingSchema, ManagedRunID: strings.Repeat("a", 16), BoxID: "original-box", RunID: "rreceiver123", ReceiverID: "original-receiver", Address: "192.0.2.1", Domain: "canary.test", Port: 443, Pin: strings.Repeat("b", 64), Scope: "owned_public_endpoint", Nonces: []string{strings.Repeat("1", 48), strings.Repeat("2", 48), strings.Repeat("3", 48)}}
}
func TestReceiverBindingRejectsAmbiguousTargetsAndNonces(t *testing.T) {
	for _, name := range []string{"nonce-count", "duplicate", "pin", "scope", "metadata-address", "port", "domain"} {
		t.Run(name, func(t *testing.T) {
			b := receiverBindingFixture()
			switch name {
			case "nonce-count":
				b.Nonces = append(b.Nonces, strings.Repeat("4", 48))
			case "duplicate":
				b.Nonces[2] = b.Nonces[0]
			case "pin":
				b.Pin = "bad"
			case "scope":
				b.Scope = "owned_private_endpoint"
			case "metadata-address":
				b.Address = "169.254.169.254"
			case "port":
				b.Port = 0
			case "domain":
				b.Domain = "https://untrusted.invalid/"
			}
			if ValidateReceiverBinding(b) == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	b := receiverBindingFixture()
	original, err := ReceiverBindingHash(b)
	if err != nil {
		t.Fatal(err)
	}
	b.Nonces = slices.Clone(b.Nonces)
	b.Nonces[1] = strings.Repeat("f", 48)
	if changed, err := ReceiverBindingHash(b); err != nil || original == changed {
		t.Fatal("changed nonce did not change binding")
	}
}
