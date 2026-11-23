// canary-health verifies the owned receiver's SSM-bound TLS public-key pin.
// RUN-21: one literal-address connection, one deadline, no application request.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

var pinMismatch = errors.New("receiver pin mismatch")

func verify(ctx context.Context, address, name, pin string) string {
	addr, err := netip.ParseAddrPort(address)
	want, decodeErr := hex.DecodeString(pin)
	validName := strings.HasPrefix(name, "health.canary.") && len(name) <= 253
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			validName = false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				validName = false
			}
		}
	}
	if err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() || addr.Addr().Zone() != "" || !validName || decodeErr != nil || len(want) != sha256.Size || strings.ToLower(pin) != pin {
		return "invalid"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return "unproven"
	}
	defer raw.Close() // No additional TLS-close write budget.
	c := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name,
		// The owned receiver uses a self-signed certificate. SSM supplies its exact
		// SPKI pin; this replaces WebPKI, as in the prior openssl deployment check.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return pinMismatch
			}
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return pinMismatch
			}
			return nil
		},
	})
	if err = c.HandshakeContext(ctx); err != nil {
		if errors.Is(err, pinMismatch) {
			return "pin_mismatch"
		}
		return "unproven"
	}
	return "verified"
}

func run(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("canary-health", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	address := fs.String("address", "", "")
	name := fs.String("name", "", "")
	pin := fs.String("pin", "", "")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(out, "invalid")
		return 2
	}
	result := verify(context.Background(), *address, *name, *pin)
	fmt.Fprintln(out, result)
	if result == "verified" {
		return 0
	}
	return 1
}
func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
