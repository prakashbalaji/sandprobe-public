//go:build linux

package probe

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
)

// ReceiverAttempt is the generic MEAS-2 single owned-endpoint attempt. No model
// output, management identity or positive-control nonce is used here.
func ReceiverAttempt(in obs.ReceiverProbeInput) (obs.ReceiverProbeDoc, error) {
	var out obs.ReceiverProbeDoc
	if err := obs.ValidateReceiverProbeInput(in); err != nil {
		return out, err
	}
	e := &env{start: time.Now(), in: Input{CanaryDomain: in.Domain, CanaryPin: in.Pin}}
	use := func(c net.Conn) error {
		if _, err := io.WriteString(c, in.Nonce+"\n"); err != nil {
			return exchangeAt("send_marker", err)
		}
		return exchangeAt("read_reply", canary.ReadMarkerAck(c, in.Nonce))
	}
	if in.Port == 443 {
		use = e.tlsUse(in.Nonce)
	}
	out = obs.ReceiverProbeDoc{Schema: obs.ReceiverAttemptSchema, RunID: in.RunID, BoxID: in.BoxID, Nonce: in.Nonce, UID: os.Geteuid(), GID: os.Getegid(), Attempt: e.tcpTry(net.JoinHostPort(in.Address, fmt.Sprint(in.Port)), use)}
	return out, nil
}
