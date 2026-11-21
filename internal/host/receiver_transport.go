package host

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
)

// MEAS-1: the protocol is shared; adapters select only their own receiver route.
func sendReceiverMarker(ctx context.Context, address string, port int, domain, nonce string, key canary.Key) error {
	ip, p, err := net.SplitHostPort(address)
	n, ne := strconv.Atoi(p)
	decoded, de := hex.DecodeString(nonce)
	if err != nil || ne != nil || de != nil || len(decoded) != 24 || key.Pub == nil || !obs.ValidReceiverTarget(ip, domain, key.Pin, n) {
		return errors.New("invalid receiver control target")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var dial net.Dialer
	c, err := dial.DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("receiver control unavailable")
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	var stream io.ReadWriter = c
	if port == 443 {
		tc := tls.Client(c, &tls.Config{ServerName: nonce + ".canary." + domain, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || canary.PinOf(cs.PeerCertificates[0]) != key.Pin {
				return errors.New("receiver pin mismatch")
			}
			return nil
		}})
		if tc.HandshakeContext(ctx) != nil {
			return errors.New("receiver control TLS unavailable")
		}
		stream = tc
	} else if _, err = io.WriteString(c, nonce+"\n"); err != nil {
		return errors.New("receiver control unavailable")
	}
	if canary.ReadMarkerAck(stream, nonce) != nil {
		return errors.New("receiver acknowledgement unavailable")
	}
	return nil
}

func (c *SSMCanary) ReceiverID() string { return c.Instance }
func (c *SSMCanary) SendMarker(ctx context.Context, port int, nonce string, key canary.Key) error {
	return sendReceiverMarker(ctx, net.JoinHostPort(c.Addr, fmt.Sprint(port)), port, c.Dom, nonce, key)
}
func (c *DockerCanary) ReceiverID() string { return c.Container }
func (c *DockerCanary) SendMarker(ctx context.Context, port int, nonce string, key canary.Key) error {
	address, ok := c.published[port]
	if !ok {
		return errors.New("receiver host route unavailable")
	}
	return sendReceiverMarker(ctx, address, port, c.Dom, nonce, key)
}
