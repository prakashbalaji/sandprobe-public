package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/canary"
)

func receiver(t *testing.T, max uint16) (string, string, <-chan string) {
	t.Helper()
	c, err := canary.New("fixture.test")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	observed := make(chan string, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(2 * time.Second))
		cfg := &tls.Config{Certificates: []tls.Certificate{c.Cert}, MinVersion: tls.VersionTLS10, MaxVersion: max}
		peer := tls.Server(raw, cfg)
		if peer.Handshake() != nil {
			observed <- "handshake_failed"
			return
		}
		data := make([]byte, 1)
		n, _ := peer.Read(data)
		if n != 0 {
			observed <- "application_data"
			return
		}
		observed <- peer.ConnectionState().ServerName
	}()
	return ln.Addr().String(), c.Pin, observed
}

func TestPinnedReceiverHandshakeWithoutApplicationRequest(t *testing.T) {
	addr, pin, seen := receiver(t, 0)
	if got := verify(context.Background(), addr, "health.canary.fixture.test", pin); got != "verified" {
		t.Fatal(got)
	}
	select {
	case got := <-seen:
		if got != "health.canary.fixture.test" {
			t.Fatal(got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not close")
	}
}
func TestPinAndTLSFailuresAreNotVerified(t *testing.T) {
	addr, _, _ := receiver(t, 0)
	if got := verify(context.Background(), addr, "health.canary.fixture.test", strings.Repeat("0", 64)); got != "pin_mismatch" {
		t.Fatal(got)
	}
	addr, pin, _ := receiver(t, tls.VersionTLS11)
	if got := verify(context.Background(), addr, "health.canary.fixture.test", pin); got != "unproven" {
		t.Fatal(got)
	}
}
func TestHandshakeHasOneSharedDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	release := make(chan struct{})
	defer close(release)
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		accepted <- struct{}{}
		<-release
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if got := verify(ctx, ln.Addr().String(), "health.canary.fixture.test", strings.Repeat("0", 64)); got != "unproven" {
		t.Fatal(got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("deadline exceeded")
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
}
func TestInvalidMetadataAndCLIOutputAreBounded(t *testing.T) {
	for _, tc := range []struct{ address, name, pin string }{
		{"localhost:443", "health.canary.fixture.test", strings.Repeat("0", 64)},
		{"127.0.0.1:0", "health.canary.fixture.test", strings.Repeat("0", 64)},
		{"127.0.0.1:443", "health.canary.fixture.test/secret", strings.Repeat("0", 64)},
		{"127.0.0.1:443", "health.canary.fixture.test", "synthetic-private-diagnostic"},
	} {
		if got := verify(context.Background(), tc.address, tc.name, tc.pin); got != "invalid" {
			t.Fatal(got)
		}
	}
	var out bytes.Buffer
	if run([]string{"-unrecognized", "synthetic-private-diagnostic"}, &out) == 0 || out.String() != "invalid\n" {
		t.Fatal("untrusted CLI output")
	}
	out.Reset()
	if run(nil, &out) == 0 || out.String() != "invalid\n" {
		t.Fatal("missing arguments accepted")
	}
}
