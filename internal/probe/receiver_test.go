//go:build linux

package probe

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

// MEAS-2/3: run the actual guest path against an owned loopback fixture, as both
// root and nobody in test/probe.sh. An unrelated reply cannot complete exchange.
func TestReceiverAttemptOwnedMarker(t *testing.T) {
	for _, tc := range []struct{ name, reply, want string }{
		{"valid", "", "completed"},
		{"forbidden", "HTTP/1.1 403 Forbidden\r\n", "http_status_403"},
		{"success-shaped", "HTTP/1.1 200 synthetic-sensitive-text\r\n", "http_status_2xx"},
		{"redirect", "HTTP/1.1 302 synthetic-sensitive-text\r\n", "http_status_3xx"},
		{"client-error", "HTTP/1.1 400 synthetic-sensitive-text\r\n", "http_status_4xx"},
		{"server-error", "HTTP/1.1 502 synthetic-sensitive-text\r\n", "http_status_5xx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			_, p, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(p)
			nonce := strings.Repeat("b", 48)
			seen := make(chan string, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					seen <- ""
					return
				}
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				seen <- line
				reply := tc.reply
				if reply == "" {
					reply = "sandprobe:" + nonce + "\n"
				}
				io.WriteString(c, reply)
			}()
			in := obs.ReceiverProbeInput{Schema: obs.ReceiverAttemptSchema, RunID: "rreceiver123", BoxID: "owned-box", Nonce: nonce, Address: "127.0.0.1", Domain: "canary.test", Port: port, Pin: strings.Repeat("a", 64)}
			d, err := ReceiverAttempt(in)
			if err != nil {
				t.Fatal(err)
			}
			if d.UID != os.Geteuid() || d.GID != os.Getegid() || d.Nonce != nonce || d.Attempt.Outcome != "connected" || <-seen != nonce+"\n" {
				t.Fatal("guest identity or marker changed")
			}
			if d.Attempt.ExchangeResult != tc.want {
				t.Fatalf("exchange result %q, want %q", d.Attempt.ExchangeResult, tc.want)
			}
		})
	}
}

func TestReceiverAttemptRejectsMetadataTarget(t *testing.T) {
	_, err := ReceiverAttempt(obs.ReceiverProbeInput{Schema: obs.ReceiverAttemptSchema, RunID: "rreceiver123", BoxID: "owned-box", Nonce: strings.Repeat("b", 48), Address: "169.254.169.254", Domain: "canary.test", Port: 80, Pin: strings.Repeat("a", 64)})
	if err == nil {
		t.Fatal("excluded link-local target accepted")
	}
}
