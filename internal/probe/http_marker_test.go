//go:build linux

package probe

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHTTPMarkerExplicitSelectionAndNoFallback(t *testing.T) {
	for _, tc := range []struct {
		name, id, protocol string
		forbidden          bool
	}{
		{"legacy", "EGR-5.80", "", false}, {"http", "EGR-5.80", canary.HTTPMarkerV1, false}, {"http-error", "EGR-5.80", canary.HTTPMarkerV1, true}, {"other-port-legacy", "EGR-5.22", canary.HTTPMarkerV1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			twin, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer twin.Close()
			go func() {
				c, e := twin.Accept()
				if e == nil {
					c.Close()
				}
			}()
			first := make(chan string, 1)
			const nonce = "nonce-http-selection"
			go func() {
				c, e := ln.Accept()
				if e != nil {
					first <- ""
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				r := bufio.NewReader(io.LimitReader(c, 2048))
				line, _ := r.ReadString('\n')
				first <- line
				if strings.HasPrefix(line, "GET ") {
					for {
						h, e := r.ReadString('\n')
						if h == "\r\n" || e != nil {
							break
						}
					}
					if tc.forbidden {
						io.WriteString(c, "HTTP/1.1 403 fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					} else {
						body := "sandprobe:" + nonce + "\n"
						fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
					}
				} else {
					io.WriteString(c, "sandprobe:"+nonce+"\n")
				}
			}()
			_, p, _ := net.SplitHostPort(twin.Addr().String())
			port, _ := strconv.Atoi(p)
			e := &env{start: time.Now(), ownPort: port, in: Input{CanaryTCP80Protocol: tc.protocol, CanaryDomain: "canary.test", CanaryPin: strings.Repeat("a", 64), Endpoints: map[string]string{tc.id: ln.Addr().String()}, CheckNonces: map[string]string{tc.id: nonce}}}
			ck, _ := catalog.Get(tc.id)
			o := egrDirect(e, ck)
			if o.Result != obs.Attempted || len(o.Attempts) != 1 || o.Attempts[0].Outcome != "connected" {
				t.Fatal("payload exchange became a verdict or retry", o)
			}
			expected := "completed"
			if tc.forbidden {
				expected = "http_status_403"
			}
			if o.Attempts[0].ExchangeResult != expected {
				t.Fatal("wrong bounded diagnostic", o.Attempts[0])
			}
			line := <-first
			wantHTTP := tc.id == "EGR-5.80" && tc.protocol != ""
			if strings.HasPrefix(line, "GET ") != wantHTTP {
				t.Fatal("HTTP not explicitly scoped to TCP/80")
			}
			if !wantHTTP && line != nonce+"\n" {
				t.Fatal("legacy payload changed")
			}
		})
	}
}
func TestUnknownHTTPMarkerProtocolSendsNoAttempt(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	e := &env{start: time.Now(), in: Input{CanaryTCP80Protocol: "untrusted", CanaryDomain: "canary.test", CanaryPin: "pin", Endpoints: map[string]string{"EGR-5.80": ln.Addr().String()}, CheckNonces: map[string]string{"EGR-5.80": "nonce"}}}
	ck, _ := catalog.Get("EGR-5.80")
	o := egrDirect(e, ck)
	if o.Result != obs.Unknown || len(o.Attempts) != 0 {
		t.Fatal("unknown protocol generated traffic", o)
	}
}
