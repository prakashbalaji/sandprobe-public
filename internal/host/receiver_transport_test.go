package host

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"sandprobe/internal/canary"
)

func TestReceiverTransportsShareOwnedMarkerProtocol(t *testing.T) {
	for _, mode := range []string{"docker-tls", "ssm-plain"} {
		t.Run(mode, func(t *testing.T) {
			server, err := canary.New("canary.test")
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			_, p, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(p)
			if mode == "docker-tls" {
				port = 443
				go server.ServeTLS(ln, port)
			} else {
				go server.ServeTCP(ln, port)
			}
			nonce := strings.Repeat("a", 48)
			run := "rtransport123"
			a := server.Handle(canary.Request{Op: "arm", Run: run, TTL: 60, Wants: []canary.Want{{Nonce: nonce, Proto: "tcp", Port: port}}})
			if !a.OK {
				t.Fatal("owned fixture arm failed")
			}
			key, err := canary.KeyOf(a)
			if err != nil {
				t.Fatal(err)
			}
			var receiver ReceiverCanary
			if mode == "docker-tls" {
				receiver = &DockerCanary{Container: "owned-docker-fixture", Dom: "canary.test", published: map[int]string{443: ln.Addr().String()}}
			} else {
				receiver = &SSMCanary{Instance: "owned-ssm-fixture", Addr: "127.0.0.1", Dom: "canary.test"}
			}
			if err = receiver.SendMarker(context.Background(), port, nonce, key); err != nil {
				t.Fatal(err)
			}
			q := server.Handle(canary.Request{Op: "query", Run: run})
			if !q.OK || len(q.Counts) != 1 || q.Counts[0].Count != 1 {
				t.Fatal("host marker did not reach owned receiver")
			}
		})
	}
}
