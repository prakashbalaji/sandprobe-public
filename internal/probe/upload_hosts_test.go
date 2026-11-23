//go:build linux

package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sandprobe/internal/obs"
)

func TestUploadHostsRejectUnapprovedAndNonpublic(t *testing.T) {
	for _, hosts := range [][]string{nil, {"169.254.169.254"}, {"github.com", "github.com"}, {"https://github.com"}} {
		o := uploadExposure(hosts, func(context.Context, string, string) ([]netip.Addr, error) {
			t.Fatal("unapproved destination reached DNS")
			return nil, nil
		}, nil)
		if o.Result != obs.Unknown {
			t.Fatal("invalid request became evidence")
		}
	}
	for _, address := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "0.0.0.0", "198.18.0.1", "192.0.2.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:0a00:0001::1", "2001::1", "2001:db8::1"} {
		for _, mixed := range []bool{false, true} {
			ips := []netip.Addr{netip.MustParseAddr(address)}
			if mixed {
				ips = append([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, ips...)
			}
			o := uploadExposure([]string{"github.com"}, func(context.Context, string, string) ([]netip.Addr, error) { return ips, nil }, func(context.Context, string, netip.Addr) error {
				t.Fatal("non-public DNS answer reached a dial")
				return nil
			})
			if o.Result != obs.Unknown {
				t.Fatal("non-public answer became a finding")
			}
		}
	}
}

func TestUploadHostsBoundedAndPartialEvidence(t *testing.T) {
	var saved context.Context
	lookups, dials := 0, 0
	lookup := func(ctx context.Context, network, name string) ([]netip.Addr, error) {
		lookups++
		end, ok := ctx.Deadline()
		if !ok || time.Until(end) > attemptTimeout || network != "ip" {
			t.Fatal("missing shared DNS/connect/TLS budget")
		}
		saved = ctx
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	handshake := func(ctx context.Context, name string, ip netip.Addr) error {
		dials++
		if ctx != saved || ip != netip.MustParseAddr("1.1.1.1") {
			t.Fatal("dial did not use the resolved address and budget")
		}
		if name == "github.com" {
			return errors.New("credential-shaped fixture diagnostic")
		}
		return nil
	}
	o := uploadExposure([]string{"github.com", "pypi.org"}, lookup, handshake)
	if lookups != 2 || dials != 2 || saved.Err() != context.Canceled || o.Result != obs.Finding || o.Variant != "handshake" || !strings.Contains(o.Evidence, "pypi.org; 1 approved destinations unproven") || strings.Contains(o.Evidence, "credential") || strings.Contains(o.Evidence, "github.com") {
		t.Fatalf("partial evidence: %+v", o)
	}
	for _, ips := range [][]netip.Addr{nil, make([]netip.Addr, 17)} {
		o := uploadExposure([]string{"github.com"}, func(context.Context, string, string) ([]netip.Addr, error) { return ips, nil }, func(context.Context, string, netip.Addr) error { t.Fatal("invalid answer dialed"); return nil })
		if o.Result != obs.Unknown {
			t.Fatal("failed resolution became a negative proof")
		}
	}
	o = uploadExposure([]string{"github.com"}, lookup, handshake)
	if o.Result != obs.Unknown || strings.Contains(o.Reason, "credential") {
		t.Fatal("transport failure became a pass or leaked a diagnostic")
	}
}

func TestUploadHandshakeVerifiesCertificateWithoutHTTP(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer s.Close()
	cert := s.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
	defer cancel()
	if err := uploadHandshake(ctx, s.Listener.Addr().String(), cert.DNSNames[0], roots); err != nil {
		t.Fatal(err)
	}
	if uploadHandshake(ctx, s.Listener.Addr().String(), "wrong.example", roots) == nil || uploadHandshake(ctx, s.Listener.Addr().String(), cert.DNSNames[0], nil) == nil {
		t.Fatal("untrusted certificate or wrong name was accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("TLS measurement sent an HTTP request")
	}
}

func TestUploadHandshakeCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- uploadHandshake(ctx, listener.Addr().String(), "github.com", nil) }()
	c, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel() // The owned server deliberately sends no TLS response.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handshake became a finding")
		}
	case <-time.After(time.Second):
		t.Fatal("TLS handshake ignored its cancellation budget")
	}
}
