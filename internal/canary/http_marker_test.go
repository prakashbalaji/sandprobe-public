package canary

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func httpFixture(t *testing.T, port int) (*Canary, string) {
	t.Helper()
	c, _, _, _ := start(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go c.ServeTCP(ln, port)
	return c, ln.Addr().String()
}
func httpRoundTrip(t *testing.T, addr, request string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
	return b
}
func markerRequest(t *testing.T, nonce string) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteHTTPMarkerV1(&b, "sandprobe.test", nonce); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
func TestHTTPMarkerReceiptsAndLegacyCompatibility(t *testing.T) {
	c, addr := httpFixture(t, 80)
	const nonce = "http-marker"
	arm(t, c, "http-run", Want{nonce, "tcp", 80})
	response := httpRoundTrip(t, addr, markerRequest(t, nonce))
	if err := ReadHTTPMarkerAckV1(bytes.NewReader(response), nonce); err != nil {
		t.Fatal(err)
	}
	if n := count(query(t, c, "http-run"), nonce); n.Count != 1 || n.Elsewhere != 0 {
		t.Fatalf("missing independent HTTP receipt: %+v", n)
	}
	forwarded := strings.Replace(markerRequest(t, nonce), "Connection: close", "Connection: close\r\nVia: owned-test\r\nX-Forwarded-For: 203.0.113.7", 1)
	response = httpRoundTrip(t, addr, forwarded)
	if err := ReadHTTPMarkerAckV1(bytes.NewReader(response), nonce); err != nil {
		t.Fatal(err)
	}
	if n := count(query(t, c, "http-run"), nonce); n.Count != 2 || !strings.HasPrefix(n.FirstFrom, "127.0.0.1:") {
		t.Fatal("forwarding metadata changed receipt attribution", n)
	}
	// Completion of an unarmed exchange cannot invent an independent receipt.
	response = httpRoundTrip(t, addr, markerRequest(t, "unarmed-marker"))
	if err := ReadHTTPMarkerAckV1(bytes.NewReader(response), "unarmed-marker"); err != nil {
		t.Fatal(err)
	}
	if n := count(query(t, c, "http-run"), "unarmed-marker"); n.Count != 0 {
		t.Fatal("unarmed completion became proof")
	}
	// Existing raw nonce and signed health exchanges remain available on the same port.
	if got := string(httpRoundTrip(t, addr, nonce+"\n")); got != "sandprobe:"+nonce+"\n" {
		t.Fatal("legacy nonce changed")
	}
	if got := string(httpRoundTrip(t, addr, "health\n")); got != "sandprobe:health\n" {
		t.Fatal("legacy health changed")
	}
	if got := string(httpRoundTrip(t, addr, "health "+strings.Repeat("a", 32)+"\n")); !strings.HasPrefix(got, "sandprobe:health:") {
		t.Fatal("signed health changed")
	}
	// A short raw nonce must not wait for an HTTP prefix.
	if got := string(httpRoundTrip(t, addr, "n\n")); got != "sandprobe:n\n" {
		t.Fatal("short legacy nonce changed")
	}
}
func TestHTTPMarkerRejectsMalformedAndWrongScope(t *testing.T) {
	c, addr := httpFixture(t, 80)
	const nonce = "rejected-marker"
	arm(t, c, "reject-run", Want{nonce, "tcp", 80})
	valid := markerRequest(t, nonce)
	for _, request := range []string{
		strings.Replace(valid, "GET ", "POST ", 1),
		strings.Replace(valid, "HTTP/1.1", "HTTP/1.0", 1),
		strings.Replace(valid, nonce+".canary.sandprobe.test", "other.example", 1),
		strings.Replace(valid, httpMarkerPath+nonce, httpMarkerPath+nonce+"?query=secret", 1),
		strings.Replace(valid, httpMarkerPath+nonce, "http://other.example"+httpMarkerPath+nonce, 1),
		strings.Replace(valid, "Connection: close", "Connection: keep-alive", 1),
		strings.Replace(valid, "Connection: close", "Connection: close\r\nAuthorization: secret", 1),
		strings.Replace(valid, "Connection: close", "Connection: close\r\nContent-Length: 1", 1) + "x",
		strings.Replace(valid, "Connection: close", "Connection: close\r\nTransfer-Encoding: chunked", 1) + "0\r\n\r\n",
		strings.Replace(valid, "Connection: close", "Connection: close\r\nX-Long: "+strings.Repeat("x", 4096), 1),
	} {
		if response := httpRoundTrip(t, addr, request); len(response) != 0 {
			t.Fatal("malformed request got an acknowledgement")
		}
	}
	if n := count(query(t, c, "reject-run"), nonce); n.Count != 0 || n.Elsewhere != 0 {
		t.Fatal("malformed request recorded a nonce", n)
	}
	other, otherAddr := httpFixture(t, 22)
	arm(t, other, "port-run", Want{nonce, "tcp", 22})
	if response := httpRoundTrip(t, otherAddr, valid); len(response) != 0 {
		t.Fatal("HTTP enabled on another port")
	}
	if n := count(query(t, other, "port-run"), nonce); n.Count != 0 {
		t.Fatal("wrong port gained HTTP receipt")
	}
}
func TestHTTPMarkerBoundsAndNoInjection(t *testing.T) {
	for _, domain := range []string{"", "bad\r\nHost: evil", "user@example.test", "https://example.test", "-bad.test", "bad..test"} {
		var b bytes.Buffer
		if err := WriteHTTPMarkerV1(&b, domain, "nonce"); err == nil || b.Len() != 0 {
			t.Fatal("unapproved host wrote bytes")
		}
	}
	for _, nonce := range []string{"health", "-nonce", "nonce-", "x\r\nX: secret", strings.Repeat("a", 64)} {
		var b bytes.Buffer
		if err := WriteHTTPMarkerV1(&b, "sandprobe.test", nonce); err == nil || b.Len() != 0 {
			t.Fatal("unapproved nonce wrote bytes")
		}
	}
	r := &countedReader{Reader: strings.NewReader("GET " + strings.Repeat("x", 10000))}
	_, nonce, isHTTP := readTCPMarker(r, "sandprobe.test", 80)
	if !isHTTP || nonce != "" || r.n > httpMarkerLimit {
		t.Fatal("HTTP request bound violated", r.n)
	}
	r = &countedReader{Reader: strings.NewReader(strings.Repeat("x", 10000))}
	readTCPMarker(r, "sandprobe.test", 80)
	if r.n > 64 {
		t.Fatal("legacy read bound expanded", r.n)
	}
}
func TestHTTPMarkerAckIsBoundedAndNotAnHTTPStatusPass(t *testing.T) {
	const nonce = "nonce-marker"
	var valid bytes.Buffer
	writeHTTPMarkerAckV1(&valid, nonce)
	if err := ReadHTTPMarkerAckV1(bytes.NewReader(valid.Bytes()), nonce); err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{
		strings.Replace(valid.String(), nonce, "other-marker", 1),
		valid.String() + "extra-sensitive-data",
		valid.String()[:len(valid.String())-2],
		strings.Replace(valid.String(), "text/plain", "application/json", 1),
		strings.Replace(valid.String(), "HTTP/1.1", "HTTP/1.0", 1),
		strings.Replace(valid.String(), "Connection: close", "Connection: keep-alive", 1),
		strings.Replace(valid.String(), "Connection: close", "Connection: close\r\nContent-Encoding: gzip", 1),
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 secret\r\nX-Long: " + strings.Repeat("secret", 1000) + "\r\n\r\n",
	} {
		r := &countedReader{Reader: strings.NewReader(wire)}
		err := ReadHTTPMarkerAckV1(r, nonce)
		if !errors.Is(err, ErrUnexpectedAck) || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "secret") || r.n > httpMarkerLimit+1 {
			t.Fatal("invalid or unbounded ack accepted", r.n)
		}
	}
	for _, status := range []int{302, 400, 403, 407, 502} {
		err := ReadHTTPMarkerAckV1(strings.NewReader(fmt.Sprintf("HTTP/1.1 %d sensitive-text\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status)), nonce)
		if !errors.Is(err, ErrUnexpectedAck) || AckDiagnostic(err) == "" || strings.Contains(err.Error(), "sensitive") {
			t.Fatal("HTTP status treated as an acknowledgement")
		}
	}
}
