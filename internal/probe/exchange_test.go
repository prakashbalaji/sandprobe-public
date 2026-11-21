//go:build linux

package probe

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"sandprobe/internal/obs"
)

func TestExchangeDiagnosticLabelsNeverEchoErrors(t *testing.T) {
	for _, c := range []struct {
		err           error
		stage, result string
	}{
		{nil, "exchange", "completed"},
		{exchangeAt("tls_handshake", errCanaryPin), "tls_handshake", "pin_mismatch"},
		{exchangeAt("read_reply", os.ErrDeadlineExceeded), "read_reply", "timeout"},
		{exchangeAt("read_reply", io.EOF), "read_reply", "closed"},
		{exchangeAt("send_marker", errors.New("synthetic-sensitive-error")), "send_marker", "io_error"},
		{exchangeAt("tls_handshake", &net.OpError{Err: syscall.ECONNRESET}), "tls_handshake", "connection_reset"},
		{exchangeAt("send_marker", syscall.EPIPE), "send_marker", "broken_pipe"},
		{exchangeAt("tls_handshake", tls.RecordHeaderError{Msg: "synthetic-sensitive-error"}), "tls_handshake", "non_tls_reply"},
	} {
		stage, result := exchangeDiagnostic(c.err)
		if stage != c.stage || result != c.result || !obs.ValidExchangeDiagnostic(stage, result) {
			t.Fatal("wrong fixed diagnostic", stage, result)
		}
	}
}

func TestTCPConnectionRetainsFailedApplicationExchange(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
	}()
	e := &env{start: time.Now()}
	a := e.tcpTry(l.Addr().String(), func(c net.Conn) error {
		_, err := bufio.NewReader(c).ReadString('\n')
		return exchangeAt("read_reply", err)
	})
	<-done
	if a.Outcome != "connected" || a.ExchangeStage != "read_reply" || a.ExchangeResult != "closed" {
		t.Fatalf("lost failed application exchange: %+v", a)
	}
}
