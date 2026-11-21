//go:build linux

package probe

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sandprobe/internal/canary"
	"syscall"
)

var errCanaryPin = errors.New("not the pinned key")

type exchangeError struct {
	stage string
	err   error
}

func (e *exchangeError) Error() string { return "canary exchange failed" }
func (e *exchangeError) Unwrap() error { return e.err }
func exchangeAt(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &exchangeError{stage, err}
}

// EVD-2: fixed labels only. A completed exchange is still not a host receipt.
func exchangeDiagnostic(err error) (string, string) {
	stage := "exchange"
	var e *exchangeError
	if errors.As(err, &e) {
		stage = e.stage
	}
	if err == nil {
		return stage, "completed"
	}
	if errors.Is(err, errCanaryPin) {
		return stage, "pin_mismatch"
	}
	if label := canary.AckDiagnostic(err); label != "" {
		return stage, label
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return stage, "connection_reset"
	}
	if errors.Is(err, syscall.EPIPE) {
		return stage, "broken_pipe"
	}
	var header tls.RecordHeaderError
	if errors.As(err, &header) {
		return stage, "non_tls_reply"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return stage, "timeout"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return stage, "closed"
	}
	return stage, "io_error"
}
