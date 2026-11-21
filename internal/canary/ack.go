package canary

import (
	"bufio"
	"errors"
	"io"
	"regexp"
)

var ErrUnexpectedAck = errors.New("unexpected canary acknowledgement")

// EVD-6: retain only a fixed classification, never the untrusted status text.
type ackError struct{ label string }

func (e *ackError) Error() string        { return ErrUnexpectedAck.Error() }
func (e *ackError) Is(target error) bool { return target == ErrUnexpectedAck }

var httpStatusLine = regexp.MustCompile(`^HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*\r\n$`)

func AckDiagnostic(err error) string {
	var e *ackError
	if errors.As(err, &e) {
		return e.label
	}
	if errors.Is(err, ErrUnexpectedAck) {
		return "unexpected_reply"
	}
	return ""
}

// ReadMarkerAck is shared by guest and host clients. MEAS-3: bounded, exact
// acknowledgement only; never return response text in diagnostics.
func ReadMarkerAck(r io.Reader, nonce string) error {
	line, err := bufio.NewReader(io.LimitReader(r, 256)).ReadString('\n')
	if err != nil {
		if len(line) > 0 {
			return ErrUnexpectedAck
		}
		return err
	}
	if line != "sandprobe:"+nonce+"\n" {
		if match := httpStatusLine.FindStringSubmatch(line); match != nil {
			label := "http_other_status"
			switch match[1] {
			case "403":
				label = "http_status_403"
			case "407":
				label = "http_status_407"
			}
			return &ackError{label: label}
		}
		return ErrUnexpectedAck
	}
	return nil
}
