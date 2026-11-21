package canary

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestMarkerAcknowledgementIsBoundedAndExact(t *testing.T) {
	nonce := strings.Repeat("a", 48)
	for _, s := range []string{"HTTP/1.1 403 Forbidden\r\n", "sandprobe:wrong\n", " sandprobe:" + nonce + "\n", strings.Repeat("sensitive-response", 1000)} {
		if err := ReadMarkerAck(strings.NewReader(s), nonce); !errors.Is(err, ErrUnexpectedAck) {
			t.Fatal("unexpected reply accepted")
		}
	}
	if err := ReadMarkerAck(strings.NewReader("sandprobe:"+nonce+"\n"), nonce); err != nil {
		t.Fatal(err)
	}
	if err := ReadMarkerAck(strings.NewReader(""), nonce); err != io.EOF {
		t.Fatal("empty reply was accepted")
	}
}

func TestMarkerReplyClassificationIsBoundedAndContainsNoResponseText(t *testing.T) {
	for _, c := range []struct{ reply, want string }{
		{"HTTP/1.1 403 synthetic-sensitive-text\r\n", "http_status_403"},
		{"HTTP/1.0 407 synthetic-sensitive-text\r\n", "http_status_407"},
		{"HTTP/1.1 200 OK\r\n", "http_other_status"},
		{"HTTP/1.1 403wrong\r\n", "unexpected_reply"},
		{"HTTP/1.1 403 Forbidden\n", "unexpected_reply"},
		{"HTTP/1.1 403 \x01secret\r\n", "unexpected_reply"},
		{"HTTP/1.1 403 " + strings.Repeat("secret", 1000) + "\r\n", "unexpected_reply"},
	} {
		r := &countedReader{Reader: strings.NewReader(c.reply)}
		err := ReadMarkerAck(r, strings.Repeat("a", 48))
		if !errors.Is(err, ErrUnexpectedAck) || AckDiagnostic(err) != c.want || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "secret") {
			t.Fatal("unbounded or incorrect reply diagnostic")
		}
		if r.n > 256 {
			t.Fatal("reply limit exceeded")
		}
	}
}

type countedReader struct {
	io.Reader
	n int
}

func (r *countedReader) Read(p []byte) (int, error) { n, e := r.Reader.Read(p); r.n += n; return n, e }
