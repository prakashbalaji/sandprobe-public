package canary

import (
	"bufio"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
)

const httpMarkerPath = "/sandprobe/v1/echo/"
const httpMarkerLimit = 2048

func validHTTPMarker(domain, nonce string) bool {
	if !nameRE.MatchString(nonce) || nonce == "health" || strings.HasPrefix(nonce, "-") || strings.HasSuffix(nonce, "-") || len(nonce)+8+len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !nameRE.MatchString(label) || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// WriteHTTPMarkerV1 writes one canonical request, without dialing, redirects or retries.
// EVD-9: only a caller's separately approved canary connection may carry it.
func WriteHTTPMarkerV1(w io.Writer, domain, nonce string) error {
	if !validHTTPMarker(domain, nonce) {
		return ErrUnexpectedAck
	}
	_, err := fmt.Fprintf(w, "GET %s%s HTTP/1.1\r\nHost: %s.canary.%s\r\nConnection: close\r\n\r\n", httpMarkerPath, nonce, nonce, domain)
	return err
}

// readTCPMarker preserves the legacy read bound; only a GET prefix on logical port80
// enables EVD-9's larger, still bounded HTTP parser. It never follows a URL.
func readTCPMarker(r io.Reader, domain string, port int) (line, nonce string, isHTTP bool) {
	limited := &io.LimitedReader{R: r, N: 64}
	br := bufio.NewReaderSize(limited, 16)
	var prefix []byte
	for len(prefix) < 4 {
		b, err := br.ReadByte()
		if err != nil {
			return string(prefix), "", false
		}
		prefix = append(prefix, b)
		if b == '\n' {
			return string(prefix), "", false
		}
	}
	if port != 80 || string(prefix) != "GET " {
		rest, _ := br.ReadString('\n')
		return string(prefix) + rest, "", false
	}
	limited.N += httpMarkerLimit - 64
	request := bufio.NewReader(io.MultiReader(strings.NewReader(string(prefix)), br))
	line, err := readHTTPLine(request)
	if err != nil {
		return "", "", true
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] != "GET" || parts[2] != "HTTP/1.1" || !strings.HasPrefix(parts[1], httpMarkerPath) {
		return "", "", true
	}
	headers, err := readHTTPHeaders(request)
	if err != nil || !validMarkerHeaders(headers) || !strings.EqualFold(headers.Get("Connection"), "close") || len(headers.Values("Connection")) != 1 || len(headers.Values("Host")) != 1 {
		return "", "", true
	}
	n := strings.TrimPrefix(parts[1], httpMarkerPath)
	expected := n + ".canary." + domain
	if !validHTTPMarker(domain, n) || !(strings.EqualFold(headers.Get("Host"), expected) || strings.EqualFold(headers.Get("Host"), expected+":80")) {
		return "", "", true
	}

	return "", n, true
}

// Forwarding metadata is bounded and ignored: receipt source is always the socket peer.
func validMarkerHeaders(h textproto.MIMEHeader) bool {
	if values := h.Values("Content-Length"); len(values) > 0 && (len(values) != 1 || values[0] != "0") {
		return false
	}
	if len(h) > 16 {
		return false
	}
	for key := range h {
		switch key {
		case "Content-Length", "Host", "Connection", "Accept", "User-Agent", "Via", "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Request-Id", "Traceparent", "Tracestate":
		default:
			return false
		}
	}
	return true
}

func writeHTTPMarkerAckV1(w io.Writer, nonce string) error {
	body := "sandprobe:" + nonce + "\n"
	_, err := fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n%s", len(body), body)
	return err
}

// ReadHTTPMarkerAckV1 accepts only a bounded, correctly framed nonce acknowledgement.
// The caller must set its connection deadline. Completion is not a host receipt (EVD-9).
func ReadHTTPMarkerAckV1(r io.Reader, nonce string) error {
	if !nameRE.MatchString(nonce) || nonce == "health" {
		return ErrUnexpectedAck
	}
	limited := &io.LimitedReader{R: r, N: httpMarkerLimit + 1}
	br := bufio.NewReader(limited)
	line, err := readHTTPLine(br)
	if err != nil {
		return ErrUnexpectedAck
	}
	match := httpStatusLine.FindStringSubmatch(line + "\r\n")
	if match == nil || !strings.HasPrefix(line, "HTTP/1.1 ") {
		return ErrUnexpectedAck
	}
	code, _ := strconv.Atoi(match[1])
	if code != 200 {
		if code == 403 || code == 407 {
			return &ackError{label: "http_status_" + strconv.Itoa(code)}
		}
		if code >= 100 && code <= 599 {
			return &ackError{label: fmt.Sprintf("http_status_%dxx", code/100)}
		}
		return ErrUnexpectedAck
	}
	headers, err := readHTTPHeaders(br)
	if err != nil {
		return ErrUnexpectedAck
	}

	expected := "sandprobe:" + nonce + "\n"
	if len(headers.Values("Content-Length")) != 1 || headers.Get("Content-Length") != strconv.Itoa(len(expected)) || len(headers.Values("Transfer-Encoding")) != 0 || len(headers.Values("Content-Type")) != 1 || headers.Get("Content-Type") != "text/plain" || len(headers.Values("Content-Encoding")) != 0 || len(headers.Values("Connection")) != 1 || !strings.EqualFold(headers.Get("Connection"), "close") {
		return ErrUnexpectedAck
	}
	body := make([]byte, len(expected))
	if _, err := io.ReadFull(br, body); err != nil || string(body) != expected {
		return ErrUnexpectedAck
	}

	if _, err = br.ReadByte(); err != io.EOF || limited.N == 0 {
		return ErrUnexpectedAck
	}
	return nil
}

// This deliberately small wire parser keeps net/http's server stack out of the probe.
func readHTTPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasSuffix(line, "\r\n") {
		return "", ErrUnexpectedAck
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}
func readHTTPHeaders(r *bufio.Reader) (textproto.MIMEHeader, error) {
	h := textproto.MIMEHeader{}
	for count := 0; ; count++ {
		line, err := readHTTPLine(r)
		if err != nil {
			return nil, ErrUnexpectedAck
		}
		if line == "" {
			return h, nil
		}
		if count >= 16 {
			return nil, ErrUnexpectedAck
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" {
			return nil, ErrUnexpectedAck
		}
		for _, c := range []byte(key) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
				return nil, ErrUnexpectedAck
			}
		}
		for _, c := range []byte(value) {
			if c != '\t' && (c < 32 || c > 126) {
				return nil, ErrUnexpectedAck
			}
		}
		h.Add(textproto.CanonicalMIMEHeaderKey(key), strings.Trim(value, " \t"))
	}
}
