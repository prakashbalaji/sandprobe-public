package canary

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
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
	req, err := http.ReadRequest(bufio.NewReader(io.MultiReader(strings.NewReader(string(prefix)), br)))
	if err != nil {
		return "", "", true
	}
	defer req.Body.Close()
	if req.Method != "GET" || req.Proto != "HTTP/1.1" || req.ContentLength != 0 || len(req.TransferEncoding) != 0 || req.Header.Get("Connection") != "close" || !validMarkerHeaders(req.Header) || len(req.Header.Values("Connection")) != 1 || !strings.HasPrefix(req.RequestURI, httpMarkerPath) {
		return "", "", true
	}
	n := strings.TrimPrefix(req.RequestURI, httpMarkerPath)
	expected := n + ".canary." + domain
	if !validHTTPMarker(domain, n) || req.URL.Path != req.RequestURI || !(strings.EqualFold(req.Host, expected) || strings.EqualFold(req.Host, expected+":80")) {
		return "", "", true
	}
	return "", n, true
}

// Forwarding metadata is bounded and ignored: receipt source is always the socket peer.
func validMarkerHeaders(h http.Header) bool {
	if len(h) > 16 {
		return false
	}
	for key := range h {
		switch key {
		case "Connection", "Accept", "User-Agent", "Via", "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Request-Id", "Traceparent", "Tracestate":
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
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		return ErrUnexpectedAck
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		code := res.StatusCode
		if code == 403 || code == 407 {
			return &ackError{label: "http_status_" + strconv.Itoa(code)}
		}
		if code >= 100 && code <= 599 {
			return &ackError{label: fmt.Sprintf("http_status_%dxx", code/100)}
		}
		return ErrUnexpectedAck
	}
	expected := "sandprobe:" + nonce + "\n"
	if res.Proto != "HTTP/1.1" || res.ContentLength != int64(len(expected)) || len(res.TransferEncoding) != 0 || res.Header.Get("Content-Type") != "text/plain" || res.Header.Get("Content-Encoding") != "" || !res.Close {
		return ErrUnexpectedAck
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, int64(len(expected)+1)))
	if err != nil || string(body) != expected {
		return ErrUnexpectedAck
	}
	if _, err = br.ReadByte(); err != io.EOF || limited.N == 0 {
		return ErrUnexpectedAck
	}
	return nil
}
