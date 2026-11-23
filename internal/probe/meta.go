//go:build linux

package probe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// Metadata addresses SEC-4 may contact (SBX-3), from the catalog's one list, which every plan names (UX-4). Azure has
// no listing that gives identity names without an identity call, so it isn't contacted.
const (
	imdsAddr        = catalog.MetadataIMDS        // AWS and GCP instance metadata
	ecsAddr         = catalog.MetadataECS         // the ECS credential endpoint
	podIdentityAddr = catalog.MetadataPodIdentity // EKS Pod Identity
)

// imdsHost and podIdentityHost are those addresses without their port: IMDS's Host header, and the host EKS Pod
// Identity's variable must name.
var imdsHost, podIdentityHost = hostOf(imdsAddr), hostOf(podIdentityAddr)

func hostOf(addr string) string {
	h, _, _ := net.SplitHostPort(addr)
	return h
}

var (
	errNoConnect = errors.New("nothing accepted a connection")           // nothing listens: the address is unreachable
	errNoAnswer  = errors.New("connected, but no HTTP answer came back") // something listens and didn't answer this request
	errOutOfTime = errors.New("the check's time ran out (SBX-7)")        // coverage was cut off: never not_found
)

// metaAnswer is one HTTP answer: its status, headers and at most 4 KB of body.
type metaAnswer struct {
	code int
	hdr  textproto.MIMEHeader
	body string
}

type (
	metaRequester func(addr, method, path, host string, headers map[string]string, deadline time.Time) (metaAnswer, error)
	metaDialer    func(addr string, deadline time.Time) error
)

// attemptDeadline is SBX-7's 3 s per attempt, cut short by the check's own deadline.
func attemptDeadline(deadline time.Time) (time.Time, error) {
	if !time.Now().Before(deadline) {
		return time.Time{}, errOutOfTime
	}
	if d := time.Now().Add(attemptTimeout); d.Before(deadline) {
		return d, nil
	}
	return deadline, nil
}

// failed maps a network error to errOutOfTime when the check's deadline is what stopped it.
func failed(err error, deadline time.Time) error {
	if !time.Now().Before(deadline) {
		return errOutOfTime
	}
	return err
}

// metaDial is a TCP connect that sends nothing. A local address is never contacted (SBX-1).
func metaDial(addr string, deadline time.Time) error {
	h, _, _ := net.SplitHostPort(addr)
	if isLocal(net.ParseIP(h)) {
		return errNoConnect
	}
	d, err := attemptDeadline(deadline)
	if err != nil {
		return err
	}
	c, err := (&net.Dialer{Deadline: d}).Dial("tcp4", addr)
	if err != nil {
		return failed(errNoConnect, deadline)
	}
	c.Close()
	return nil
}

// errUnsafeRequest: a request line or header carries a control character, which could smuggle bytes into the request.
var errUnsafeRequest = errors.New("a metadata request would carry a control character, so it isn't sent")

// safeField: no control characters, so a value can't end its header line and start another.
func safeField(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return false
		}
	}
	return true
}

// metaRequest sends one HTTP/1.1 request to a link-local metadata address and reads its answer. A local address is
// never contacted (SBX-1), and a request whose line or headers carry a control character is never sent.
func metaRequest(addr, method, path, host string, headers map[string]string, deadline time.Time) (metaAnswer, error) {
	if !safeField(method) || !safeField(path) || !safeField(host) {
		return metaAnswer{}, errUnsafeRequest
	}
	for k, v := range headers {
		if !safeField(k) || !safeField(v) {
			return metaAnswer{}, errUnsafeRequest
		}
	}
	h, _, _ := net.SplitHostPort(addr)
	if isLocal(net.ParseIP(h)) {
		return metaAnswer{}, errNoConnect
	}
	d, err := attemptDeadline(deadline)
	if err != nil {
		return metaAnswer{}, err
	}
	conn, err := (&net.Dialer{Deadline: d}).Dial("tcp4", addr)
	if err != nil {
		return metaAnswer{}, failed(errNoConnect, deadline)
	}
	defer conn.Close()
	conn.SetDeadline(d)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: 0\r\n", method, path, host)
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	return exchange(conn, b.String(), deadline)
}

// exchange writes one request and reads its answer. Any failure once the check's deadline has passed is errOutOfTime,
// a stall before the status line included: the check didn't finish, so it can't end not_found.
func exchange(conn net.Conn, request string, deadline time.Time) (metaAnswer, error) {
	if _, err := io.WriteString(conn, request); err != nil {
		return metaAnswer{}, failed(errNoAnswer, deadline)
	}
	a, err := readAnswer(conn)
	switch {
	case err == errNoAnswer:
		return a, failed(errNoAnswer, deadline)
	case err != nil:
		return a, failed(fmt.Errorf("%s: %w", conn.RemoteAddr(), err), deadline)
	}
	return a, nil
}

const (
	maxHead = 16 << 10 // status line and headers
	maxBody = 4 << 10  // a listing
)

// readAnswer reads one HTTP/1.x answer whole: the status, headers and a body that ends where its Content-Length says,
// or at the connection's end. A body cut short, by a stall, a close or a cap, is an error, never a shorter listing.
func readAnswer(r io.Reader) (metaAnswer, error) {
	head := &io.LimitedReader{R: r, N: maxHead + maxBody + 1}
	tp := textproto.NewReader(bufio.NewReader(head))
	status, err := tp.ReadLine()
	if err != nil {
		return metaAnswer{}, errNoAnswer
	}
	f := strings.Fields(status)
	code := 0
	if len(f) >= 2 && strings.HasPrefix(f[0], "HTTP/1.") {
		code, _ = strconv.Atoi(f[1])
	}
	if code == 0 {
		return metaAnswer{}, fmt.Errorf("answered %q, not HTTP", clip(status))
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return metaAnswer{}, errors.New("the answer's headers didn't parse")
	}
	if hdr.Get("Transfer-Encoding") != "" {
		return metaAnswer{}, errors.New("a transfer-encoded answer isn't one SEC-4 reads")
	}
	var body []byte
	if cl := hdr.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 || n > maxBody {
			return metaAnswer{}, fmt.Errorf("a body of %q bytes isn't one SEC-4 reads", cl)
		}
		body = make([]byte, n)
		if _, err := io.ReadFull(tp.R, body); err != nil {
			return metaAnswer{}, errors.New("the body ended before its Content-Length")
		}
	} else {
		body, err = io.ReadAll(io.LimitReader(tp.R, maxBody+1))
		switch {
		case err != nil:
			return metaAnswer{}, errors.New("the body didn't end: " + err.Error())
		case len(body) > maxBody:
			return metaAnswer{}, errors.New("the body is longer than a listing")
		case head.N == 0:
			return metaAnswer{}, errors.New("the answer is longer than SEC-4 reads")
		}
	}
	return metaAnswer{code, hdr, string(body)}, nil
}

var metaName = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,128}$`)

// imdsToken is the shape of an IMDSv2 session token: base64-like, nothing that could end a header line.
var imdsToken = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{1,512}$`)

// listing reads a metadata listing body as names, one per line (GCP's end in "/"). A line that isn't a name means the
// answer isn't the listing it should be.
func listing(body string) ([]string, bool) {
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(body), "\n") {
		l = strings.TrimSuffix(strings.TrimSpace(l), "/")
		switch {
		case l == "":
		case !metaName.MatchString(l):
			return nil, false
		default:
			names = append(names, l)
		}
	}
	return names, true
}

// SEC-4: metadata credentials, by the names their listings give, never a credential document (SBX-2). AWS IMDSv2 and
// IMDSv1 role listings, GCP's service account listing, and the ECS and EKS Pod Identity endpoints the agent's
// variables point at, which get a TCP connect and no request. Find-only: nothing listed proves nothing.
func sec4(e *env, ck *catalog.Check) obs.Observation {
	return metaScan(time.Now().Add(checkLimit), metaRequest, metaDial)
}

// metaScan is SEC-4 under one deadline for the whole check (SBX-7). Each listing is asked independently, so a service
// that ignores one request is still asked the others; only nothing accepting a connection at the instance metadata
// address skips the requests after the first. A role found is a finding whenever it was found; running out of time
// before every listing was asked is unknown, never not_found.
func metaScan(deadline time.Time, request metaRequester, dial metaDialer) obs.Observation {
	var found []string
	const roles = "/latest/meta-data/iam/security-credentials/"
	cut := false
	// ask requests one listing and adds what it names to found. It returns why the answer can't be trusted, if so.
	ask := func(who, noun, method, path, host string, headers map[string]string, accept func(metaAnswer) bool) string {
		a, err := request(imdsAddr, method, path, host, headers, deadline)
		switch {
		case err == errOutOfTime:
			cut = true
			return ""
		case err == errNoConnect, err == errNoAnswer:
			return ""
		case err != nil:
			return err.Error()
		case a.code != 200 || !accept(a):
			return ""
		}
		names, ok := listing(a.body)
		if !ok {
			return who + " answered its " + noun + " listing with something that isn't one"
		}
		if len(names) > 0 {
			found = append(found, who+" lists "+noun+" "+strings.Join(names, ", "))
		}
		return ""
	}
	always := func(metaAnswer) bool { return true }

	// IMDSv2: a session token, held in memory for one listing and never recorded.
	reachable, oddToken := true, false
	if a, err := request(imdsAddr, "PUT", "/latest/api/token", imdsHost,
		map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"}, deadline); err == nil && a.code == 200 && a.body != "" {
		// The token goes back as a header, so only a token-shaped one does: anything else could smuggle bytes into the
		// request. The other listings are still asked, and with nothing found SEC-4 is unknown.
		if token := strings.TrimSpace(a.body); !imdsToken.MatchString(token) {
			oddToken = true
		} else if why := ask("AWS IMDSv2", "role", "GET", roles, imdsHost, map[string]string{"X-aws-ec2-metadata-token": token}, always); why != "" {
			return unknownObs(why)
		}
	} else {
		switch {
		case err == errOutOfTime:
			cut = true
		case err == errNoConnect:
			reachable = false
		case err != nil && err != errNoAnswer:
			return unknownObs(err.Error())
		}
	}
	if reachable && !cut {
		// IMDSv1: the same listing with no token.
		if why := ask("AWS IMDSv1 (no token needed)", "role", "GET", roles, imdsHost, nil, always); why != "" {
			return unknownObs(why)
		}
	}
	if reachable && !cut {
		// GCP: the service account listing, only from a server that says it is Google's metadata server.
		google := func(a metaAnswer) bool { return a.hdr.Get("Metadata-Flavor") == "Google" }
		if why := ask("GCP metadata", "service account", "GET", "/computeMetadata/v1/instance/service-accounts/",
			"metadata.google.internal", map[string]string{"Metadata-Flavor": "Google"}, google); why != "" {
			return unknownObs(why)
		}
	}
	// ECS and EKS Pod Identity: offered when the agent's variables point at them and they accept a connection. The
	// variables' values are never recorded.
	full, _ := url.Parse(os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"))
	for _, ep := range []struct {
		addr, what string
		offered    bool
	}{
		{ecsAddr, "the ECS credential endpoint (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)", os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != ""},
		{podIdentityAddr, "EKS Pod Identity (AWS_CONTAINER_CREDENTIALS_FULL_URI)", full != nil && full.Hostname() == podIdentityHost},
	} {
		if !ep.offered || cut {
			continue
		}
		switch err := dial(ep.addr, deadline); err {
		case nil:
			found = append(found, ep.what+" is offered and accepts a connection (no request sent)")
		case errOutOfTime:
			cut = true
		}
	}
	switch {
	case len(found) > 0:
		return obs.Observation{Result: obs.Finding, Variant: "role_listed", Evidence: strings.Join(found, "; ")}
	case cut:
		return unknownObs("SEC-4 ran out of its 10 s before every metadata listing was asked (SBX-7)")
	case oddToken:
		return unknownObs("AWS IMDSv2 answered with a token that isn't token-shaped, so its role listing wasn't asked")
	}
	return obs.Observation{Result: obs.NotFound, Reason: "no metadata service listed a role or identity, and none was offered"}
}
