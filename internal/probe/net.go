//go:build linux

package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

const attemptTimeout = 3 * time.Second // SBX-7: 3 s per network attempt

// sysConnect is syscall.Connect. Only a fault-injection build (the sandprobe_faults tag, never shipped) replaces it, so
// the network fixture can prove a refusal the kernel never saw can't pass (TWN-1).
var sysConnect = syscall.Connect

// tcpTry is one non-blocking TCP attempt at dest ("ip:port"), with TWN-1's kernel evidence: SYN_SENT seen through
// TCP_INFO before the final error arrives through SO_ERROR, SYN retransmits for a timeout, and the kernel's own route
// lookup for an immediate unreachable error. On a connection, use runs on it.
func (e *env) tcpTry(dest string, use func(net.Conn) error) (a obs.Attempt) {
	a = obs.Attempt{Dest: dest, StartMS: e.ms()}
	defer func() { a.EndMS = e.ms() }()
	host, portS, err := net.SplitHostPort(dest)
	ip := net.ParseIP(host).To4()
	port, perr := strconv.Atoi(portS)
	if err != nil || ip == nil || perr != nil {
		a.Outcome = "error"
		return a
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		a.Outcome = "error"
		return a
	}
	owned := true
	defer func() {
		if owned {
			syscall.Close(fd)
		}
	}()
	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip)
	err = sysConnect(fd, sa)
	switch e := errnoOf(err); {
	case err == nil:
	case e == syscall.EINPROGRESS:
		if info, ok := tcpInfo(fd); ok && info.state == 2 /* SYN_SENT */ {
			a.SynSent = true
		}
		done := pollWritable(fd, attemptTimeout)
		// On a fast path the exchange can finish before the sample above: the kernel's count of segments sent, which
		// survives the socket closing, still shows the SYN went out. A connect never issued sends nothing.
		if info, ok := tcpInfo(fd); ok && info.segsOut > 0 {
			a.SynSent = true
		}
		if !done {
			a.Outcome, a.SynRetrans = "timeout", retransmits(fd)
			return a
		}
		soerr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			a.Outcome = "error"
			return a
		}
		if soerr != 0 {
			a.Outcome = outcomeOf(syscall.Errno(soerr))
			if a.Outcome == "timeout" {
				a.SynRetrans = retransmits(fd)
			}
			return a
		}
	default:
		a.Immediate, a.Outcome = true, outcomeOf(e)
		if a.Outcome == "netunreach" || a.Outcome == "hostunreach" {
			a.RouteLookup = routeLookup(ip)
		}
		return a
	}
	a.Outcome = "connected"
	f := os.NewFile(uintptr(fd), "probe")
	owned = false
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return a
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(attemptTimeout))
	if use != nil {
		a.ExchangeStage, a.ExchangeResult = exchangeDiagnostic(use(conn))
	}
	return a
}

func outcomeOf(e syscall.Errno) string {
	switch e {
	case syscall.ECONNREFUSED:
		return "refused"
	case syscall.ETIMEDOUT:
		return "timeout"
	case syscall.ENETUNREACH:
		return "netunreach"
	case syscall.EHOSTUNREACH:
		return "hostunreach"
	case syscall.EACCES, syscall.EPERM:
		return "eperm"
	}
	return "error"
}

func retransmits(fd int) int {
	info, ok := tcpInfo(fd)
	if !ok {
		return 0
	}
	return max(info.retransmits, info.totalRetrans)
}

type tcpState struct {
	state, retransmits, totalRetrans, segsOut int
}

// tcpInfo reads TCP_INFO with a raw getsockopt, as linux/tcp.h lays it out: tcpi_state at 0, tcpi_retransmits at 2,
// tcpi_total_retrans at 100, tcpi_segs_out at 136 (kernels before 4.2 return less, and segsOut stays 0).
func tcpInfo(fd int) (tcpState, bool) {
	var buf [232]byte
	n := uint32(len(buf))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.IPPROTO_TCP, syscall.TCP_INFO,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
	if e != 0 || n < 104 {
		return tcpState{}, false
	}
	le := binary.LittleEndian
	t := tcpState{state: int(buf[0]), retransmits: int(buf[2]), totalRetrans: int(le.Uint32(buf[100:]))}
	if n >= 140 {
		t.segsOut = int(le.Uint32(buf[136:]))
	}
	return t, true
}

// pollWritable waits for a connect to finish, with ppoll, which has no limit on the descriptor's number (select's
// fd_set stops at 1024). ppoll writes the time left back, so an interrupted wait resumes where it stopped.
func pollWritable(fd int, d time.Duration) bool {
	pfd := struct {
		fd              int32
		events, revents int16
	}{fd: int32(fd), events: 0x4 /* POLLOUT */}
	ts := syscall.NsecToTimespec(d.Nanoseconds())
	for {
		n, _, e := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&pfd)), 1, uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
		if e == syscall.EINTR {
			continue
		}
		return e == 0 && n > 0
	}
}

// routeLookup asks the kernel, over netlink (RTM_GETROUTE, after policy rules), how it would route to ip:
// none, unreachable, prohibit or ok. Anything it can't establish is "", which never supports a refusal.
func routeLookup(ip net.IP) string {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return ""
	}
	defer syscall.Close(fd)
	req := make([]byte, 36)
	le := binary.LittleEndian
	le.PutUint32(req[0:], 36)
	le.PutUint16(req[4:], syscall.RTM_GETROUTE)
	le.PutUint16(req[6:], syscall.NLM_F_REQUEST)
	le.PutUint32(req[8:], 1)
	req[16], req[17] = syscall.AF_INET, 32 // rtmsg: family, dst_len
	le.PutUint16(req[28:], 8)              // rtattr RTA_DST
	le.PutUint16(req[30:], syscall.RTA_DST)
	copy(req[32:], ip.To4())
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil || n < 20 {
		return ""
	}
	switch le.Uint16(buf[4:]) {
	case syscall.NLMSG_ERROR:
		if code := int32(le.Uint32(buf[16:])); code == -int32(syscall.ENETUNREACH) {
			return "none"
		}
	case syscall.RTM_NEWROUTE:
		if n < 24 {
			return ""
		}
		switch buf[16+7] { // rtm_type
		case syscall.RTN_UNICAST, syscall.RTN_LOCAL:
			return "ok"
		case syscall.RTN_UNREACHABLE, syscall.RTN_BLACKHOLE:
			return "unreachable"
		case syscall.RTN_PROHIBIT:
			return "prohibit"
		}
	}
	return ""
}

// The EGR checks. Each attempt carries its check's own nonce; the canary's receipts, which only the host reads,
// decide the result (SBX-11). The probe reports attempts and evidence, never a pass.

func (e *env) twin() bool {
	return e.tcpTry(fmt.Sprintf("127.0.0.1:%d", e.ownPort), nil).Outcome == "connected"
}

// tries runs one attempt, and a second when the first times out (SBX-7), each with the loopback twin.
func (e *env) tries(dest string, use func(net.Conn) error) []obs.Attempt {
	var as []obs.Attempt
	for i := 0; i < 2; i++ {
		tw := e.twin()
		a := e.tcpTry(dest, use)
		a.LoopbackTwin = tw
		as = append(as, a)
		if a.Outcome != "timeout" {
			break
		}
	}
	return as
}

func (e *env) canaryReady(ck *catalog.Check) (dest, nonce string, ok bool) {
	dest, nonce = e.in.Endpoints[ck.ID], e.in.CheckNonces[ck.ID]
	return dest, nonce, dest != "" && nonce != "" && e.in.CanaryDomain != "" && e.in.CanaryPin != ""
}

// tlsUse is the TLS echo over a connection: the SNI carries the nonce, and a key other than the pinned one is
// interception (EGR-4).
func (e *env) tlsUse(nonce string) func(net.Conn) error {
	return func(c net.Conn) error {
		tc := tls.Client(c, &tls.Config{ServerName: nonce + ".canary." + e.in.CanaryDomain, InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || canary.PinOf(cs.PeerCertificates[0]) != e.in.CanaryPin {
					e.intercepted = true
					return errCanaryPin
				}
				return nil
			}})
		if err := tc.Handshake(); err != nil {
			return exchangeAt("tls_handshake", err)
		}
		return exchangeAt("read_reply", canary.ReadMarkerAck(tc, nonce))
	}
}

func egrDirect(e *env, ck *catalog.Check) obs.Observation {
	dest, nonce, ok := e.canaryReady(ck)
	if !ok {
		return unknownObs("the run has no canary endpoint, nonce or pin for this check")
	}
	use := func(c net.Conn) error {
		if _, err := io.WriteString(c, nonce+"\n"); err != nil {
			return exchangeAt("send_marker", err)
		}
		return exchangeAt("read_reply", canary.ReadMarkerAck(c, nonce))
	}
	if ck.Canary.Port == 443 {
		use = e.tlsUse(nonce)
	}
	return obs.Observation{Result: obs.Attempted, Attempts: e.tries(dest, use)}
}

func agentProxy() (obs.ProxySetting, bool) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		raw := os.Getenv(k)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return obs.ProxySetting{Var: k, Malformed: true}, true // the parse error would quote the URL: never kept
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443", "socks5": "1080"}[u.Scheme]
		}
		return obs.ProxySetting{Var: k, Scheme: u.Scheme, Addr: net.JoinHostPort(u.Hostname(), port), Credentials: u.User != nil}, true
	}
	return obs.ProxySetting{}, false
}

// resolveProxy finds the address the probe would connect to, and whether it is local: loopback, unspecified, or one of
// the box's own addresses. When the box's addresses can't be read, it counts as local.
func resolveProxy(addr string) (string, bool, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return "", false, errors.New("unresolved")
		}
		ip = ips[0]
	}
	if ip = ip.To4(); ip == nil {
		return "", false, errors.New("not IPv4")
	}
	return net.JoinHostPort(ip.String(), port), isLocal(ip), nil
}

// isLocal: loopback, unspecified, or one of the box's own addresses, where something the probe didn't start may be
// listening (SBX-1). When the box's addresses can't be read, it counts as local.
func isLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// tunnel is a proxied connection whose first bytes may already sit in the reader that parsed the proxy's answer.
type tunnel struct {
	net.Conn
	r *bufio.Reader
}

func (t *tunnel) Read(p []byte) (int, error) {
	if t.r.Buffered() > 0 {
		return t.r.Read(p)
	}
	return t.Conn.Read(p)
}

// connect asks the proxy for a tunnel to dest and reads its whole answer, at most 16 KB of status and headers.
func connect(c net.Conn, dest string) (net.Conn, error) {
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest); err != nil {
		return nil, err
	}
	head := &io.LimitedReader{R: c, N: 16 << 10}
	br := bufio.NewReader(head)
	tp := textproto.NewReader(br)
	status, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		return nil, err
	}
	if f := strings.Fields(status); len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") || f[1] != "200" {
		return nil, errors.New("the proxy refused the tunnel")
	}
	return &tunnel{Conn: c, r: br}, nil
}

// EGR-3: the same TLS echo through the agent's proxy, by the probe's own client, and only through the proxy the plan
// named (SBX-3). A local one is contacted only with the person's approval (SBX-1 (e)), and a proxy URL's credentials
// are never used (SBX-6). Each attempt names the canary as its destination and the proxy it went through.
func egrProxy(e *env, ck *catalog.Check) obs.Observation {
	dest, nonce, ok := e.canaryReady(ck)
	if !ok {
		return unknownObs("the run has no canary endpoint, nonce or pin for this check")
	}
	p, set := agentProxy()
	switch {
	case !set:
		return unknownObs("the agent's environment names no proxy")
	case p.Malformed:
		return unknownObs(p.Var + " isn't a URL the probe can use")
	case p.Credentials:
		return unknownObs("the proxy URL carries credentials, which the probe never uses (SBX-6)")
	case p.Scheme != "http":
		return unknownObs("the probe's client speaks HTTP CONNECT to a proxy, not " + p.Scheme)
	case e.in.Proxy == "" || p.Addr != e.in.Proxy:
		return unknownObs("the agent's proxy isn't the one the plan named, so it isn't contacted (SBX-3)")
	}
	proxy, local, err := resolveProxy(p.Addr)
	if err != nil {
		return unknownObs("can't resolve the proxy to an IPv4 address")
	}
	if local && !e.in.AllowLocal {
		return unknownObs("the proxy is local, and the plan didn't approve contacting it (SBX-1 (e))")
	}
	tlsUse := e.tlsUse(nonce)
	as := e.tries(proxy, func(c net.Conn) error {
		t, err := connect(c, dest)
		if err != nil {
			return exchangeAt("proxy_connect", err)
		}
		return tlsUse(t)
	})
	for i := range as {
		as[i].Dest, as[i].Via = dest, proxy
	}
	return obs.Observation{Result: obs.Attempted, Attempts: as}
}

// EGR-4: interception, seen while EGR-2 or EGR-3 ran. Find-only: not seeing it proves nothing.
func egrIntercept(e *env, ck *catalog.Check) obs.Observation {
	if e.intercepted {
		return obs.Observation{Result: obs.Finding, Variant: "intercepted",
			Evidence: "a TLS session to the canary presented a key other than the pinned one"}
	}
	return obs.Observation{Result: obs.NotFound, Reason: "no interception seen"}
}

// EGR-1: a lookup of the check's nonce name through the box's own resolver. A logged query at the canary's name
// server is the finding, whatever answer comes back.
func egrDNS(e *env, ck *catalog.Check) obs.Observation {
	dest, nonce, ok := e.canaryReady(ck)
	if !ok {
		return unknownObs("the run has no canary endpoint, nonce or pin for this check")
	}
	a := obs.Attempt{Dest: dest, StartMS: e.ms(), Outcome: "sent"} // find-only: no twin is claimed
	ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
	defer cancel()
	r := &net.Resolver{PreferGo: true}
	r.LookupHost(ctx, nonce+".dns."+e.in.CanaryDomain)
	a.EndMS = e.ms()
	return obs.Observation{Result: obs.Attempted, Attempts: []obs.Attempt{a}}
}

// EGR-5's UDP 53: a query for the nonce's name sent straight to the canary.
func egrUDP(e *env, ck *catalog.Check) obs.Observation {
	dest, nonce, ok := e.canaryReady(ck)
	if !ok {
		return unknownObs("the run has no canary endpoint, nonce or pin for this check")
	}
	a := obs.Attempt{Dest: dest, StartMS: e.ms(), Outcome: "sent"} // find-only: no twin is claimed
	if c, err := net.DialTimeout("udp", dest, attemptTimeout); err == nil {
		c.SetDeadline(time.Now().Add(attemptTimeout))
		if _, err := c.Write(canary.DNSQuery(1, nonce+".udp."+e.in.CanaryDomain)); err != nil {
			a.Outcome = outcomeOf(errnoOf(err))
		}
		c.Read(make([]byte, 512))
		c.Close()
	} else {
		a.Outcome = outcomeOf(errnoOf(err))
	}
	a.EndMS = e.ms()
	return obs.Observation{Result: obs.Attempted, Attempts: []obs.Attempt{a}}
}
