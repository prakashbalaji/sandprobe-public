// sandprobe-canary runs the canary (SBX-11): TLS echo on 443, plain TCP on 22, 80 and 8080, and DNS on UDP 53. It
// counts only the nonces the host armed, and answers the host on a unix socket only the host reaches (docker exec
// into the fixture canary, or SSM on the live one): sandprobe-canary -ctl status|arm|query|disarm. The box's network
// never sees that socket. With -public-control it also serves HCN-1's public path on 443, by SNI, every answer signed
// by the control key in -control-key (make one with -make-control-key).
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"sandprobe/internal/canary"
	"sandprobe/internal/canarycontrol"
)

func main() {
	domain := flag.String("domain", "sandprobe.test", "the canary's domain")
	control := flag.String("control", "/run/sandprobe-canary.sock", "the control socket")
	op := flag.String("ctl", "", "ask the running canary: status, arm, query or disarm; print its answer as JSON and exit")
	run := flag.String("run", "", "the run to arm, query or disarm")
	ttl := flag.Int("ttl", 0, "arm: the run's lifetime in seconds")
	wants := flag.String("wants", "", "arm: the run's nonces, as nonce/proto/port,...")
	public := flag.String("public-control", "", "serve the public control path (HCN-1) on 443 for this name, e.g. control.probe.ac0.dev")
	acmeCache := flag.String("acme-cache", "/var/lib/sandprobe-canary/acme", "with -public-control: where its Let's Encrypt account and certificate are kept")
	controlKey := flag.String("control-key", "/var/lib/sandprobe-canary/control.key", "with -public-control: the key that signs every answer, whose pin hosts hold (HCN-1)")
	makeKey := flag.String("make-control-key", "", "write a new control key to this file, print its pin, and exit")
	publicAddr := flag.String("public-addr", "", "with -public-control: the canary's public receipt address, named in every signed answer (HCN-1)")
	pinFile := flag.String("control-pin-file", "", "with -public-control: write the control key's pin here (public), for the deploy to read")
	staging := flag.Bool("acme-staging", false, "with -public-control: take the certificate from Let's Encrypt's staging service (a dry run)")
	flag.Parse()

	if *makeKey != "" {
		pin, err := canarycontrol.MakeKey(*makeKey)
		if err != nil {
			fail(err)
		}
		fmt.Println(pin)
		return
	}

	if *op != "" {
		q := canary.Request{Op: *op, Run: *run, TTL: *ttl}
		if *wants != "" {
			ws, err := parseWants(*wants)
			if err != nil {
				fail(err)
			}
			q.Wants = ws
		}
		a, err := canary.Ask("unix", *control, q)
		if err != nil {
			fail(err)
		}
		json.NewEncoder(os.Stdout).Encode(a)
		return
	}
	c, err := canary.New(*domain)
	if err != nil {
		fail(err)
	}
	if *public != "" { // HCN-1: a WebPKI certificate for the control name only, from Let's Encrypt over TLS-ALPN-01 on 443
		key, err := canarycontrol.LoadKey(*controlKey)
		if err != nil {
			fail(err)
		}
		ip, err := netip.ParseAddr(*publicAddr)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			fail(errors.New("-public-control needs -public-addr, the canary's public IP"))
		}
		c.PublicAddr = ip.String()
		if *pinFile != "" {
			pin, err := canarycontrol.PinOf(&key.PublicKey)
			if err != nil || os.WriteFile(*pinFile, []byte(pin+"\n"), 0o644) != nil {
				fail(errors.New("couldn't write the control pin file"))
			}
		}
		canary.SetPublicBounds()
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(*public), Cache: autocert.DirCache(*acmeCache)}
		if *staging {
			m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
		}
		canarycontrol.Attach(c, *public, &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1", acme.ALPNProto}}, key)
	}
	errs := make(chan error)
	listen := func(port int, serve func(net.Listener, int) error) {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			fail(err)
		}
		go func() { errs <- serve(ln, port) }()
	}
	listen(443, c.ServeTLS)
	for _, p := range []int{22, 80, 8080} {
		listen(p, c.ServeTCP)
	}
	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		fail(err)
	}
	go func() { errs <- c.ServeDNS(pc) }()
	os.Remove(*control)
	ctl, err := net.Listen("unix", *control)
	if err != nil {
		fail(err)
	}
	if err := os.Chmod(*control, 0o600); err != nil {
		fail(err)
	}
	go func() { errs <- c.ServeControl(ctl) }()
	go func() { // an expired run is freed within 30 s, even with nothing arriving
		for range time.Tick(30 * time.Second) {
			c.Sweep()
		}
	}()
	fmt.Println("canary ready, pin", c.Pin)
	fail(<-errs)
}

// parseWants reads nonce/proto/port,...; the canary checks each one again when it arms.
func parseWants(s string) ([]canary.Want, error) {
	var ws []canary.Want
	for _, w := range strings.Split(s, ",") {
		f := strings.Split(w, "/")
		if len(f) != 3 {
			return nil, errors.New("want nonce/proto/port, got " + w)
		}
		port, err := strconv.Atoi(f[2])
		if err != nil {
			return nil, err
		}
		ws = append(ws, canary.Want{Nonce: f[0], Proto: f[1], Port: port})
	}
	return ws, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sandprobe-canary:", err)
	os.Exit(1)
}
