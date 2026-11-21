// stub plays the services the fixtures plant beside a box (Tests): instance metadata on :80 with one role, whose
// credential document holds only sandprobe-fake and must never be asked for; a TLS endpoint on :443 standing in for
// the Kubernetes API; on UDP 53 a resolver that answers every name itself, NXDOMAIN, forwarding nothing (the
// network fixture's local resolver); and on :3128 a proxy that refuses every request, 403 (the deceptive fixture). It logs every request it gets, one per line, so a fixture can check what was asked.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout) // docker logs keeps the streams apart; the fixture reads stdout
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("http %s %s", r.Method, r.URL.Path)
		switch {
		case r.Method == "PUT" && r.URL.Path == "/latest/api/token":
			fmt.Fprint(w, "stub-imds-session")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			fmt.Fprint(w, "sandprobe-fixture-role")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/sandprobe-fixture-role":
			fmt.Fprint(w, `{"AccessKeyId":"sandprobe-fake","SecretAccessKey":"sandprobe-fake"}`)
		default:
			http.NotFound(w, r)
		}
	})
	go func() { log.Fatal(http.ListenAndServe(":80", nil)) }()
	go dns()
	go proxy403()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes"},
		DNSNames: []string{"kubernetes.default.svc"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", ":443", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		log.Fatal(err)
	}
	log.Print("stub ready")
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if err := c.(*tls.Conn).Handshake(); err == nil {
				log.Printf("tls handshake from %s", c.RemoteAddr())
			}
			if n, _ := c.Read(make([]byte, 1)); n > 0 { // the probe sends no request; one would show here
				log.Printf("tls request from %s", c.RemoteAddr())
			}
		}(c)
	}
}

// dns answers every query NXDOMAIN itself, forwarding nothing.
func dns() {
	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			continue
		}
		q := buf[:n]
		i := 12
		var name []string
		for i < n && q[i] != 0 && i+1+int(q[i]) <= n {
			name = append(name, string(q[i+1:i+1+int(q[i])]))
			i += 1 + int(q[i])
		}
		end := i + 5 // the root label, type and class
		if end > n {
			continue
		}
		log.Printf("dns %s", strings.Join(name, "."))
		r := append([]byte(nil), q[:end]...)
		r[2], r[3] = 0x80|q[2]&0x01, 0x03 // a response, NXDOMAIN
		r[6], r[7], r[8], r[9], r[10], r[11] = 0, 0, 0, 0, 0, 0
		pc.WriteTo(r, from)
	}
}

// proxy403 refuses every request with a 403, logging each request's whole head, so a fixture can see exactly what
// reached the proxy (credentials included, if any ever did).
func proxy403() {
	ln, err := net.Listen("tcp", ":3128")
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(c)
			head, _ := r.ReadString('\n')
			var rest strings.Builder
			for {
				l, err := r.ReadString('\n')
				rest.WriteString(l)
				if err != nil || l == "\r\n" || l == "\n" {
					break
				}
			}
			log.Printf("proxy %q %q", strings.TrimSpace(head), rest.String())
			io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		}(c)
	}
}
