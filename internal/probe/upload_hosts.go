//go:build linux

package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

func egrUploadHosts(e *env, _ *catalog.Check) obs.Observation {
	return uploadExposure(e.in.Targets["EGR-6"], net.DefaultResolver.LookupNetIP,
		func(ctx context.Context, host string, ip netip.Addr) error {
			return uploadHandshake(ctx, net.JoinHostPort(ip.String(), "443"), host, nil)
		})
}

// MEAS-6: fixed names, one resolution and at most one literal-address dial each.
// Resolver or transport failures remain unknown; none is a negative proof.
func uploadExposure(hosts []string, lookup func(context.Context, string, string) ([]netip.Addr, error), handshake func(context.Context, string, netip.Addr) error) obs.Observation {
	if len(hosts) == 0 || catalog.ValidateUploadHosts(hosts) != nil {
		return unknownObs("no valid approved workload-host list")
	}
	var verified []string
	for _, host := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
		ips, err := lookup(ctx, "ip", host)
		valid := err == nil && len(ips) > 0 && len(ips) <= 16
		for _, ip := range ips {
			valid = valid && uploadPublicIP(ip)
		}
		if valid && ctx.Err() == nil {
			chosen := ips[0].Unmap()
			for _, ip := range ips {
				if ip.Unmap().Is4() {
					chosen = ip.Unmap() // Same IPv4 preference as the managed workload's network policy.
					break
				}
			}
			if handshake(ctx, host, chosen) == nil {
				verified = append(verified, host)
			}
		}
		cancel()
	}
	if len(verified) == 0 {
		return unknownObs("no certificate-verified TLS handshake to the approved workload hosts; DNS or transport failures prove no refusal")
	}
	return obs.Observation{Result: obs.Finding, Variant: "handshake", Evidence: fmt.Sprintf("Certificate-verified TLS handshake to %s; %d approved destinations unproven. No HTTP request or upload was attempted.", strings.Join(verified, ", "), len(hosts)-len(verified))}
}

func uploadPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Exclude translation/tunneling ranges that could route a public-looking IPv6
	// address to a private IPv4 endpoint. Ordinary IPv6 unicast is in 2000::/3.
	if ip.Is6() && (!netip.MustParsePrefix("2000::/3").Contains(ip) || netip.MustParsePrefix("2002::/16").Contains(ip) || netip.MustParsePrefix("2001::/32").Contains(ip)) {
		return false
	}
	for _, block := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(block).Contains(ip) {
			return false
		}
	}
	return true
}

// uploadHandshake verifies TLS then closes without sending any HTTP or application data.
// roots is nil in production. The production caller always selects literal public IP:443.
func uploadHandshake(ctx context.Context, address, name string, roots *x509.CertPool) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	// Close the underlying transport, avoiding any extra TLS-close write budget.
	defer c.Close()
	t := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots})
	return t.HandshakeContext(ctx)
}
