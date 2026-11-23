package catalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

//go:embed upload_hosts.json
var uploadHostPolicy []byte

// ParseUploadHosts is the common managed-runner flag parser; no environment default.
func ParseUploadHosts(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	hosts := strings.Split(value, ",")
	if err := ValidateUploadHosts(hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// ValidateUploadHosts enforces MEAS-6's finite, explicit workload destinations.
// Empty is the default-off choice; execution requires a nonempty list.
func ValidateUploadHosts(hosts []string) error {
	if len(hosts) > 4 {
		return errors.New("upload hosts takes at most four distinct shipped workload names")
	}
	seen := map[string]bool{}
	var allowed []string
	if json.Unmarshal(uploadHostPolicy, &allowed) != nil || len(allowed) == 0 {
		return errors.New("shipped upload host policy unavailable")
	}
	for _, h := range hosts {
		found := false
		for _, name := range allowed {
			found = found || h == name
		}
		if !found {
			return errors.New("upload hosts accepts only exact shipped workload names")
		}
		if seen[h] {
			return errors.New("upload hosts contains a duplicate")
		}
		seen[h] = true
	}
	return nil
}

// UploadTarget is MEAS-7's optional host-frozen public endpoint; an invalid Address
// means the legacy name-only target, resolved by the guest under MEAS-6.
type UploadTarget struct {
	Host    string
	Address netip.Addr
}

func ParseUploadTargets(targets []string) ([]UploadTarget, error) {
	if len(targets) > 4 {
		return nil, errors.New("too many approved workload endpoint bindings")
	}
	var result []UploadTarget
	var names []string
	for _, target := range targets {
		name, address, bound := strings.Cut(target, "=")
		t := UploadTarget{Host: name}
		if bound {
			ip, err := netip.ParseAddr(address)
			if err != nil || !PublicUploadIP(ip) || ip.Unmap().String() != address {
				return nil, errors.New("invalid approved workload endpoint binding")
			}
			t.Address = ip.Unmap()
		}
		names = append(names, name)
		result = append(result, t)
	}
	if err := ValidateUploadHosts(names); err != nil {
		return nil, err
	}
	return result, nil
}

func ValidateUploadTargets(targets []string) error { _, err := ParseUploadTargets(targets); return err }

// BindUploadHosts copies the approved selection and binds only its explicitly
// supplied workload-policy addresses. No resolver or network operation occurs.
func BindUploadHosts(hosts []string, addresses map[string]string) ([]string, error) {
	if err := ValidateUploadHosts(hosts); err != nil {
		return nil, err
	}
	for host := range addresses {
		selected := false
		for _, h := range hosts {
			selected = selected || h == host
		}
		if !selected {
			return nil, errors.New("endpoint binding is outside the approved workload host selection")
		}
	}
	targets := append([]string(nil), hosts...)
	for i, h := range hosts {
		if address, ok := addresses[h]; ok {
			targets[i] = h + "=" + address
		}
	}
	if err := ValidateUploadTargets(targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// PublicUploadIP is the shared MEAS-6/7 no-infrastructure-address boundary.
func PublicUploadIP(ip netip.Addr) bool {
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
