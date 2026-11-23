package catalog

import (
	_ "embed"
	"encoding/json"
	"errors"
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
