package host

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"sandprobe/internal/obs"
)

// SaveMeasurementPrerequisites retains the already collected original-agent survey
// without any provider calls or changes to the assessment (EVD-22).
func SaveMeasurementPrerequisites(folder string, r *Run) error {
	if r == nil || r.Survey == nil {
		return errors.New("prerequisite survey unavailable")
	}
	p := obs.MeasurementPrerequisites{Schema: obs.MeasurementPrerequisitesSchema,
		RunID: r.Manifest.RunID, Nonce: r.Manifest.Nonce, BoxID: r.Manifest.BoxID, ProbeSHA256: r.Manifest.ProbeSHA256,
		Proxy: "not_configured", ProxyCredentials: "not_applicable", ProxyProtocol: "not_applicable", KubeAPI: "absent", Vsock: "absent"}
	if proxy := r.Survey.Proxy; proxy != nil {
		p.ProxyCredentials = "unknown"
		p.ProxyProtocol = "unknown"
		if !proxy.Malformed {
			p.ProxyCredentials = "absent"
			if proxy.Credentials {
				p.ProxyCredentials = "present_not_used"
			}
			p.ProxyProtocol = "unsupported"
			if proxy.Scheme == "http" {
				p.ProxyProtocol = "http_connect"
			}
		}
		switch {
		case proxy.Malformed:
			p.Proxy = "malformed"
		case local(proxy.Addr) && !r.Manifest.AllowLocalProxy:
			p.Proxy = "local_unapproved"
		default:
			p.Proxy = "configured"
		}
	}
	if r.Survey.KubeAPI != "" {
		p.KubeAPI = "present"
	}
	if r.Survey.Vsock {
		p.Vsock = "present"
	}
	if !p.Valid() {
		return errors.New("prerequisite binding unavailable")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return errors.New("prerequisite encoding failed")
	}
	f, err := os.OpenFile(filepath.Join(folder, "measurement-prerequisites.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("prerequisite destination unavailable")
	}
	defer f.Close()
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return errors.New("prerequisite write failed")
	}
	if f.Sync() != nil {
		return errors.New("prerequisite sync failed")
	}
	if f.Close() != nil {
		return errors.New("prerequisite close failed")
	}
	return nil
}
