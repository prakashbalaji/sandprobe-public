package obs

// MeasurementPrerequisites is EVD-22's separate, guest-reported survey context.
// It is neither a proof nor an addition to the public report/evidence schemas.
type MeasurementPrerequisites struct {
	Schema           string `json:"schema"`
	RunID            string `json:"run_id"`
	Nonce            string `json:"nonce"`
	BoxID            string `json:"box_id"`
	ProbeSHA256      string `json:"probe_sha256"`
	Proxy            string `json:"proxy"`
	ProxyCredentials string `json:"proxy_credentials"`
	ProxyProtocol    string `json:"proxy_protocol"`
	KubeAPI          string `json:"kube_api"`
	Vsock            string `json:"vsock"`
}

const MeasurementPrerequisitesSchema = "sandprobe.measurement-prerequisites/1"

func (p MeasurementPrerequisites) Valid() bool {
	if p.Schema != MeasurementPrerequisitesSchema || p.RunID == "" || p.Nonce == "" || p.BoxID == "" || len(p.ProbeSHA256) != 64 {
		return false
	}
	for _, c := range p.ProbeSHA256 {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	switch p.Proxy {
	case "not_configured", "configured", "malformed", "local_unapproved":
	default:
		return false
	}
	switch p.ProxyCredentials {
	case "not_applicable", "unknown", "absent", "present_not_used":
	default:
		return false
	}
	switch p.ProxyProtocol {
	case "not_applicable", "unknown", "http_connect", "unsupported":
	default:
		return false
	}

	switch p.Proxy {
	case "not_configured":
		if p.ProxyCredentials != "not_applicable" || p.ProxyProtocol != "not_applicable" {
			return false
		}
	case "malformed":
		if p.ProxyCredentials != "unknown" || p.ProxyProtocol != "unknown" {
			return false
		}
	default:
		if (p.ProxyCredentials != "absent" && p.ProxyCredentials != "present_not_used") || (p.ProxyProtocol != "http_connect" && p.ProxyProtocol != "unsupported") {
			return false
		}
	}
	for _, state := range []string{p.KubeAPI, p.Vsock} {
		if state != "present" && state != "absent" {
			return false
		}
	}
	return true
}
