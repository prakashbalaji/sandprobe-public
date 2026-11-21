package obs

// ValidExchangeDiagnostic bounds EVD-2's optional diagnostics. Callers must never
// render an arbitrary guest error or promote these labels into network proof.
func ValidExchangeDiagnostic(stage, result string) bool {
	switch stage {
	case "exchange", "proxy_connect", "tls_handshake", "send_marker", "read_reply":
	default:
		return false
	}
	switch result {
	case "completed", "timeout", "closed", "pin_mismatch", "io_error", "unexpected_reply":
		return true
	case "http_status_403", "http_status_407", "http_other_status", "connection_reset", "broken_pipe", "non_tls_reply":
		return true
	}
	return false
}
