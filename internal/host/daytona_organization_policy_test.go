package host

import (
	"context"
	"encoding/json"
	"errors"
	"sandprobe/internal/obs"
	"strings"
	"testing"
)

func TestDaytonaOrganizationPolicyIsOptionalAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name, wire, result, reason string
		failed                     bool
	}{
		{"true", `{"result":"observed","reason":"matching_organization_readback","limited_network_egress":true}`, "observed", "matching_organization_readback", false},
		{"false", `{"result":"observed","reason":"matching_organization_readback","limited_network_egress":false}`, "observed", "matching_organization_readback", false},
		{"denied", `{"result":"unknown","reason":"permission_denied"}`, "unknown", "permission_denied", false},
		{"binding", `{"result":"unknown","reason":"binding_unverified"}`, "unknown", "binding_unverified", false},
		{"missing", `{"result":"observed","reason":"matching_organization_readback"}`, "unknown", "readback_unavailable", false},
		{"string", `{"result":"observed","reason":"matching_organization_readback","limited_network_egress":"false"}`, "unknown", "readback_unavailable", false},
		{"raw", `{"result":"unknown","reason":"NEVER_EXPORT_API_KEY"}`, "unknown", "readback_unavailable", false},
		{"runtime", "", "unknown", "readback_unavailable", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := workloadDaytonaFixture(t)
			calls := 0
			b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
				calls++
				if in["op"] != "organization_network_policy" || in["id"] != b.ID() || in["organization"] != b.journal.Organization || in["born"] != b.journal.Born || in["nonce"] != b.journal.Nonce {
					t.Fatal("readback not bound to owned sandbox")
				}
				if tc.failed {
					return nil, errors.New("NEVER_EXPORT_API_KEY")
				}
				return []byte(tc.wire), nil
			}
			e := b.OrganizationNetworkPolicy(context.Background(), strings.Repeat("a", 16), strings.Repeat("b", 64))
			if calls != 1 || e.Result != tc.result || e.Reason != tc.reason || e.EnforcementObserved || obs.ValidateOrganizationNetworkPolicy(e) != nil {
				t.Fatal("wrong optional evidence", e)
			}
			wire, _ := json.Marshal(e)
			if strings.Contains(string(wire), "NEVER_EXPORT") || strings.Contains(string(wire), `"organization"`) {
				t.Fatal("private raw details exported")
			}
			if b.gone || len(b.Calls) != 1 {
				t.Fatal("readback altered lifecycle or omitted call")
			}
		})
	}
	b, _ := workloadDaytonaFixture(t)
	b.gone = true
	b.client.runtime = func(context.Context, map[string]any) ([]byte, error) {
		t.Fatal("queried a deleted sandbox")
		return nil, nil
	}
	if e := b.OrganizationNetworkPolicy(context.Background(), strings.Repeat("a", 16), strings.Repeat("b", 64)); e.Result != "unknown" || e.Reason != "binding_unverified" {
		t.Fatal("gone sandbox readback", e)
	}
}

func TestDaytonaOrganizationPolicyFailureReasons(t *testing.T) {
	for _, reason := range []string{"authentication_failed", "endpoint_unavailable", "rate_limited", "request_rejected", "service_unavailable", "request_timeout", "transport_unavailable", "response_schema_invalid"} {
		b, _ := workloadDaytonaFixture(t)
		calls := 0
		b.client.runtime = func(_ context.Context, in map[string]any) ([]byte, error) {
			calls++
			if in["op"] != "organization_network_policy" || in["id"] != b.ID() || in["organization"] != b.journal.Organization {
				t.Fatal("unbound policy read")
			}
			return json.Marshal(map[string]string{"result": "unknown", "reason": reason})
		}
		e := b.OrganizationNetworkPolicy(context.Background(), strings.Repeat("a", 16), strings.Repeat("b", 64))
		if calls != 1 || e.Result != "unknown" || e.Reason != reason || e.LimitedNetworkEgress != nil || e.EnforcementObserved {
			t.Fatalf("failure altered policy semantics: %+v", e)
		}
	}
}
