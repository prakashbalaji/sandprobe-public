package host

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// MEAS-5: no public service is contacted; the signed-control fixture owns every slot.
func TestManagedHostedCanaryLifecycle(t *testing.T) {
	_, _, fixture := publicCanary(t)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := openHostedCanary(ctx, func(_ context.Context, url string, pins []string) (*HTTPSCanary, error) {
		if url != HostedCanaryURL || !slices.Equal(pins, HostedCanaryPins()) {
			t.Fatal("managed collector changed the shipped trust anchors")
		}
		return fixture, nil
	})
	if err != nil || c != fixture || len(c.pending) != 1 {
		t.Fatalf("assessment slot not reserved: %v", err)
	}
	cancel()
	if err := CloseHostedCanary(c); err != nil || len(c.pending)+len(c.runs)+len(c.doubt) != 0 {
		t.Fatalf("cancelled workload did not release its slot: %v", err)
	}
	pins := HostedCanaryPins()
	pins[0] = "changed by caller"
	if HostedCanaryPins()[0] != hostedCanaryPin {
		t.Fatal("caller changed shared trust")
	}
}

func TestManagedHostedCanaryFailureIsClosedAndSanitized(t *testing.T) {
	_, err := openHostedCanary(context.Background(), func(context.Context, string, []string) (*HTTPSCanary, error) {
		return nil, errors.New("untrusted credential-shaped diagnostic")
	})
	if err == nil || strings.Contains(err.Error(), "credential") {
		t.Fatal("status failure was accepted or leaked a diagnostic")
	}
	_, _, c := publicCanary(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := openHostedCanary(ctx, func(context.Context, string, []string) (*HTTPSCanary, error) { return c, nil }); err == nil || got != nil || len(c.doubt) != 0 {
		t.Fatal("failed reservation was accepted or its ambiguous slot was retained")
	}
	if err := c.Reserve(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	original := c.Client
	c.Client = &http.Client{Transport: failing{}}
	if CloseHostedCanary(c) == nil || len(c.doubt) != 1 {
		t.Fatal("unconfirmed release was reported as successful")
	}
	c.Client = original
	if err := CloseHostedCanary(c); err != nil {
		t.Fatal(err)
	}
}
