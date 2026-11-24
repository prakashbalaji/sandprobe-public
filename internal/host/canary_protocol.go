package host

import (
	"context"
	"errors"
	"sandprobe/internal/canary"
	"slices"
)

// RequireHTTPMarkerV1 performs only trusted canary-control preflight, with no guest traffic.
func RequireHTTPMarkerV1(ctx context.Context, c Canary) error {
	a, err := c.Ask(ctx, canary.Request{Op: "status"})
	if err != nil || !a.OK {
		return errors.New("HTTP marker canary status unavailable")
	}
	if _, err = canary.KeyOf(a); err != nil {
		return errors.New("HTTP marker canary key unavailable")
	}
	return requireHTTPMarkerForPin(ctx, c, a.Pin)
}
func requireHTTPMarkerForPin(ctx context.Context, c Canary, pin string) error {
	a, err := c.Ask(ctx, canary.Request{Op: "protocols"})
	if err != nil || !a.OK || a.Pin != pin || !slices.Contains(a.Protocols, canary.HTTPMarkerV1) {
		return errors.New("HTTP marker canary capability not verified")
	}
	if _, err = canary.KeyOf(a); err != nil {
		return errors.New("HTTP marker canary capability key unavailable")
	}
	return nil
}
