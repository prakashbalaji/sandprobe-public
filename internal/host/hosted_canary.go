package host

import (
	"context"
	"errors"
	"time"
)

// HostedCanaryURL and its control-key pin are shipped trust anchors (HCN-5, HCN-7).
// Managed collectors and the CLI use the same values; a pin rotation needs a release.
const HostedCanaryURL = "https://control.pub.probe.ac0.dev"
const hostedCanaryPin = "37b7b9ffebd2a547d10eeaf75f791d78a28973c5498d8c6ce2aa521369f620d0"

// PublicCanaryRetention is HCN-4's disclosure, shared by plans and managed reports.
const PublicCanaryRetention = "That canary sees two addresses and keeps both in memory only: the box's public address, " +
	"with this run's random nonces, for the run's lifetime, at most 30 minutes; and the public address of the machine " +
	"running Sandprobe, which reserves and arms the run, in a rate counter for at most an hour. It writes no access log " +
	"and stores nothing (HCN-4)."

// HostedCanaryPins returns a fresh slice, so one caller cannot change another's trust.
func HostedCanaryPins() []string { return []string{hostedCanaryPin} }

// OpenHostedCanary verifies signed status and reserves one assessment slot (MEAS-5).
// It never falls back to an operator canary or accepts an environment trust anchor.
func OpenHostedCanary(ctx context.Context) (*HTTPSCanary, error) {
	return openHostedCanary(ctx, NewHTTPSCanary)
}

func openHostedCanary(ctx context.Context, connect func(context.Context, string, []string) (*HTTPSCanary, error)) (*HTTPSCanary, error) {
	c, err := connect(ctx, HostedCanaryURL, HostedCanaryPins())
	if err != nil || c == nil {
		return nil, errors.New("hosted canary signed status unavailable")
	}
	if err := c.Reserve(ctx, 1); err != nil {
		if CloseHostedCanary(c) != nil {
			return nil, errors.New("hosted canary reservation failed and release is unconfirmed")
		}
		return nil, errors.New("hosted canary reservation unavailable")
	}
	return c, nil
}

// CloseHostedCanary has its own budget even after the workload was cancelled (MEAS-5).
func CloseHostedCanary(c *HTTPSCanary) error {
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return c.Close(ctx)
}
