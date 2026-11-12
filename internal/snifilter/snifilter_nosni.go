//go:build nosni

package snifilter

import (
	"context"
	"time"
)

// Filter is a zero-overhead no-op SNI filter used when built with -tags=nosni
// (pure DNS firewall profile).  It validates YAML sni_filter parameters for
// 100% schema_version 34 compatibility without opening NFQUEUE/netlink sockets.
type Filter struct{}

// New validates c.Params and returns a no-op *Filter.
func New(c *Config) (f *Filter, err error) {
	if err = c.Params.Validate(); err != nil {
		return nil, err
	}

	return &Filter{}, nil
}

// SetProtectionStatus is a no-op under nosni.
func (f *Filter) SetProtectionStatus(_ bool, _ *time.Time) {}

// Start is a silent no-op under nosni so blocking_mode: strong continues to
// serve fast NODATA DNS responses without kernel NFQUEUE hooks.
func (f *Filter) Start(_ context.Context) (err error) {
	return nil
}

// Shutdown is a no-op under nosni.
func (f *Filter) Shutdown(_ context.Context) {}
