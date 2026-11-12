//go:build android_slim

package home

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
)

// noopChecker satisfies [filtering.Checker] without instantiating cloud DoH
// upstreams (family.adguard-dns.com) or hashprefix SHA-256 caches.
type noopChecker struct{}

func (noopChecker) Check(_ string) (block bool, err error) {
	return false, nil
}

func setupCloudFilteringCheckers(
	_ context.Context,
	_ *slog.Logger,
	conf *filtering.Config,
) (err error) {
	conf.SafeBrowsingChecker = noopChecker{}
	if conf.SafeBrowsingBlockHost == "" {
		conf.SafeBrowsingBlockHost = defaultSafeBrowsingBlockHost
	}

	conf.ParentalControlChecker = noopChecker{}
	if conf.ParentalBlockHost == "" {
		conf.ParentalBlockHost = defaultParentalBlockHost
	}

	return nil
}

func isUpdateEnabled(
	ctx context.Context,
	l *slog.Logger,
	_ *options,
	_ bool,
) (ok bool) {
	l.DebugContext(ctx, "self-updates are disabled in android_slim builds")

	return false
}
