//go:build !android_slim

package home

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghslog"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/hashprefix"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

func setupCloudFilteringCheckers(
	ctx context.Context,
	baseLogger *slog.Logger,
	conf *filtering.Config,
) (err error) {
	const (
		dnsTimeout = 3 * time.Second

		sbService                 = "safe_browsing"
		defaultSafeBrowsingServer = `https://family.adguard-dns.com/dns-query`
		sbTXTSuffix               = `sb.dns.adguard.com.`

		pcService             = "parental_control"
		defaultParentalServer = `https://family.adguard-dns.com/dns-query`
		pcTXTSuffix           = `pc.dns.adguard.com.`
	)

	cacheTime := time.Duration(conf.CacheTime) * time.Minute

	upsOpts := &upstream.Options{
		Logger:  aghslog.NewForUpstream(baseLogger, aghslog.UpstreamTypeService),
		Timeout: dnsTimeout,
		Bootstrap: upstream.StaticResolver{
			netip.AddrFrom4([4]byte{94, 140, 14, 15}),
			netip.AddrFrom4([4]byte{94, 140, 14, 16}),
			netip.AddrFrom16([16]byte{42, 16, 80, 192, 12: 186, 209, 0, 255}),
			netip.AddrFrom16([16]byte{42, 16, 80, 192, 12: 186, 210, 0, 255}),
		},
	}

	sbUps, err := upstream.AddressToUpstream(defaultSafeBrowsingServer, upsOpts)
	if err != nil {
		return fmt.Errorf("converting safe browsing server: %w", err)
	}

	conf.SafeBrowsingChecker = hashprefix.New(&hashprefix.Config{
		Logger:    baseLogger.With(slogutil.KeyPrefix, sbService),
		Upstream:  sbUps,
		TXTSuffix: sbTXTSuffix,
		CacheTime: cacheTime,
		CacheSize: conf.SafeBrowsingCacheSize,
	})

	if conf.SafeBrowsingBlockHost == "" {
		conf.SafeBrowsingBlockHost = defaultSafeBrowsingBlockHost
	}

	parUps, err := upstream.AddressToUpstream(defaultParentalServer, upsOpts)
	if err != nil {
		return fmt.Errorf("converting parental server: %w", err)
	}

	conf.ParentalControlChecker = hashprefix.New(&hashprefix.Config{
		Logger:    baseLogger.With(slogutil.KeyPrefix, pcService),
		Upstream:  parUps,
		TXTSuffix: pcTXTSuffix,
		CacheTime: cacheTime,
		CacheSize: conf.ParentalCacheSize,
	})

	if conf.ParentalBlockHost == "" {
		conf.ParentalBlockHost = defaultParentalBlockHost
	}

	return nil
}

func isUpdateEnabled(
	ctx context.Context,
	l *slog.Logger,
	opts *options,
	isCustomURL bool,
) (ok bool) {
	if opts.disableUpdate {
		l.DebugContext(ctx, "updates are disabled by command-line option")
		return false
	}

	if isCustomURL {
		l.DebugContext(ctx, "updates are enabled because custom url is used")
		return true
	}

	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" {
		l.DebugContext(ctx, "updates are disabled for this platform", "goos", runtime.GOOS, "goarch", runtime.GOARCH)
		return false
	}

	l.DebugContext(ctx, "updates are enabled for the mod builds")
	return true
}
