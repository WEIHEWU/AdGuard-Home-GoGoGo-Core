// Package ratelimit provides a rate limiting functionality.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/netutil"
	rate "github.com/beefsack/go-rate"
	"github.com/bluele/gcache"
)

// maxBucketCount caps per-subnet rate-limiter buckets with zero janitor wakeups.
const maxBucketCount = 4096

// middleware implements [proxy.Middleware] with rate limiting functionality.
type middleware struct {
	buckets gcache.Cache
	logger  *slog.Logger

	// mu protects buckets.
	mu *sync.Mutex

	allowlistAddrs netutil.SliceSubnetSet
	ratelimit      uint
	subnetLenIPv4  uint
	subnetLenIPv6  uint
}

// NewMiddleware returns middleware with rate limiting functionality.  c must be
// valid.
func NewMiddleware(c *Config) (m proxy.Middleware) {
	return &middleware{
		logger:         c.Logger,
		mu:             &sync.Mutex{},
		allowlistAddrs: c.AllowlistAddrs,
		ratelimit:      c.Ratelimit,
		subnetLenIPv4:  c.SubnetLenIPv4,
		subnetLenIPv6:  c.SubnetLenIPv6,
	}
}

// type check
var _ proxy.Middleware = (*middleware)(nil)

// Wrap implements the [proxy.Middleware] interface for *middleware.  If the
// client is rate limited, it returns [proxy.ErrDrop] to signal that no response
// should be sent.
func (m *middleware) Wrap(h proxy.Handler) (wrapped proxy.Handler) {
	f := func(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) (err error) {
		if dctx.Proto == proxy.ProtoUDP && m.isRatelimited(dctx.Addr.Addr()) {
			m.logger.Debug("ratelimited based on ip only", "addr", dctx.Addr)

			return proxy.ErrDrop
		}

		return h.ServeDNS(ctx, p, dctx)
	}

	return proxy.HandlerFunc(f)
}

// limiterForIP returns a rate limiter for the specified IP address.
func (m *middleware) limiterForIP(ip netip.Addr) (rl *rate.RateLimiter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.buckets == nil {
		m.buckets = gcache.New(maxBucketCount).LRU().Expiration(time.Hour).Build()
	}

	val, err := m.buckets.Get(ip)
	if err != nil {
		rl = rate.New(int(m.ratelimit), time.Second)
		_ = m.buckets.SetWithExpire(ip, rl, time.Hour)

		return rl
	}

	rl, ok := val.(*rate.RateLimiter)
	if !ok {
		panic(fmt.Sprintf("invalid value found in ratelimit cache: bad type: %T", val))
	}

	return rl
}

// isRatelimited checks if the specified address should be rate limited.
func (m *middleware) isRatelimited(addr netip.Addr) (ok bool) {
	addr = addr.Unmap()
	if m.allowlistAddrs.Contains(addr) {
		return false
	}

	var pref netip.Prefix
	if addr.Is4() {
		pref = netip.PrefixFrom(addr, int(m.subnetLenIPv4))
	} else {
		pref = netip.PrefixFrom(addr, int(m.subnetLenIPv6))
	}
	pref = pref.Masked()

	rl := m.limiterForIP(pref.Addr())
	allow, _ := rl.Try()

	return !allow
}
