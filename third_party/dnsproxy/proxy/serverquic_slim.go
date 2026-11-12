//go:build android_slim

package proxy

import (
	"context"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
)

// NextProtoDQ is the ALPN token for DoQ.
const NextProtoDQ = "doq"

func (p *Proxy) initQUICListeners(_ context.Context) (err error) {
	if len(p.quicListenAddr) > 0 {
		return errors.Error("dns-over-quic server is disabled in android_slim build")
	}

	return nil
}

func (p *Proxy) quicPacketLoop(_ context.Context, _ *quicEarlyListener, _ syncutil.Semaphore) {}

func (p *Proxy) respondQUIC(_ *DNSContext) error {
	return errors.Error("dns-over-quic is disabled in android_slim build")
}
