//go:build android_slim

package proxy

import (
	"context"

	"github.com/AdguardTeam/golibs/errors"
)

func (p *Proxy) initDNSCryptServers(_ context.Context) (err error) {
	if len(p.dnsCryptUDPListenAddr) > 0 || len(p.dnsCryptTCPListenAddr) > 0 {
		return errors.Error("dnscrypt server is disabled in android_slim build")
	}

	return nil
}

func (p *Proxy) startDNSCryptServers(_ context.Context) (err error) { return nil }

func shutdownDNSCryptServers(_ context.Context, _ []*dnsCryptServer) (err error) { return nil }

func (p *Proxy) respondDNSCrypt(_ context.Context, _ *DNSContext) error {
	return errors.Error("dnscrypt is disabled in android_slim build")
}
