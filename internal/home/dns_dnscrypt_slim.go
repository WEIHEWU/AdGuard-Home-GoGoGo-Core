//go:build android_slim

package home

import (
	"net/netip"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/aghtls"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
)

func newDNSCryptConfig(
	extTLSConf *aghtls.ExtendedTLSConfig,
	_ []netip.Addr,
) (dnsCryptConf *dnsforward.DNSCryptConfig, err error) {
	if extTLSConf.PortDNSCrypt == 0 {
		return nil, nil
	}

	return nil, aghos.Unsupported("dnscrypt")
}
