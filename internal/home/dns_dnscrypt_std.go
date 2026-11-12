//go:build !android_slim

package home

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtls"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/golibs/errors"
	yaml "go.yaml.in/yaml/v4"
)

func newDNSCryptConfig(
	extTLSConf *aghtls.ExtendedTLSConfig,
	addrs []netip.Addr,
) (dnsCryptConf *dnsforward.DNSCryptConfig, err error) {
	if extTLSConf.PortDNSCrypt == 0 {
		return nil, nil
	}

	if extTLSConf.DNSCryptConfigFile == "" {
		return nil, fmt.Errorf("dnscrypt_config_file: %w", errors.ErrEmptyValue)
	}

	f, err := os.Open(extTLSConf.DNSCryptConfigFile)
	if err != nil {
		return nil, fmt.Errorf("opening dnscrypt config: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	rc := &dnscrypt.ResolverConfig{}
	err = yaml.NewDecoder(f).Decode(rc)
	if err != nil {
		return nil, fmt.Errorf("decoding dnscrypt config: %w", err)
	}

	err = rc.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating dnscrypt config: %w", err)
	}

	cert, err := rc.NewCert()
	if err != nil {
		return nil, fmt.Errorf("creating dnscrypt cert: %w", err)
	}

	return &dnsforward.DNSCryptConfig{
		ResolverCert:   cert,
		UDPListenAddrs: ipsToUDPAddrs(addrs, extTLSConf.PortDNSCrypt),
		TCPListenAddrs: ipsToTCPAddrs(addrs, extTLSConf.PortDNSCrypt),
		ProviderName:   rc.ProviderName,
	}, nil
}
