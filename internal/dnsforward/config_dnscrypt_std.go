//go:build !android_slim

package dnsforward

import (
	"net"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnsproxy/proxy"
)

// DNSCryptConfig contains the configuration settings for a DNSCrypt server.
type DNSCryptConfig struct {
	// ResolverCert is the certificate used for DNSCrypt connections.  It is not
	// nil if there is at least one UDP or TCP address present.
	ResolverCert *dnscrypt.Certificate

	// UDPListenAddrs are the addresses to listen on for DNSCrypt UDP
	// connections.
	UDPListenAddrs []*net.UDPAddr

	// TCPListenAddrs are the addresses to listen on for DNSCrypt TCP
	// connections.
	TCPListenAddrs []*net.TCPAddr

	// ProviderName is the name of the DNSCrypt provider.  It is not empty if
	// there is at least one UDP or TCP address present.
	ProviderName string
}

// prepareDNSCrypt sets up the DNSCrypt configuration for the DNS proxy.
func (s *Server) prepareDNSCrypt(proxyConf *proxy.Config) {
	dnsCryptConf := s.conf.TLSConf.DNSCryptConf
	if dnsCryptConf == nil {
		return
	}

	proxyConf.DNSCryptUDPListenAddr = dnsCryptConf.UDPListenAddrs
	proxyConf.DNSCryptTCPListenAddr = dnsCryptConf.TCPListenAddrs
	proxyConf.DNSCryptProviderName = dnsCryptConf.ProviderName
	proxyConf.DNSCryptResolverCert = dnsCryptConf.ResolverCert
}
