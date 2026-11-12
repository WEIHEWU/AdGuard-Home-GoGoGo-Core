//go:build android_slim

package dnsforward

import "github.com/AdguardTeam/dnsproxy/proxy"

// DNSCryptConfig is an empty stub when DNSCrypt is excluded in Android slim
// builds.
type DNSCryptConfig struct{}

// prepareDNSCrypt is a no-op in Android slim builds.
func (s *Server) prepareDNSCrypt(_ *proxy.Config) {}
