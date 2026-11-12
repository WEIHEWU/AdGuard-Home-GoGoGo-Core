//go:build android_slim

package upstream

import (
	"net/url"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

type dnsCrypt struct{}

func (*dnsCrypt) Address() string                      { return "" }
func (*dnsCrypt) Exchange(*dns.Msg) (*dns.Msg, error)  { return nil, errors.Error("disabled") }
func (*dnsCrypt) Close() error                         { return nil }

func newDNSCrypt(_ *url.URL, _ *Options) (u Upstream, err error) {
	return nil, errors.Error("dnscrypt upstream is disabled in android_slim build")
}
