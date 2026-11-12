//go:build android_slim

package upstream

import (
	"net/url"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

const (
	// QUICKeepAlivePeriod is preserved for API compatibility.
	QUICKeepAlivePeriod = 20 * time.Second

	// NextProtoDQ is the ALPN token for DoQ.
	NextProtoDQ = "doq"
)

type dnsOverQUIC struct {
	addr *url.URL
}

func (p *dnsOverQUIC) Address() string                     { return p.addr.String() }
func (*dnsOverQUIC) Exchange(*dns.Msg) (*dns.Msg, error)   { return nil, errors.Error("disabled") }
func (*dnsOverQUIC) Close() error                          { return nil }

func newDoQ(_ *url.URL, _ *Options) (u Upstream, err error) {
	return nil, errors.Error("dns-over-quic upstream is disabled in android_slim build")
}
