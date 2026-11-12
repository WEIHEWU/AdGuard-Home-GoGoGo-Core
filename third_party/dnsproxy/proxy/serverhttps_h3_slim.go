//go:build android_slim

package proxy

import (
	"context"
	"net"
	"net/http"

	"github.com/AdguardTeam/golibs/errors"
)

func (p *Proxy) initH3Server(_ *http.ServeMux, _ bool) {}

func (p *Proxy) addH3Listener(_ context.Context, _ *net.TCPAddr) (err error) {
	return errors.Error("http/3 server is disabled in android_slim build")
}

func (p *Proxy) serveH3Listeners() {}
