//go:build !android_slim

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (p *Proxy) initH3Server(mux *http.ServeMux, enabled bool) {
	if enabled {
		p.h3Server = &http3.Server{
			Handler: mux,
		}
	}
}

func (p *Proxy) addH3Listener(ctx context.Context, tcpAddr *net.TCPAddr) (err error) {
	udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port}

	quicListen, err := p.listenH3(ctx, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start h3 server on %s: %w", udpAddr, err)
	}

	p.h3Listen = append(p.h3Listen, quicListen)

	return nil
}

func (p *Proxy) serveH3Listeners() {
	for _, l := range p.h3Listen {
		go func(l *quic.EarlyListener) { _ = p.h3Server.ServeListener(l) }(l)
	}
}

// listenH3 creates instances of QUIC listeners that will be used for running
// an HTTP/3 server.  addr must not be nil.
func (p *Proxy) listenH3(
	ctx context.Context,
	addr *net.UDPAddr,
) (ln *quic.EarlyListener, err error) {
	tlsConfig := p.tlsConf.Clone()
	tlsConfig.NextProtos = []string{"h3"}
	quicListen, err := quic.ListenAddrEarly(addr.String(), tlsConfig, newServerDoH3Config())
	if err != nil {
		return nil, fmt.Errorf("quic listener: %w", err)
	}

	p.logger.InfoContext(ctx, "listening to h3", "addr", quicListen.Addr())

	return quicListen, nil
}

// newServerDoH3Config creates *quic.Config populated with the default settings.
// This function is supposed to be used for the DoH3 server only.
func newServerDoH3Config() (conf *quic.Config) {
	return &quic.Config{
		MaxIdleTimeout: maxQUICIdleTimeout,
		// Enable 0-RTT by default for all connections on the server-side.
		Allow0RTT: true,
	}
}
