//go:build android_slim

package proxy

import (
	"crypto/tls"
	"net"
)

type (
	dnsCryptCert           struct{}
	dnsCryptServer         struct{}
	dnsCryptResponseWriter interface{}
	quicConn               struct{}
	quicStream             struct{}
	quicEarlyListener      struct{}
	quicTransport          struct{}
	http3Server            struct{}
	quicConnState          struct{ TLS tls.ConnectionState }
)

func (*quicConn) ConnectionState() quicConnState { return quicConnState{} }
func (*dnsCryptServer) LocalAddr() net.Addr      { return nil }
func (*quicEarlyListener) Addr() net.Addr        { return nil }
func (*quicEarlyListener) Close() error          { return nil }
func (*quicTransport) Close() error              { return nil }
func (*http3Server) Close() error                { return nil }
