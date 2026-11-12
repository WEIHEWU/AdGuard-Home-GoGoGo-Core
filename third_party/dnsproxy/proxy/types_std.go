//go:build !android_slim

package proxy

import (
	"github.com/AdguardTeam/dnscrypt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type (
	dnsCryptCert           = dnscrypt.Certificate
	dnsCryptServer         = dnscrypt.Server
	dnsCryptResponseWriter = dnscrypt.ResponseWriter
	quicConn               = quic.Conn
	quicStream             = quic.Stream
	quicEarlyListener      = quic.EarlyListener
	quicTransport          = quic.Transport
	http3Server            = http3.Server
)
