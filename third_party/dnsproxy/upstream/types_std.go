//go:build !android_slim

package upstream

import (
	"context"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
)

type dnsCryptCert = dnscrypt.Certificate

// QUICTracer creates [qlogwriter.Trace] instances for QUIC connection tracing.
type QUICTracer interface {
	// TraceForConnection creates a [qlogwriter.Trace] specific for a given
	// role and connection ID.
	TraceForConnection(
		ctx context.Context,
		isClient bool,
		connID quic.ConnectionID,
	) (trace qlogwriter.Trace)
}
