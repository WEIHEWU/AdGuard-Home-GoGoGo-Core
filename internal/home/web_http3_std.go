//go:build !android_slim

package home

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/quic-go/quic-go/http3"
)

type http3ServerHolder = *http3.Server

// mustStartHTTP3 initializes and starts HTTP3 server.
func (web *webAPI) mustStartHTTP3(ctx context.Context, address string) {
	defer slogutil.RecoverAndExit(ctx, web.logger, osutil.ExitCodeFailure)

	logger := web.baseLogger.With(loggerKeyServer, "http3")
	hdlr := web.wrapMux(logger)

	web.httpsServer.server3 = &http3.Server{
		Addr:      address,
		TLSConfig: web.tlsManager.TLSConfig(),
		Handler:   hdlr,
	}

	web.logger.DebugContext(ctx, "starting http/3 server")
	err := web.httpsServer.server3.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		cleanupAlways(ctx, logger, web.pidFilePath)

		panic(fmt.Errorf("http3: %w", err))
	}
}

// shutdownSrv3 shuts down srv and logs the error, if any.
func shutdownSrv3(ctx context.Context, l *slog.Logger, srv *http3.Server) {
	defer slogutil.RecoverAndLog(ctx, l)

	if srv == nil {
		return
	}

	err := srv.Close()
	if err == nil {
		return
	}

	lvl := slog.LevelDebug
	if !errors.Is(err, context.Canceled) {
		lvl = slog.LevelError
	}

	l.Log(ctx, lvl, "shutting down http/3 server", "addr", srv.Addr, slogutil.KeyError, err)
}
