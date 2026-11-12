//go:build android_slim

package home

import (
	"context"
	"log/slog"
)

type http3ServerHolder = struct{}

func (web *webAPI) mustStartHTTP3(_ context.Context, _ string) {}

func shutdownSrv3(_ context.Context, _ *slog.Logger, _ http3ServerHolder) {}
