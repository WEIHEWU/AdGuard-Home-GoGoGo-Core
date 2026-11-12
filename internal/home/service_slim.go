//go:build android_slim

package home

import (
	"context"
	"io/fs"
	"log/slog"
	"os"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
)

const serviceName = "AdGuardHome"

// restartService returns unsupported on Android where service lifecycle is
// managed by the Magisk / KernelSU / APatch module scripts.
func restartService(_ context.Context, _ *slog.Logger) (err error) {
	return aghos.Unsupported("service")
}

// handleServiceControlAction returns unsupported on Android.
func handleServiceControlAction(
	_ context.Context,
	_ *slog.Logger,
	_ *slog.Logger,
	_ *os.Root,
	_ options,
	_ fs.FS,
	_ chan os.Signal,
	_ chan struct{},
	_ *signalHandler,
	_ string,
	_ string,
	_ string,
	_ *aghnet.HostsContainer,
) (err error) {
	return aghos.Unsupported("service")
}
