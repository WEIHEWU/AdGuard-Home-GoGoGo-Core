//go:build android_slim

package main

import (
	"os"
	"runtime/debug"
	"testing/fstest"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/home"
)

// minimalClientFS provides a tiny headless status stub in place of the ~6 MB
// embedded Web UI bundle so /control/* HTTP APIs work with zero Web UI overhead.
var minimalClientFS = fstest.MapFS{
	"build/static/index.html": &fstest.MapFile{
		Data: []byte(`<!doctype html><meta charset="utf-8"><title>AdGuard Home GoGoGo Core</title><body style="font-family:system-ui;padding:2rem"><h2>AdGuard Home GoGoGo Core (Android Slim)</h2><p>Headless pure-DNS firewall build. Manage via AdGuard Home GoGoGo Manager App.</p></body>`),
		Mode: 0o444,
	},
}

func main() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(64 << 20)
	}

	aghos.InitAndroidTZ()
	home.Main(minimalClientFS)
}
