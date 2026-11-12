//go:build android_slim

package home

import (
	"log/slog"
	"net/http"
)

type mobileConfigHandlerConfig struct {
	logger *slog.Logger
}

type mobileConfigHandler struct{}

func newMobileConfigHandler(_ *mobileConfigHandlerConfig) *mobileConfigHandler {
	return &mobileConfigHandler{}
}

func (m *mobileConfigHandler) handleMobileConfigDoH(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Apple mobileconfig profiles are disabled in Android slim builds", http.StatusNotImplemented)
}

func (m *mobileConfigHandler) handleMobileConfigDoT(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Apple mobileconfig profiles are disabled in Android slim builds", http.StatusNotImplemented)
}
