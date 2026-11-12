//go:build android_slim

package updater

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/osutil/executil"
)

// Updater is a disabled stub in android_slim builds (updates are delivered via
// Magisk / KernelSU / APatch module zips).
type Updater struct{}

// DefaultVersionURL returns a placeholder URL for schema compatibility.
func DefaultVersionURL() *url.URL {
	return &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   "github.com",
		Path:   "/WEIHEWU/AdGuard-Home-GoGoGo/releases",
	}
}

// Config is the AdGuard Home updater configuration.
type Config struct {
	Client             *http.Client
	Logger             *slog.Logger
	VersionCheckURL    *url.URL
	CommandConstructor executil.CommandConstructor
	Version            string
	Channel            string
	GOARCH             string
	GOOS               string
	GOARM              string
	GOMIPS             string
	ConfName           string
	WorkDir            string
	ExecPath           string
}

// VersionInfo contains information about a new version.
type VersionInfo struct {
	NewVersion      string          `json:"new_version,omitempty"`
	Announcement    string          `json:"announcement,omitempty"`
	AnnouncementURL string          `json:"announcement_url,omitempty"`
	CanAutoUpdate   aghalg.NullBool `json:"can_autoupdate,omitempty"`
}

// NewUpdater returns a disabled stub *Updater.
func NewUpdater(_ *Config) *Updater {
	return &Updater{}
}

// VersionInfo returns ErrUnsupported in android_slim builds.
func (u *Updater) VersionInfo(_ context.Context, _ bool) (vi VersionInfo, err error) {
	return VersionInfo{CanAutoUpdate: aghalg.NBFalse}, errors.ErrUnsupported
}

// NewVersion always returns empty string in android_slim builds.
func (u *Updater) NewVersion() (nv string) {
	return ""
}

// Update returns ErrUnsupported in android_slim builds.
func (u *Updater) Update(_ context.Context, _ bool) (err error) {
	return errors.ErrUnsupported
}
