package stats

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// checkInterval returns true if days is valid to be used as statistics
// retention interval.  The valid values are 0, 1, 7, 30 and 90.
func checkInterval(days uint32) (ok bool) {
	return days == 0 || days == 1 || days == 7 || days == 30 || days == 90
}

// validateIvl returns an error if ivl is less than an hour or more than a
// year.
func validateIvl(ivl time.Duration) (err error) {
	if ivl < time.Hour {
		return errors.Error("less than an hour")
	}

	if ivl > timeutil.Day*365 {
		return errors.Error("more than a year")
	}

	return nil
}

// Config is the configuration structure for the statistics collecting.
//
// Do not alter any fields of this structure after using it.
type Config struct {
	// Logger is used for logging the operation of the statistics management.
	// It must not be nil.
	Logger *slog.Logger

	// UnitID is the function to generate the identifier for current unit.  If
	// nil, the default function is used, see newUnitID.
	UnitID UnitIDGenFunc

	// ConfigModifier is used to update the global configuration.  It must not
	// be nil.
	ConfigModifier agh.ConfigModifier

	// ShouldCountClient returns client's ignore setting.
	ShouldCountClient func([]string) bool

	// HTTPReg is the function that registers handlers for the stats endpoints.
	HTTPReg aghhttp.Registrar

	// Ignored contains the list of host names, which should not be counted,
	// and matches them.
	Ignored *aghnet.IgnoreEngine

	// Filename is the name of the database file.
	Filename string

	// Limit is an upper limit for collecting statistics.
	Limit time.Duration

	// Enabled tells if the statistics are enabled.
	Enabled bool
}

// Interface is the statistics interface to be used by other packages.
type Interface interface {
	// Start begins the statistics collecting.
	Start()

	io.Closer

	// Update collects the incoming statistics data.
	Update(e *Entry)

	// TopClientsIP returns at most limit IP addresses corresponding to the
	// clients with the most number of requests.
	TopClientsIP(limit uint) []netip.Addr

	// WriteDiskConfig puts the Interface's configuration to the dc.
	WriteDiskConfig(dc *Config)

	// ShouldCount returns true if request for the host should be counted.
	ShouldCount(host string, qType, qClass uint16, ids []string) bool
}

// withRecovered turns the value recovered from panic if any into an error and
// combines it with the one pointed by orig.  orig must be non-nil.
func withRecovered(orig *error) {
	p := recover()
	if p == nil {
		return
	}

	var err error
	switch p := p.(type) {
	case error:
		err = fmt.Errorf("panic: %w", p)
	default:
		err = fmt.Errorf("panic: recovered value of type %[1]T: %[1]v", p)
	}

	*orig = errors.WithDeferred(*orig, err)
}
