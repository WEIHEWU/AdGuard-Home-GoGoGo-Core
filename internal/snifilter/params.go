package snifilter

import (
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/golibs/errors"
)

// Params is the configuration of the SNI filter read from the configuration
// file.
type Params struct {
	// Ports is the list of TCP ports to inspect.  It must not be empty.
	Ports []uint16 `yaml:"ports"`

	// QueueNum is the number of the NFQUEUE queue used to receive the packets.
	QueueNum uint16 `yaml:"queue_num"`

	// DropQUIC defines whether to reject the UDP traffic to Ports in order to
	// make the clients fall back to TCP.  The server names in QUIC are
	// encrypted, so the SNI filter cannot inspect it.
	DropQUIC bool `yaml:"drop_quic"`
}

// Validate returns an error if p isn't valid.
func (p *Params) Validate() (err error) {
	if len(p.Ports) == 0 {
		return errors.Error("ports: empty")
	}

	for _, port := range p.Ports {
		if port == 0 {
			return fmt.Errorf("ports: invalid port %d", port)
		}
	}

	return nil
}

// Config is the configuration of the SNI filter.
type Config struct {
	// Logger is used to log the operation of the filter.  It must not be nil.
	Logger *slog.Logger

	// Filter is the DNS filtering engine used to check the host names.  It
	// must not be nil.
	Filter *filtering.DNSFilter

	// QueryLog, if not nil, is used to record the blocked connections, so
	// that they can be analyzed in the admin UI.
	QueryLog querylog.QueryLog

	// Params are the settings read from the configuration file.
	Params
}
