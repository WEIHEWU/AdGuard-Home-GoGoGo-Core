//go:build android_slim

package stats

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// maxMemoryRingHours bounds the number of historical hourly buckets retained in
// RAM regardless of user-configured interval, preventing unbounded heap growth
// while preserving full 24h+ dashboard fidelity.
const maxMemoryRingHours uint32 = 168

// StatsCtx collects DNS filtering statistics purely in memory with zero disk
// writes (no bbolt/stats.db) and zero 1-second idle CPU wakeups on Android.
type StatsCtx struct {
	logger            *slog.Logger
	currMu            *sync.RWMutex
	curr              *unit
	ring              map[uint32]*unitDB
	unitIDGen         UnitIDGenFunc
	httpReg           aghhttp.Registrar
	configModifier    agh.ConfigModifier
	confMu            *sync.RWMutex
	ignored           *aghnet.IgnoreEngine
	shouldCountClient func([]string) bool
	limit             time.Duration
	enabled           bool
}

// New creates an in-memory StatsCtx from conf.
func New(conf Config) (s *StatsCtx, err error) {
	defer withRecovered(&err)

	err = validateIvl(conf.Limit)
	if err != nil {
		return nil, fmt.Errorf("unsupported interval: %w", err)
	}

	if conf.ShouldCountClient == nil {
		return nil, errors.Error("should count client is unspecified")
	}

	s = &StatsCtx{
		logger:            conf.Logger,
		currMu:            &sync.RWMutex{},
		ring:              map[uint32]*unitDB{},
		httpReg:           conf.HTTPReg,
		configModifier:    conf.ConfigModifier,
		confMu:            &sync.RWMutex{},
		ignored:           conf.Ignored,
		shouldCountClient: conf.ShouldCountClient,
		limit:             conf.Limit,
		enabled:           conf.Enabled,
	}

	if s.unitIDGen = newUnitID; conf.UnitID != nil {
		s.unitIDGen = conf.UnitID
	}

	s.curr = newUnit(s.unitIDGen())
	s.logger.Debug("initialized in-memory stats engine")

	return s, nil
}

// type check
var _ Interface = (*StatsCtx)(nil)

// Start implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) Start() {
	if s.httpReg != nil {
		s.initWeb()
	}
}

// Close implements the [io.Closer] interface for *StatsCtx.
func (s *StatsCtx) Close() (err error) {
	return nil
}

// rotateLocked advances s.curr if the current hour ID has changed and prunes
// expired buckets from s.ring.  s.currMu must be locked for writing.
func (s *StatsCtx) rotateLocked(nowID, keepHours uint32) {
	if s.curr == nil {
		s.curr = newUnit(nowID)
		return
	}
	if s.curr.id == nowID {
		return
	}

	if keepHours > maxMemoryRingHours {
		keepHours = maxMemoryRingHours
	}
	if keepHours > 1 && s.curr.nTotal > 0 {
		s.ring[s.curr.id] = s.curr.serialize()
	}

	s.curr = newUnit(nowID)

	var minID uint32
	if nowID > keepHours {
		minID = nowID - keepHours
	}
	for id := range s.ring {
		if id <= minID {
			delete(s.ring, id)
		}
	}
}

// Update implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) Update(e *Entry) {
	s.confMu.RLock()
	enabled := s.enabled
	limitHours := uint32(s.limit.Hours())
	s.confMu.RUnlock()

	if !enabled || limitHours == 0 {
		return
	}

	err := e.validate()
	if err != nil {
		s.logger.Debug("validating entry", slogutil.KeyError, err)
		return
	}

	nowID := s.unitIDGen()

	s.currMu.Lock()
	defer s.currMu.Unlock()

	s.rotateLocked(nowID, limitHours)
	s.curr.add(e)
}

// WriteDiskConfig implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) WriteDiskConfig(dc *Config) {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	dc.Ignored = s.ignored
	dc.Limit = s.limit
	dc.Enabled = s.enabled
}

// TopClientsIP implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) TopClientsIP(maxCount uint) (ips []netip.Addr) {
	s.confMu.RLock()
	enabled := s.enabled
	limit := uint32(s.limit.Hours())
	s.confMu.RUnlock()

	if !enabled || limit == 0 {
		return nil
	}

	units, _ := s.loadUnits(limit)
	if units == nil {
		return nil
	}

	m := map[string]uint64{}
	for _, u := range units {
		for _, it := range u.Clients {
			m[it.Name] += it.Count
		}
	}

	a := convertMapToSlice(m, int(maxCount))
	ips = []netip.Addr{}
	for _, it := range a {
		ip, err := netip.ParseAddr(it.Name)
		if err == nil {
			ips = append(ips, ip)
		}
	}

	return ips
}

// setLimit updates the retention limit.  s.confMu is expected to be locked.
func (s *StatsCtx) setLimit(limit time.Duration) {
	if limit != 0 {
		s.enabled = true
		s.limit = limit
		s.logger.Debug("setting limit in days", "num", limit/timeutil.Day)
		return
	}

	s.enabled = false
	s.logger.Debug("disabled")
	_ = s.clear()
}

// clear resets all in-memory statistics counters.
func (s *StatsCtx) clear() (err error) {
	s.currMu.Lock()
	defer s.currMu.Unlock()

	clear(s.ring)
	s.curr = newUnit(s.unitIDGen())
	s.logger.Debug("cleared in-memory stats")

	return nil
}

// loadUnits returns the last limit hourly units and current unit ID from RAM.
func (s *StatsCtx) loadUnits(limit uint32) (units []*unitDB, curID uint32) {
	nowID := s.unitIDGen()

	s.currMu.Lock()
	s.rotateLocked(nowID, limit)
	cur := s.curr
	curID = cur.id

	emptyUnit := &unitDB{NResult: make([]uint64, resultLast)}
	units = make([]*unitDB, 0, limit)
	firstID := curID - limit + 1
	for i := firstID; i != curID; i++ {
		u := s.ring[i]
		if u == nil {
			u = emptyUnit
		}
		units = append(units, u)
	}
	units = append(units, cur.serialize())
	s.currMu.Unlock()

	return units, curID
}

// ShouldCount returns true if request for the host should be counted.
func (s *StatsCtx) ShouldCount(host string, _, _ uint16, ids []string) bool {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	if !s.shouldCountClient(ids) {
		return false
	}

	return !s.isIgnored(host)
}

func (s *StatsCtx) isIgnored(host string) bool {
	return s.ignored.Has(host)
}
