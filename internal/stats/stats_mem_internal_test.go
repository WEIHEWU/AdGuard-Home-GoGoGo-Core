//go:build android_slim

package stats

import (
	"fmt"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatsMem_RotateDoesNotRetainTruncatedBackingArrays(t *testing.T) {
	var curHour uint32 = 100
	s, err := New(Config{
		Logger:            slogutil.NewDiscardLogger(),
		Limit:             7 * timeutil.Day,
		Enabled:           true,
		Ignored:           &aghnet.IgnoreEngine{},
		ShouldCountClient: func([]string) bool { return true },
		UnitID:            func() uint32 { return curHour },
	})
	require.NoError(t, err)

	// Populate hour 100 with 2000 unique domains and 500 unique blocked domains,
	// well above maxDomains (100).
	for i := range 2000 {
		s.Update(&Entry{
			Client:         "192.168.1.10",
			Domain:         fmt.Sprintf("allowed-%04d.example.com", i),
			Result:         RNotFiltered,
			ProcessingTime: 100 * time.Microsecond,
		})
	}
	for i := range 500 {
		s.Update(&Entry{
			Client:         "192.168.1.10",
			Domain:         fmt.Sprintf("blocked-%04d.example.com", i),
			Result:         RFiltered,
			ProcessingTime: 50 * time.Microsecond,
		})
	}

	// Advance hour to trigger rotateLocked.
	curHour = 101
	s.Update(&Entry{
		Client:         "192.168.1.10",
		Domain:         "next-hour.example.com",
		Result:         RNotFiltered,
		ProcessingTime: 100 * time.Microsecond,
	})

	s.currMu.RLock()
	u100 := s.ring[100]
	s.currMu.RUnlock()

	require.NotNil(t, u100)
	assert.Len(t, u100.Domains, maxDomains)
	assert.Equal(t, maxDomains, cap(u100.Domains))
	assert.Len(t, u100.BlockedDomains, maxDomains)
	assert.Equal(t, maxDomains, cap(u100.BlockedDomains))
	assert.Len(t, u100.Clients, 1)
	assert.Equal(t, 1, cap(u100.Clients))
}
