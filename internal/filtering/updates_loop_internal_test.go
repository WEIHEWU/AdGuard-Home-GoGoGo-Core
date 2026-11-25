package filtering

import (
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
)

func TestDNSFilter_periodicallyRefreshFilters_zeroInterval(t *testing.T) {
	t.Parallel()

	d := &DNSFilter{
		logger: slogutil.NewDiscardLogger(),
		conf: &Config{
			Logger:                     slogutil.NewDiscardLogger(),
			FiltersUpdateIntervalHours: 0,
			filtersMu:                  &sync.RWMutex{},
		},
	}

	assert.Equal(t, time.Hour, d.periodicallyRefreshFilters(5*time.Second))

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				d.conf.filtersMu.Lock()
				d.conf.FiltersUpdateIntervalHours = 0
				d.conf.filtersMu.Unlock()
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				got := d.periodicallyRefreshFilters(5 * time.Second)
				assert.Equal(t, time.Hour, got)
			}
		}()
	}
	wg.Wait()
}
