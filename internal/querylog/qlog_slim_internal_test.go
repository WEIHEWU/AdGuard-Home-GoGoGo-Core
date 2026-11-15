//go:build android_slim

package querylog

import (
	"fmt"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryLogSlim_DoesNotScheduleFlushWhenFileEnabledOrDisabled(t *testing.T) {
	for _, fileEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("file_enabled_%v", fileEnabled), func(t *testing.T) {
			const memSize = 5
			l, err := newQueryLog(Config{
				Logger:      testLogger,
				Enabled:     true,
				FileEnabled: fileEnabled,
				RotationIvl: timeutil.Day,
				MemSize:     memSize,
				BaseDir:     t.TempDir(),
			})
			require.NoError(t, err)

			// Add more than memSize entries; in android_slim builds, flushPending
			// must never be set and the ring buffer must retain the last memSize entries.
			const totalEntries = 20
			for i := range totalEntries {
				addTestEntry(
					l,
					fmt.Sprintf("host-%02d.example.org", i),
					testAnswerIPv4,
					testClientIPv4,
					filtering.NotFilteredNotFound,
				)

				l.bufferLock.RLock()
				pending := l.flushPending
				bufLen := l.buffer.Len()
				l.bufferLock.RUnlock()

				assert.False(t, pending, "android_slim must not schedule file flush")
				assert.LessOrEqual(t, bufLen, uint(memSize))
			}

			ctx := testutil.ContextWithTimeout(t, 5*time.Second)
			params := newSearchParams()
			entries, oldest := l.search(ctx, params)
			require.Len(t, entries, memSize)
			assert.False(t, oldest.IsZero())

			for i := range memSize {
				wantHost := fmt.Sprintf("host-%02d.example.org", totalEntries-1-i)
				assert.Equal(t, wantHost, entries[i].QHost)
			}

			// Verify clear resets buffer.
			l.clear(ctx)
			entries, oldest = l.search(ctx, params)
			assert.Empty(t, entries)
			assert.True(t, oldest.IsZero())
		})
	}
}
