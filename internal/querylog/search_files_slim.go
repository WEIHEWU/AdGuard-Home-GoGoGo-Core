//go:build android_slim

package querylog

import (
	"context"
	"time"
)

// searchFiles returns empty results in android_slim builds because query log
// entries are retained exclusively in the bounded in-memory RingBuffer.
func (l *queryLog) searchFiles(
	_ context.Context,
	_ *searchParams,
	_ clientCache,
) (entries []*logEntry, oldest time.Time, total int) {
	return nil, time.Time{}, 0
}

// flushLogBuffer resets the pending flag without clearing l.buffer or writing
// querylog.json to flash storage, keeping the most recent MemSize entries in
// the RingBuffer even if file_enabled is left true in YAML.
func (l *queryLog) flushLogBuffer(_ context.Context) (err error) {
	l.bufferLock.Lock()
	l.flushPending = false
	l.bufferLock.Unlock()

	return nil
}

// periodicRotate is a no-op in android_slim builds (zero background disk/timer
// wakeups).
func (l *queryLog) periodicRotate(_ context.Context) {}
