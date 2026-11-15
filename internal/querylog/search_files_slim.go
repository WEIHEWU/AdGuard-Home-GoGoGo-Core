//go:build android_slim

package querylog

import (
	"context"
	"time"
)

// canFlushToFile indicates whether query log entries can be flushed to disk.
// In android_slim builds, query logs are kept exclusively in the in-memory
// RingBuffer, so scheduling a flush goroutine when the buffer is full would
// only perform useless lock/goroutine churn.
const canFlushToFile = false

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
