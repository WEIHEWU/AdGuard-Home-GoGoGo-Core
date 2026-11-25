package snifilter

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStartWakeupWriter_StopBeforeCancel(t *testing.T) {
	t.Parallel()

	for range 1000 {
		ctx, cancel := context.WithCancel(context.Background())
		var closed atomic.Bool
		var wroteAfterClose atomic.Bool

		stopAndWait := startWakeupWriter(ctx, func() {
			if closed.Load() {
				wroteAfterClose.Store(true)
			}
		})

		stopAndWait()
		closed.Store(true)
		cancel()

		assert.False(t, wroteAfterClose.Load())
	}
}
