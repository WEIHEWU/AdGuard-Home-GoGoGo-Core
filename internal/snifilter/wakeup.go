package snifilter

import "context"

// startWakeupWriter waits for ctx cancellation and invokes onCancel unless
// stopAndWait is called first.  Callers must invoke the returned stopAndWait
// before releasing resources captured by onCancel so onCancel never runs after
// stopAndWait returns.
func startWakeupWriter(ctx context.Context, onCancel func()) (stopAndWait func()) {
	done := make(chan struct{})
	exited := make(chan struct{})

	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			onCancel()
		case <-done:
		}
	}()

	return func() {
		close(done)
		<-exited
	}
}
