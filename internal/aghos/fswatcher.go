package aghos

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/golibs/service"
)

// Event is a convenient alias for an empty struct to signal that watched file
// event happened.
type Event = struct{}

// FSWatcher tracks all the file system events and notifies about those.
type FSWatcher interface {
	service.Interface

	// Events returns the channel to notify about the file system events.
	Events() (e <-chan Event)

	// Add starts tracking the file.  It returns an error if the file can't be
	// tracked.  Adding the same file multiple times must not result in an
	// error.
	Add(name string) (err error)

	// Remove stops tracking the file.  Removing a non-tracked file must not
	// result in an error.
	Remove(name string) (err error)
}

// OSWatcherConfig is the configuration structure for [NewOSWatcher].
type OSWatcherConfig struct {
	// Logger is used for logging the operations of watcher.  It must not be
	// nil.
	Logger *slog.Logger
}

// EmptyFSWatcher is a no-op implementation of the [FSWatcher] interface.  It
// may be used on systems not supporting filesystem events.
type EmptyFSWatcher struct{}

// type check
var _ FSWatcher = EmptyFSWatcher{}

// Start implements the [FSWatcher] interface for EmptyFSWatcher.  It always
// returns nil error.
func (EmptyFSWatcher) Start(_ context.Context) (err error) {
	return nil
}

// Shutdown implements the [FSWatcher] interface for EmptyFSWatcher.  It always
// returns nil error.
func (EmptyFSWatcher) Shutdown(_ context.Context) (err error) {
	return nil
}

// Events implements the [FSWatcher] interface for EmptyFSWatcher.  It always
// returns nil channel.
func (EmptyFSWatcher) Events() (e <-chan Event) {
	return nil
}

// Add implements the [FSWatcher] interface for EmptyFSWatcher.  It always
// returns nil error.
func (EmptyFSWatcher) Add(_ string) (err error) {
	return nil
}

// Remove implements the [FSWatcher] interface for EmptyFSWatcher.  It always
// returns nil error.
func (EmptyFSWatcher) Remove(_ string) (err error) {
	return nil
}
