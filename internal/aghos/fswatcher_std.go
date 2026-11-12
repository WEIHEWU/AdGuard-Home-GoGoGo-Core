//go:build !android_slim

package aghos

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/fsnotify/fsnotify"
)

// OSWatcher tracks the file system provided by the OS.
type OSWatcher struct {
	logger  *slog.Logger
	filesMu *sync.RWMutex
	watcher *fsnotify.Watcher
	events  chan Event
	files   map[string]*container.MapSet[string]
}

const osWatcherPref = "os_watcher"

// NewOSWatcher creates an [FSWatcher] that tracks the file system of the OS.
func NewOSWatcher(c *OSWatcherConfig) (w *OSWatcher, err error) {
	defer func() { err = errors.Annotate(err, "%s: %w", osWatcherPref) }()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating watcher: %w", err)
	}

	return &OSWatcher{
		logger:  c.Logger,
		filesMu: &sync.RWMutex{},
		watcher: watcher,
		events:  make(chan Event, 1),
		files:   map[string]*container.MapSet[string]{},
	}, nil
}

// type check
var _ FSWatcher = (*OSWatcher)(nil)

// Start implements the [service.Interface] interface for *OSWatcher.
func (w *OSWatcher) Start(ctx context.Context) (err error) {
	go w.handleErrors(ctx)
	go w.handleEvents(ctx)

	return nil
}

// Shutdown implements the [service.Interface] interface for *OSWatcher.
func (w *OSWatcher) Shutdown(_ context.Context) (err error) {
	return errors.Annotate(w.watcher.Close(), "%s: %w", osWatcherPref)
}

// Events implements the [FSWatcher] interface for *OSWatcher.
func (w *OSWatcher) Events() (e <-chan Event) {
	return w.events
}

// Add implements the [FSWatcher] interface for *OSWatcher.
func (w *OSWatcher) Add(name string) (err error) {
	defer func() { err = errors.Annotate(err, "%s: %w", osWatcherPref) }()

	fi, err := os.Stat(name)
	if err != nil {
		return fmt.Errorf("checking file %q: %w", name, err)
	}

	dirName := name
	if !fi.IsDir() {
		dirName = filepath.Dir(name)
	}

	w.filesMu.Lock()
	defer w.filesMu.Unlock()

	names := w.files[dirName]
	if names == nil {
		names = container.NewMapSet[string]()
		w.files[dirName] = names
	}
	names.Add(name)

	err = w.watcher.Add(dirName)
	if err != nil {
		return fmt.Errorf("adding %q: %w", dirName, err)
	}

	return nil
}

// Remove implements the [FSWatcher] interface for *OSWatcher.
func (w *OSWatcher) Remove(name string) (err error) {
	defer func() { err = errors.Annotate(err, "%s: %w", osWatcherPref) }()

	dirName := filepath.Dir(name)

	w.filesMu.Lock()
	defer w.filesMu.Unlock()

	names, ok := w.files[name]
	if ok {
		dirName = name
	} else {
		names = w.files[dirName]
	}

	if !names.Has(name) {
		return nil
	}

	names.Delete(name)
	if names.Len() > 0 {
		return nil
	}

	delete(w.files, dirName)

	err = w.watcher.Remove(dirName)
	if err != nil {
		return fmt.Errorf("removing %q: %w", dirName, err)
	}

	return nil
}

func (w *OSWatcher) handleEvents(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, w.logger)
	defer close(w.events)

	ch := w.watcher.Events
	for e := range ch {
		if !w.isTrackedEvent(e) {
			continue
		}

		skipDuplicates(ch)

		select {
		case w.events <- Event{}:
		default:
			w.logger.DebugContext(ctx, "events buffer is full")
		}
	}
}

func (w *OSWatcher) isTrackedEvent(e fsnotify.Event) (isDir bool) {
	const changeEvent = fsnotify.Write | fsnotify.Create | fsnotify.Rename | fsnotify.Remove

	if !e.Has(changeEvent) {
		return false
	}

	dirName := filepath.Dir(e.Name)

	w.filesMu.RLock()
	defer w.filesMu.RUnlock()

	names, isDir := w.files[e.Name]
	if !isDir {
		names = w.files[dirName]
	}

	return names.Has(e.Name)
}

func skipDuplicates(ch <-chan fsnotify.Event) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func (w *OSWatcher) handleErrors(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, w.logger)

	for err := range w.watcher.Errors {
		w.logger.ErrorContext(ctx, "handling error", slogutil.KeyError, err)
	}
}
