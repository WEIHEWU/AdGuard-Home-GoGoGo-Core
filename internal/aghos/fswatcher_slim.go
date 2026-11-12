//go:build android_slim

package aghos

// NewOSWatcher returns an [EmptyFSWatcher] in android_slim builds to avoid
// inotify descriptors and background watcher goroutines on Android.
func NewOSWatcher(_ *OSWatcherConfig) (w FSWatcher, err error) {
	return EmptyFSWatcher{}, nil
}
