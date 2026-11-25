//go:build linux

package home

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoundedCrashLogWriter(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), crashLogName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	w := &boundedCrashLogWriter{
		f:        f,
		path:     path,
		maxBytes: 32,
	}

	chunk := bytes.Repeat([]byte("a"), 20)
	n, err := w.Write(chunk)
	require.NoError(t, err)
	require.Equal(t, len(chunk), n)

	// Exceeding maxBytes copies current file to .1 and truncates active file
	// before appending the new chunk.
	n, err = w.Write(chunk)
	require.NoError(t, err)
	require.Equal(t, len(chunk), n)

	cur, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, chunk, cur)

	bak, err := os.ReadFile(path + crashLogBackupSuffix)
	require.NoError(t, err)
	assert.Equal(t, chunk, bak)
}
