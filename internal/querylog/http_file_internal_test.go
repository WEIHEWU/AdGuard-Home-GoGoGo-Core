//go:build !android_slim

package querylog

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

func runFileSearchSubtestIfSupported(
	t *testing.T,
	l *queryLog,
	wantStatus int,
	wantHosts []string,
	wantMsg string,
	u string,
) {
	t.Helper()

	require.True(t, t.Run("file", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		err := l.flushLogBuffer(ctx)
		require.NoError(t, err)

		testSearchAPI(t, l, wantStatus, wantHosts, wantMsg, u)
	}))
}
