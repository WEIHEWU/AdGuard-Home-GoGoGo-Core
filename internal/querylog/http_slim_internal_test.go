//go:build android_slim

package querylog

import "testing"

func runFileSearchSubtestIfSupported(
	_ *testing.T,
	_ *queryLog,
	_ int,
	_ []string,
	_ string,
	_ string,
) {
	// File-backed query logs are compiled out in android_slim builds.
}
