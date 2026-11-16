//go:build !android_slim

package querylog

import (
	"fmt"
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryLog tests adding and loading (with filtering) entries from disk and
// memory.
func TestQueryLog(t *testing.T) {
	hosts := []string{
		"example.org",
		"example.org",
		"test.example.org",
		"example.com",
		"",
	}

	entries := make([]*logEntry, len(hosts))
	for i, h := range hosts {
		n := byte(i + 1)
		entries[i] = &logEntry{
			QHost:  h,
			Answer: net.IPv4(192, 0, 2, n),
			IP:     net.IPv4(203, 0, 113, n),
		}
	}

	entry1, entry2, entry3, entry4 := entries[0], entries[1], entries[2], entries[3]

	entryRoot := entries[4]
	entryRootWant := &logEntry{QHost: ".", Answer: entryRoot.Answer, IP: entryRoot.IP}

	l, err := newQueryLog(Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Add disk entries.
	addTestEntry(l, entry1.QHost, entry1.Answer, entry1.IP, filtering.Rewritten)
	// Write to disk (first file).
	require.NoError(t, l.flushLogBuffer(ctx))

	// Start writing to the second file.
	require.NoError(t, l.rotate(ctx))

	// Add disk entries.
	addTestEntry(l, entry2.QHost, entry2.Answer, entry2.IP, filtering.Rewritten)
	// Write to disk.
	require.NoError(t, l.flushLogBuffer(ctx))

	// Add memory entries.
	addTestEntry(l, entry3.QHost, entry3.Answer, entry3.IP, filtering.Rewritten)
	addTestEntry(l, entry4.QHost, entry4.Answer, entry4.IP, filtering.Rewritten)
	addTestEntry(l, entryRoot.QHost, entryRoot.Answer, entryRoot.IP, filtering.Rewritten)

	testCases := []struct {
		name string
		sCr  []searchCriterion
		want []*logEntry
	}{{
		name: "all",
		sCr:  []searchCriterion{},
		want: []*logEntry{entryRootWant, entry4, entry3, entry2, entry1},
	}, {
		name: "by_domain_strict",
		sCr:  []searchCriterion{searchCriTerm("TEST.example.org", true)},
		want: []*logEntry{entry3},
	}, {
		name: "by_domain_non-strict",
		sCr:  []searchCriterion{searchCriTerm("example.ORG", false)},
		want: []*logEntry{entry3, entry2, entry1},
	}, {
		name: "by_client_ip_strict",
		sCr:  []searchCriterion{searchCriTerm(entry2.IP.String(), true)},
		want: []*logEntry{entry2},
	}, {
		name: "by_client_ip_non-strict",
		sCr:  []searchCriterion{searchCriTerm("203.0.113", false)},
		want: []*logEntry{entryRootWant, entry4, entry3, entry2, entry1},
	}, {
		name: "by_reason",
		sCr:  []searchCriterion{searchReason([]string{filtering.Rewritten.String()})},
		want: []*logEntry{entryRootWant, entry4, entry3, entry2, entry1},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := newSearchParams()
			params.searchCriteria = tc.sCr

			entries, _ = l.search(ctx, params)
			require.Len(t, entries, len(tc.want))

			for i, want := range tc.want {
				assertLogEntry(t, entries[i], want.QHost, want.Answer, want.IP)
			}
		})
	}
}

func TestQueryLogOffsetLimit(t *testing.T) {
	l, err := newQueryLog(Config{
		Logger:      testLogger,
		Enabled:     true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	const (
		entNum           = 10
		firstPageDomain  = "first.example.org"
		secondPageDomain = "second.example.org"
	)

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Add entries to the log.
	for range entNum {
		addTestEntry(
			l,
			secondPageDomain,
			testAnswerIPv4,
			testClientIPv4,
			filtering.Rewritten,
		)
	}
	// Write them to the first file.
	require.NoError(t, l.flushLogBuffer(ctx))

	// Add more to the in-memory part of log.
	for range entNum {
		addTestEntry(
			l,
			firstPageDomain,
			testAnswerIPv4,
			testClientIPv4,
			filtering.Rewritten,
		)
	}

	params := newSearchParams()

	testCases := []struct {
		name    string
		want    string
		wantLen int
		offset  int
		limit   int
	}{{
		name:    "page_1",
		want:    firstPageDomain,
		wantLen: 10,
		offset:  0,
		limit:   10,
	}, {
		name:    "page_2",
		want:    secondPageDomain,
		wantLen: 10,
		offset:  10,
		limit:   10,
	}, {
		name:    "page_2.5",
		want:    secondPageDomain,
		wantLen: 5,
		offset:  15,
		limit:   10,
	}, {
		name:    "page_3",
		want:    "",
		wantLen: 0,
		offset:  20,
		limit:   10,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params.offset = tc.offset
			params.limit = tc.limit
			entries, _ := l.search(ctx, params)
			require.Len(t, entries, tc.wantLen)

			if tc.wantLen > 0 {
				assert.Equal(t, entries[0].QHost, tc.want)
				assert.Equal(t, entries[tc.wantLen-1].QHost, tc.want)
			}
		})
	}
}

func TestQueryLogMaxFileScanEntries(t *testing.T) {
	l, err := newQueryLog(Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	const entNum = 10
	// Add entries to the log.
	for range entNum {
		addTestEntry(
			l,
			"example.org",
			testAnswerIPv4,
			testClientIPv4,
			filtering.Rewritten,
		)
	}
	// Write them to disk.
	require.NoError(t, l.flushLogBuffer(ctx))

	params := newSearchParams()
	for _, maxFileScanEntries := range []int{5, 0} {
		t.Run(fmt.Sprintf("limit_%d", maxFileScanEntries), func(t *testing.T) {
			params.maxFileScanEntries = maxFileScanEntries
			entries, _ := l.search(ctx, params)
			assert.Len(t, entries, entNum-maxFileScanEntries)
		})
	}
}
