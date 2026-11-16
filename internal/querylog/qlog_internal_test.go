package querylog

import (
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// searchCriTerm is a helper function for tests that constructs a search
// criterion of type [ctTerm].
func searchCriTerm(val string, isStrict bool) (c searchCriterion) {
	return searchCriterion{
		value:         val,
		criterionType: ctTerm,
		strict:        isStrict,
	}
}

// searchReason is a helper function for tests that constructs a search
// criterion of type [ctReason].
func searchReason(values []string) (c searchCriterion) {
	return searchCriterion{
		values:        values,
		criterionType: ctReason,
	}
}

func TestQueryLogFileDisabled(t *testing.T) {
	l, err := newQueryLog(Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: false,
		RotationIvl: timeutil.Day,
		MemSize:     2,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	addTestEntry(l, "example1.org", testAnswerIPv4, testClientIPv4, filtering.Rewritten)
	addTestEntry(l, "example2.org", testAnswerIPv4, testClientIPv4, filtering.Rewritten)
	// The oldest entry is going to be removed from memory buffer.
	addTestEntry(l, "example3.org", testAnswerIPv4, testClientIPv4, filtering.Rewritten)

	params := newSearchParams()
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	ll, _ := l.search(ctx, params)
	require.Len(t, ll, 2)

	assert.Equal(t, "example3.org", ll[0].QHost)
	assert.Equal(t, "example2.org", ll[1].QHost)
}

func TestQueryLogShouldLog(t *testing.T) {
	const (
		ignored1        = "ignor.ed"
		ignored2        = "ignored.to"
		ignoredWildcard = "*.ignored.com"
		ignoredRoot     = "|.^"
	)

	ignored := []string{
		ignored1,
		ignored2,
		ignoredWildcard,
		ignoredRoot,
	}

	engine, err := aghnet.NewIgnoreEngine(ignored, true)
	require.NoError(t, err)

	findClient := func(ids []string) (c *Client, err error) {
		log := ids[0] == "no_log"

		return &Client{IgnoreQueryLog: log}, nil
	}

	l, err := newQueryLog(Config{
		Ignored:     engine,
		Enabled:     true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
		FindClient:  findClient,
	})
	require.NoError(t, err)

	testCases := []struct {
		name    string
		host    string
		ids     []string
		wantLog bool
	}{{
		name:    "log",
		host:    "example.com",
		ids:     []string{"whatever"},
		wantLog: true,
	}, {
		name:    "no_log_ignored_1",
		host:    ignored1,
		ids:     []string{"whatever"},
		wantLog: false,
	}, {
		name:    "no_log_ignored_2",
		host:    ignored2,
		ids:     []string{"whatever"},
		wantLog: false,
	}, {
		name:    "no_log_ignored_wildcard",
		host:    "www.ignored.com",
		ids:     []string{"whatever"},
		wantLog: false,
	}, {
		name:    "no_log_ignored_root",
		host:    ".",
		ids:     []string{"whatever"},
		wantLog: false,
	}, {
		name:    "no_log_client_ignore",
		host:    "example.com",
		ids:     []string{"no_log"},
		wantLog: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := l.ShouldLog(tc.host, dns.TypeA, dns.ClassINET, tc.ids)

			assert.Equal(t, tc.wantLog, res)
		})
	}
}

func assertLogEntry(tb testing.TB, entry *logEntry, host string, answer, client net.IP) {
	tb.Helper()

	require.NotNil(tb, entry)

	assert.Equal(tb, host, entry.QHost)
	assert.Equal(tb, client, entry.IP)
	assert.Equal(tb, "A", entry.QType)
	assert.Equal(tb, "IN", entry.QClass)

	msg := &dns.Msg{}
	require.NoError(tb, msg.Unpack(entry.Answer))
	require.Len(tb, msg.Answer, 1)

	a := testutil.RequireTypeAssert[*dns.A](tb, msg.Answer[0])
	assert.Equal(tb, answer, a.A.To16())
}
