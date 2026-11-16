package snifilter

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mapRegistrar map[string]http.HandlerFunc

func (m mapRegistrar) Register(method, path string, h http.HandlerFunc) {
	m[method+" "+path] = h
}

func newDiagnosticStack(
	t *testing.T,
	qlEnabled bool,
	ignored []string,
	ignoreClientIP string,
	filters []filtering.Filter,
) (*Filter, mapRegistrar) {
	t.Helper()

	reg := make(mapRegistrar)
	igEng, err := aghnet.NewIgnoreEngine(ignored, len(ignored) > 0)
	require.NoError(t, err)

	anon := &aghnet.IPMut{}
	anon.Store(func(net.IP) {})

	ql, err := querylog.New(querylog.Config{
		Logger:      slogutil.NewDiscardLogger(),
		Enabled:     qlEnabled,
		FileEnabled: false,
		RotationIvl: timeutil.Day,
		MemSize:     32,
		BaseDir:     t.TempDir(),
		Anonymizer:  anon,
		Ignored:     igEng,
		HTTPReg:     reg,
		FindClient: func(ids []string) (*querylog.Client, error) {
			if ignoreClientIP != "" && slices.Contains(ids, ignoreClientIP) {
				return &querylog.Client{Name: "ignored-client", IgnoreQueryLog: true}, nil
			}
			return nil, nil
		},
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, 5*time.Second)
	require.NoError(t, ql.Start(ctx))
	t.Cleanup(func() { _ = ql.Shutdown(ctx) })

	flt, err := filtering.New(&filtering.Config{
		Logger:            slogutil.NewDiscardLogger(),
		ProtectionEnabled: true,
	}, filters)
	require.NoError(t, err)
	flt.SetEnabled(true)

	sniFlt, err := New(&Config{
		Logger:   slogutil.NewDiscardLogger(),
		Filter:   flt,
		QueryLog: ql,
		Params: Params{
			Ports: []uint16{443, 8443},
		},
	})
	require.NoError(t, err)

	return sniFlt, reg
}

func queryHTTPJSON(t *testing.T, h http.HandlerFunc, target string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rw := httptest.NewRecorder()
	h(rw, req)
	require.Equal(t, http.StatusOK, rw.Code)

	var out map[string]any
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &out))
	return out
}

func TestFilter_RealHandshake_QueryLogAndSummary(t *testing.T) {
	t.Parallel()

	sniFlt, reg := newDiagnosticStack(t, true, nil, "", []filtering.Filter{
		{
			ID:   42,
			Data: []byte("||ct.sendgrid.net^\n@@||ok.ct.sendgrid.net^\n"),
		},
		{
			ID:   rulelist.IDCustom,
			Data: []byte("||important-blocked.example^\n||imp-only.example^$important\n@@||imp-only.example^\n"),
		},
	})

	getQLog := reg[http.MethodGet+" /control/querylog"]
	getSummary := reg[http.MethodGet+" /control/querylog/blocked_summary"]
	require.NotNil(t, getQLog)
	require.NotNil(t, getSummary)

	const sniHost = "u56112681.ct.sendgrid.net"
	hello := captureClientHello(t, sniHost)
	require.NotEmpty(t, hello)

	src := netip.MustParseAddrPort("10.0.0.8:54321")
	dst := netip.MustParseAddrPort("198.51.100.2:443")

	// Feed split ClientHello, retransmission, duplicate segment, and trailing RST.
	mid := len(hello) / 2
	seg1 := tcpPacket4(src, dst, 100, 1, tcpFlagACK, hello[:mid])
	seg2 := tcpPacket4(src, dst, 100+uint32(mid), 1, tcpFlagACK, hello[mid:])
	rst := tcpPacket4(src, dst, 100+uint32(len(hello)), 1, tcpFlagRST|tcpFlagACK, nil)

	assert.Equal(t, verdictAccept, feedPacket(t, sniFlt, seg1).verdict)
	assert.Equal(t, verdictReset, feedPacket(t, sniFlt, seg2).verdict)
	// Same connection retransmission & RST must NOT create extra querylog entries.
	assert.Equal(t, verdictDrop, feedPacket(t, sniFlt, seg1).verdict)
	assert.Equal(t, verdictDrop, feedPacket(t, sniFlt, seg2).verdict)
	assert.Equal(t, verdictAccept, feedPacket(t, sniFlt, rst).verdict)

	blockedResp := queryHTTPJSON(t, getQLog, "/control/querylog?response_status=blocked")
	data := blockedResp["data"].([]any)
	require.Len(t, data, 1, "segmentation, retransmit and RST on same connection must log exactly once")

	// Filter directly by reason=FilteredSNI as well.
	byReasonResp := queryHTTPJSON(t, getQLog, "/control/querylog?reason=FilteredSNI")
	require.Len(t, byReasonResp["data"].([]any), 1, "reason=FilteredSNI query must return SNI block")

	entry := data[0].(map[string]any)
	assert.Equal(t, filtering.FilteredSNI.String(), entry["reason"])
	assert.Equal(t, "", entry["upstream"])
	assert.Equal(t, "198.51.100.2:443", entry["destination"])
	assert.NotEmpty(t, entry["time"])
	qObj := entry["question"].(map[string]any)
	assert.Equal(t, sniHost, qObj["name"])

	rules := entry["rules"].([]any)
	require.Len(t, rules, 1)
	r0 := rules[0].(map[string]any)
	assert.Equal(t, "||ct.sendgrid.net^", r0["text"])
	assert.Equal(t, float64(42), r0["filter_list_id"])

	// Allowlist hit is NOT in blocked list.
	okHello := captureClientHello(t, "ok.ct.sendgrid.net")
	okPkt := tcpPacket4(netip.MustParseAddrPort("10.0.0.8:54322"), dst, 200, 1, tcpFlagACK, okHello)
	assert.Equal(t, verdictAccept, feedPacket(t, sniFlt, okPkt).verdict)

	// New connection retry (new source port) for blocked SNI increments summary count to 2.
	retryPkt := tcpPacket4(netip.MustParseAddrPort("10.0.0.8:54323"), dst, 300, 1, tcpFlagACK, hello)
	assert.Equal(t, verdictReset, feedPacket(t, sniFlt, retryPkt).verdict)

	summaryResp := queryHTTPJSON(t, getSummary, "/control/querylog/blocked_summary")
	sData := summaryResp["data"].([]any)
	require.Len(t, sData, 1)
	s0 := sData[0].(map[string]any)
	assert.Equal(t, sniHost, s0["domain"])
	assert.Equal(t, float64(2), s0["count"])
	assert.Equal(t, true, s0["is_sni"])

	// Protection paused: must allow traffic and NOT appear in blocked querylog or blocked_summary.
	sniFlt.SetProtectionStatus(false, nil)
	pausedHost := "paused-pred.ct.sendgrid.net"
	pausedHello := captureClientHello(t, pausedHost)
	pausedPkt := tcpPacket4(netip.MustParseAddrPort("10.0.0.8:54324"), dst, 400, 1, tcpFlagACK, pausedHello)
	assert.Equal(t, verdictAccept, feedPacket(t, sniFlt, pausedPkt).verdict)

	blockedAfterPause := queryHTTPJSON(t, getQLog, "/control/querylog?response_status=blocked&search="+pausedHost)
	assert.Empty(t, blockedAfterPause["data"].([]any), "paused rule prediction must not appear as blocked")

	allPausedResp := queryHTTPJSON(t, getQLog, "/control/querylog?search="+pausedHost)
	allPausedData := allPausedResp["data"].([]any)
	require.Len(t, allPausedData, 1)
	pEntry := allPausedData[0].(map[string]any)
	assert.Equal(t, filtering.NotFilteredSNI.String(), pEntry["reason"])
	assert.Equal(t, true, pEntry["predicted_blocked"])

	summaryAfterPause := queryHTTPJSON(t, getSummary, "/control/querylog/blocked_summary?search="+pausedHost)
	assert.Empty(t, summaryAfterPause["data"].([]any))
}

func TestFilter_QueryLogDisabledAndIgnoredPrivacy(t *testing.T) {
	t.Parallel()

	hello := captureClientHello(t, "u56112681.ct.sendgrid.net")
	dst := netip.MustParseAddrPort("198.51.100.2:443")

	t.Run("querylog_disabled", func(t *testing.T) {
		t.Parallel()
		sniFlt, reg := newDiagnosticStack(t, false, nil, "", []filtering.Filter{
			{ID: 1, Data: []byte("||ct.sendgrid.net^\n")},
		})
		pkt := tcpPacket4(netip.MustParseAddrPort("10.0.0.9:40001"), dst, 1, 1, tcpFlagACK, hello)
		assert.Equal(t, verdictReset, feedPacket(t, sniFlt, pkt).verdict)
		summary := queryHTTPJSON(t, reg[http.MethodGet+" /control/querylog/blocked_summary"], "/control/querylog/blocked_summary")
		assert.Empty(t, summary["data"].([]any))
	})

	t.Run("ignored_domain", func(t *testing.T) {
		t.Parallel()
		sniFlt, reg := newDiagnosticStack(t, true, []string{"*.ct.sendgrid.net"}, "", []filtering.Filter{
			{ID: 1, Data: []byte("||ct.sendgrid.net^\n")},
		})
		pkt := tcpPacket4(netip.MustParseAddrPort("10.0.0.9:40002"), dst, 1, 1, tcpFlagACK, hello)
		assert.Equal(t, verdictReset, feedPacket(t, sniFlt, pkt).verdict)
		summary := queryHTTPJSON(t, reg[http.MethodGet+" /control/querylog/blocked_summary"], "/control/querylog/blocked_summary")
		assert.Empty(t, summary["data"].([]any))
	})

	t.Run("ignored_client", func(t *testing.T) {
		t.Parallel()
		sniFlt, reg := newDiagnosticStack(t, true, nil, "10.0.0.99", []filtering.Filter{
			{ID: 1, Data: []byte("||ct.sendgrid.net^\n")},
		})
		pkt := tcpPacket4(netip.MustParseAddrPort("10.0.0.99:40003"), dst, 1, 1, tcpFlagACK, hello)
		assert.Equal(t, verdictReset, feedPacket(t, sniFlt, pkt).verdict)
		summary := queryHTTPJSON(t, reg[http.MethodGet+" /control/querylog/blocked_summary"], "/control/querylog/blocked_summary")
		assert.Empty(t, summary["data"].([]any))
	})

	t.Run("narrow_exception_semantics_vs_sibling_and_important", func(t *testing.T) {
		t.Parallel()
		flt, err := filtering.New(&filtering.Config{
			Logger:            slogutil.NewDiscardLogger(),
			ProtectionEnabled: true,
		}, []filtering.Filter{
			{ID: 1, Data: []byte("||ct.sendgrid.net^\n||imp.example^$important\n")},
			{ID: rulelist.IDCustom, Data: []byte("@@||u56112681.ct.sendgrid.net^\n@@||imp.example^\n")},
		})
		require.NoError(t, err)
		flt.SetEnabled(true)
		setts := flt.Settings()
		setts.FilteringEnabled = true
		setts.ProtectionEnabled = true

		resTarget, err := flt.CheckHostRules("u56112681.ct.sendgrid.net", dns.TypeA, setts)
		require.NoError(t, err)
		assert.False(t, resTarget.IsFiltered)
		assert.Equal(t, filtering.NotFilteredAllowList, resTarget.Reason)

		resSibling, err := flt.CheckHostRules("other99.ct.sendgrid.net", dns.TypeA, setts)
		require.NoError(t, err)
		assert.True(t, resSibling.IsFiltered, "narrow subdomain exception must NOT allow sibling subdomains")

		resImp, err := flt.CheckHostRules("imp.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.True(t, resImp.IsFiltered, "normal exception must NOT override $important block")
	})

	_ = aghhttp.RegisterFunc(nil)
}
