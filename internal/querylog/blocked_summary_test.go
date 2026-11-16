package querylog

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testReg map[string]http.HandlerFunc

func (r testReg) Register(method, path string, h http.HandlerFunc) {
	r[method+" "+path] = h
}

func makeQuestion(host string) *dns.Msg {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	return m
}

func TestBlockedSummary_RetainsSendGridAcrossRawRingEviction(t *testing.T) {
	t.Parallel()

	reg := make(testReg)
	var anonIP atomic.Bool
	anonymizer := &aghnet.IPMut{}
	anonymizer.Store(func(ip net.IP) {
		if anonIP.Load() {
			AnonymizeIP(ip)
		}
	})

	ql, err := newQueryLog(Config{
		Logger:      slogutil.NewDiscardLogger(),
		Enabled:     true,
		FileEnabled: false,
		RotationIvl: timeutil.Day,
		MemSize:     10,
		BaseDir:     t.TempDir(),
		Anonymizer:  anonymizer,
		HTTPReg:     reg,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, 5*time.Second)
	require.NoError(t, ql.Start(ctx))
	t.Cleanup(func() { _ = ql.Shutdown(ctx) })

	now := time.Now()
	ql.blockedSummary.now = func() time.Time { return now }

	// 1) Record a single critical SendGrid SNI block.
	ql.Add(&AddParams{
		Question: makeQuestion("u56112681.ct.sendgrid.net"),
		ClientIP: net.ParseIP("192.168.1.55"),
		Dst:      "1.2.3.4:443",
		Result: &filtering.Result{
			IsFiltered: true,
			Reason:     filtering.FilteredSNI,
			Rules: []*filtering.ResultRule{{
				FilterListID: 12,
				Text:         "||ct.sendgrid.net^",
			}},
		},
	})

	// 2) Flood raw MemSize=10 ring with 50 noisy Google retries -> SendGrid is evicted from raw ring.
	for i := range 50 {
		ql.Add(&AddParams{
			Question: makeQuestion("ogads-pa.clients6.google.com"),
			ClientIP: net.ParseIP("192.168.1.55"),
			Result: &filtering.Result{
				IsFiltered: true,
				Reason:     filtering.FilteredBlockList,
				Rules: []*filtering.ResultRule{{
					FilterListID: 1,
					Text:         "||ogads-pa.clients6.google.com^",
				}},
			},
		})
		_ = i
	}

	// Verify raw ring lost SendGrid.
	reqRaw := httptest.NewRequest(http.MethodGet, "/control/querylog?response_status=blocked&search=sendgrid", nil)
	rwRaw := httptest.NewRecorder()
	reg[http.MethodGet+" /control/querylog"](rwRaw, reqRaw)
	var rawBody map[string]any
	require.NoError(t, json.Unmarshal(rwRaw.Body.Bytes(), &rawBody))
	assert.Empty(t, rawBody["data"].([]any), "raw 10-entry ring was evicted by Google retries")

	// Verify /control/querylog/blocked_summary retained SendGrid AND folded 50 Google retries into 1 row.
	reqSum := httptest.NewRequest(http.MethodGet, "/control/querylog/blocked_summary", nil)
	rwSum := httptest.NewRecorder()
	reg[http.MethodGet+" /control/querylog/blocked_summary"](rwSum, reqSum)
	require.Equal(t, http.StatusOK, rwSum.Code)

	var sumBody map[string]any
	require.NoError(t, json.Unmarshal(rwSum.Body.Bytes(), &sumBody))
	assert.Equal(t, float64(blockedSummaryMaxEntries), sumBody["max_entries"])
	assert.Equal(t, float64(300), sumBody["ttl_seconds"])
	sumRows := sumBody["data"].([]any)
	require.Len(t, sumRows, 2)

	byDomain := map[string]map[string]any{}
	for _, r := range sumRows {
		m := r.(map[string]any)
		byDomain[m["domain"].(string)] = m
	}
	assert.Equal(t, float64(1), byDomain["u56112681.ct.sendgrid.net"]["count"])
	assert.Equal(t, true, byDomain["u56112681.ct.sendgrid.net"]["is_sni"])
	assert.Equal(t, float64(50), byDomain["ogads-pa.clients6.google.com"]["count"])

	// 3) Paused / allowed NotFilteredSNI entry with PredictedBlocked must NOT enter summary.
	ql.Add(&AddParams{
		Question:         makeQuestion("paused.example"),
		ClientIP:         net.ParseIP("192.168.1.55"),
		PredictedBlocked: true,
		Result: &filtering.Result{
			IsFiltered: false,
			Reason:     filtering.NotFilteredSNI,
			Rules:      []*filtering.ResultRule{{FilterListID: 1, Text: "||paused.example^"}},
		},
	})
	rwPause := httptest.NewRecorder()
	reg[http.MethodGet+" /control/querylog/blocked_summary"](rwPause, httptest.NewRequest(http.MethodGet, "/control/querylog/blocked_summary?search=paused.example", nil))
	var pauseBody map[string]any
	require.NoError(t, json.Unmarshal(rwPause.Body.Bytes(), &pauseBody))
	assert.Empty(t, pauseBody["data"].([]any))

	// 4) AnonymizeClientIP masks IP in summary output.
	anonIP.Store(true)
	rwAnon := httptest.NewRecorder()
	reg[http.MethodGet+" /control/querylog/blocked_summary"](rwAnon, httptest.NewRequest(http.MethodGet, "/control/querylog/blocked_summary?search=sendgrid", nil))
	var anonBody map[string]any
	require.NoError(t, json.Unmarshal(rwAnon.Body.Bytes(), &anonBody))
	anonRow := anonBody["data"].([]any)[0].(map[string]any)
	assert.Equal(t, "192.168.0.0", anonRow["client"])
	_, hasClientInfo := anonRow["client_info"]
	assert.False(t, hasClientInfo)

	// 5) Capacity bound (>256 distinct domains evicts oldest) & lazy TTL expiry.
	for i := range 270 {
		ql.Add(&AddParams{
			Question: makeQuestion(fmt.Sprintf("cap-%03d.example", i)),
			ClientIP: net.ParseIP("10.0.0.1"),
			Result: &filtering.Result{
				IsFiltered: true,
				Reason:     filtering.FilteredBlockList,
				Rules:      []*filtering.ResultRule{{FilterListID: 1, Text: fmt.Sprintf("||cap-%03d.example^", i)}},
			},
		})
	}
	rwCap := httptest.NewRecorder()
	reg[http.MethodGet+" /control/querylog/blocked_summary"](rwCap, httptest.NewRequest(http.MethodGet, "/control/querylog/blocked_summary", nil))
	var capBody map[string]any
	require.NoError(t, json.Unmarshal(rwCap.Body.Bytes(), &capBody))
	assert.LessOrEqual(t, len(capBody["data"].([]any)), blockedSummaryMaxEntries)

	// Clear wipes summary cleanly.
	reg[http.MethodPost+" /control/querylog_clear"](httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/control/querylog_clear", nil))
	rwCleared := httptest.NewRecorder()
	reg[http.MethodGet+" /control/querylog/blocked_summary"](rwCleared, httptest.NewRequest(http.MethodGet, "/control/querylog/blocked_summary", nil))
	var clearedBody map[string]any
	require.NoError(t, json.Unmarshal(rwCleared.Body.Bytes(), &clearedBody))
	assert.Empty(t, clearedBody["data"].([]any))

	// TTL lazy expiration (>5m).
	ql.Add(&AddParams{
		Question: makeQuestion("ttl-test.example"),
		ClientIP: net.ParseIP("10.0.0.1"),
		Result: &filtering.Result{
			IsFiltered: true,
			Reason:     filtering.FilteredSNI,
			Rules:      []*filtering.ResultRule{{FilterListID: 1, Text: "||ttl-test.example^"}},
		},
	})
	now = now.Add(6 * time.Minute)
	rwExpired := httptest.NewRecorder()
	reg[http.MethodGet+" /control/querylog/blocked_summary"](rwExpired, httptest.NewRequest(http.MethodGet, "/control/querylog/blocked_summary", nil))
	var expiredBody map[string]any
	require.NoError(t, json.Unmarshal(rwExpired.Body.Bytes(), &expiredBody))
	assert.Empty(t, expiredBody["data"].([]any))
}
