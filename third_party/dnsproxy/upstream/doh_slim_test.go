//go:build android_slim

package upstream

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDoHTestServer(t *testing.T, enableH2 bool, handler http.HandlerFunc) (srv *httptest.Server, activeConns, idleConns *atomic.Int32) {
	t.Helper()

	active := &atomic.Int32{}
	idle := &atomic.Int32{}

	srv = httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = enableH2
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			active.Add(1)
		case http.StateIdle:
			idle.Add(1)
		case http.StateActive:
			// If transitioning from idle to active, decrement idle if > 0.
			for {
				cur := idle.Load()
				if cur <= 0 || idle.CompareAndSwap(cur, cur-1) {
					break
				}
			}
		case http.StateClosed, http.StateHijacked:
			active.Add(-1)
		}
	}
	if enableH2 {
		srv.StartTLS()
	} else {
		srv.TLS = &tls.Config{
			NextProtos: []string{"http/1.1"},
		}
		srv.StartTLS()
	}
	t.Cleanup(srv.Close)

	return srv, active, idle
}

func defaultDNSHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := &dns.Msg{}
		req.SetQuestion("example.org.", dns.TypeA)
		resp := &dns.Msg{}
		resp.SetReply(req)
		resp.Id = 0
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.org.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(93, 184, 216, 34),
			},
		}
		packed, err := resp.Pack()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packed)
	}
}

func TestDoHSlim_HTTP11IdleConnClosedOnCloseAndReset(t *testing.T) {
	srv, activeConns, _ := newDoHTestServer(t, false, defaultDNSHandler(t))

	u, err := url.Parse(srv.URL + "/dns-query")
	require.NoError(t, err)

	upsIface, err := newDoH(u, &Options{
		Logger:             slogutil.NewDiscardLogger(),
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
		HTTPVersions:       []HTTPVersion{HTTPVersion11},
	})
	require.NoError(t, err)
	ups := upsIface.(*dnsOverHTTPS)

	req := &dns.Msg{}
	req.SetQuestion("example.org.", dns.TypeA)

	resp, err := ups.Exchange(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// After HTTP/1.1 keep-alive exchange, the connection remains open in idle pool.
	require.Eventually(t, func() bool {
		return activeConns.Load() == 1
	}, 2*time.Second, 10*time.Millisecond)

	// Resetting client must close the old HTTP/1.1 idle connection.
	_, err = ups.resetClient(assert.AnError)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return activeConns.Load() == 0
	}, 2*time.Second, 10*time.Millisecond)

	// Perform another exchange to create a new HTTP/1.1 idle connection.
	resp, err = ups.Exchange(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Eventually(t, func() bool {
		return activeConns.Load() == 1
	}, 2*time.Second, 10*time.Millisecond)

	// Closing upstream must close the HTTP/1.1 idle connection, and repeated Close must be safe.
	require.NoError(t, ups.Close())
	require.NoError(t, ups.Close())
	require.Eventually(t, func() bool {
		return activeConns.Load() == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestDoHSlim_HTTP2PathAndActiveRequestSafety(t *testing.T) {
	inFlightEntered := make(chan struct{})
	releaseInFlight := make(chan struct{})
	var blockFirst atomic.Bool
	blockFirst.Store(true)

	baseHandler := defaultDNSHandler(t)
	srv, activeConns, _ := newDoHTestServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		if blockFirst.CompareAndSwap(true, false) {
			close(inFlightEntered)
			<-releaseInFlight
		}
		baseHandler(w, r)
	})

	u, err := url.Parse(srv.URL + "/dns-query")
	require.NoError(t, err)

	upsIface, err := newDoH(u, &Options{
		Logger:             slogutil.NewDiscardLogger(),
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
		HTTPVersions:       []HTTPVersion{HTTPVersion2, HTTPVersion11},
	})
	require.NoError(t, err)
	ups := upsIface.(*dnsOverHTTPS)

	req := &dns.Msg{}
	req.SetQuestion("example.org.", dns.TypeA)

	var wg sync.WaitGroup
	var inFlightResp *dns.Msg
	var inFlightErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		inFlightResp, inFlightErr = ups.Exchange(req)
	}()

	<-inFlightEntered

	// Calling Close() while a request is in-flight must NOT kill the active request.
	require.NoError(t, ups.Close())

	close(releaseInFlight)
	wg.Wait()

	require.NoError(t, inFlightErr)
	require.NotNil(t, inFlightResp)

	// Subsequent Exchange and Close work and clean up idle H2 connection.
	resp, err := ups.Exchange(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.NoError(t, ups.Close())
	require.Eventually(t, func() bool {
		return activeConns.Load() == 0
	}, 2*time.Second, 10*time.Millisecond)
}
