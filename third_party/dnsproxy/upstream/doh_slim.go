//go:build android_slim

package upstream

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/ioutil"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Values to configure HTTP and HTTP/2 transport.
const (
	transportDefaultReadIdleTimeout = 30 * time.Second
	transportDefaultIdleConnTimeout = 5 * time.Minute
	dohMaxConnsPerHost              = 2
	dohMaxIdleConns                 = 2
)

// dnsOverHTTPS implements the [Upstream] interface for DNS-over-HTTPS over
// HTTP/1.1 and HTTP/2 (HTTP/3 QUIC excluded in Android slim builds).
type dnsOverHTTPS struct {
	getDialer    DialerInitializer
	addr         *url.URL
	tlsConf      *tls.Config
	client       *http.Client
	clientMu     *sync.Mutex
	logger       *slog.Logger
	transportH2  *http2.Transport
	addrRedacted string
	timeout      time.Duration
}

// newDoH returns the DNS-over-HTTPS Upstream.
func newDoH(addr *url.URL, opts *Options) (u Upstream, err error) {
	if addr.Scheme == "h3" {
		return nil, errors.Error("h3:// upstream is disabled in android_slim build; use https://")
	}

	addPort(addr, defaultPortDoH)

	httpVersions := opts.HTTPVersions
	if len(httpVersions) == 0 {
		httpVersions = DefaultHTTPVersions
	}

	ups := &dnsOverHTTPS{
		getDialer: newDialerInitializer(addr, opts),
		addr:      addr,
		tlsConf: &tls.Config{
			ServerName:         addr.Hostname(),
			RootCAs:            opts.RootCAs,
			CipherSuites:       opts.CipherSuites,
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
			MinVersion:         tls.VersionTLS12,
			// #nosec G402 -- TLS certificate verification could be disabled by configuration.
			InsecureSkipVerify:    opts.InsecureSkipVerify,
			VerifyPeerCertificate: opts.VerifyServerCertificate,
			VerifyConnection:      opts.VerifyConnection,
		},
		clientMu:     &sync.Mutex{},
		logger:       opts.Logger,
		addrRedacted: addr.Redacted(),
		timeout:      opts.Timeout,
	}
	for _, v := range httpVersions {
		if v == HTTPVersion3 {
			continue
		}
		ups.tlsConf.NextProtos = append(ups.tlsConf.NextProtos, string(v))
	}
	if len(ups.tlsConf.NextProtos) == 0 {
		ups.tlsConf.NextProtos = []string{string(HTTPVersion2), string(HTTPVersion11)}
	}

	runtime.SetFinalizer(ups, (*dnsOverHTTPS).Close)

	return ups, nil
}

// type check
var _ Upstream = (*dnsOverHTTPS)(nil)

// Address implements the [Upstream] interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Address() string { return p.addrRedacted }

// Exchange implements the [Upstream] interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	client, isCached, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("failed to init http client: %w", err)
	}

	resp, err = p.exchangeHTTPS(client, req)

	for i := 0; isCached && p.shouldRetry(err) && i < 2; i++ {
		client, err = p.resetClient(err)
		if err != nil {
			return nil, fmt.Errorf("failed to reset http client: %w", err)
		}

		resp, err = p.exchangeHTTPS(client, req)
	}

	if err != nil {
		_, resErr := p.resetClient(err)

		return nil, errors.WithDeferred(err, resErr)
	}

	return resp, nil
}

// Close implements the [Upstream] interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Close() (err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	runtime.SetFinalizer(p, nil)

	p.closeClient()

	return nil
}

// closeClient closes any idle HTTP/1.1 and HTTP/2 connections held by the
// current client and transport.  p.clientMu must be locked.
func (p *dnsOverHTTPS) closeClient() {
	if p.client != nil {
		p.client.CloseIdleConnections()
	}

	if p.transportH2 != nil {
		p.transportH2.CloseIdleConnections()
	}
}

func (p *dnsOverHTTPS) exchangeHTTPS(client *http.Client, req *dns.Msg) (resp *dns.Msg, err error) {
	logBegin(p.logger, p.addrRedacted, networkTCP, req)
	defer func() { logFinish(p.logger, p.addrRedacted, networkTCP, err) }()

	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	binary.BigEndian.PutUint16(buf, 0)

	resp, err = p.exchangeHTTPSClient(client, buf)
	if err != nil {
		return nil, fmt.Errorf("exchanging: %w", err)
	}

	if resp.Id != 0 {
		return nil, fmt.Errorf("unexpected non-zero id in response: %d", resp.Id)
	}

	resp.Id = req.Id

	err = validateResponse(req, resp)
	if err != nil {
		return nil, fmt.Errorf("validating response: %w", err)
	}

	return resp, nil
}

func (p *dnsOverHTTPS) exchangeHTTPSClient(
	client *http.Client,
	buf []byte,
) (resp *dns.Msg, err error) {
	q := url.Values{
		"dns": []string{base64.RawURLEncoding.EncodeToString(buf)},
	}

	u := url.URL{
		Scheme:   p.addr.Scheme,
		User:     p.addr.User,
		Host:     p.addr.Host,
		Path:     p.addr.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.addrRedacted, err)
	}

	httpReq.Header.Set(httphdr.UserAgent, "")
	httpReq.Header.Set(httphdr.Accept, "application/dns-message")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", p.addrRedacted, err)
	}
	defer slogutil.CloseAndLog(httpReq.Context(), p.logger, httpResp.Body, slog.LevelDebug)

	limitBody := ioutil.LimitReader(httpResp.Body, dns.MaxMsgSize)
	body, err := io.ReadAll(limitBody)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.addrRedacted, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"expected status %d, got %d from %s",
			http.StatusOK,
			httpResp.StatusCode,
			p.addrRedacted,
		)
	}

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf(
			"unpacking response from %s: body is %s: %w",
			p.addrRedacted,
			body,
			err,
		)
	}

	return resp, nil
}

func (p *dnsOverHTTPS) shouldRetry(err error) (ok bool) {
	if err == nil {
		return false
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (p *dnsOverHTTPS) resetClient(resetErr error) (client *http.Client, err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	p.closeClient()
	p.client = nil
	p.transportH2 = nil

	p.logger.Debug("recreating the http client", slogutil.KeyError, resetErr)
	p.client, err = p.createClient()

	return p.client, err
}

func (p *dnsOverHTTPS) getClient() (c *http.Client, isCached bool, err error) {
	startTime := time.Now()

	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	if p.client != nil {
		return p.client, true, nil
	}

	elapsed := time.Since(startTime)
	if p.timeout > 0 && elapsed > p.timeout {
		return nil, false, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	p.logger.Debug("creating a new http client")
	p.client, err = p.createClient()

	return p.client, false, err
}

func (p *dnsOverHTTPS) createClient() (*http.Client, error) {
	transport, err := p.createTransport()
	if err != nil {
		return nil, fmt.Errorf("initializing http transport: %w", err)
	}

	p.client = &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
	}

	return p.client, nil
}

func (p *dnsOverHTTPS) createTransport() (t http.RoundTripper, err error) {
	dialContext, err := p.getDialer()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.addrRedacted, err)
	}

	transport := &http.Transport{
		TLSClientConfig:    p.tlsConf.Clone(),
		DisableCompression: true,
		DialContext:        dialContext,
		IdleConnTimeout:    transportDefaultIdleConnTimeout,
		MaxConnsPerHost:    dohMaxConnsPerHost,
		MaxIdleConns:       dohMaxIdleConns,
		ForceAttemptHTTP2:  true,
	}

	p.transportH2, err = http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	p.transportH2.ReadIdleTimeout = transportDefaultReadIdleTimeout

	return transport, nil
}
