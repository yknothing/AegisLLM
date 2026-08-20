package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/requestid"
	"github.com/yknothing/AegisLLM/internal/utils"
)

const oversizedScannerDefaultLineSize = 70 * 1024

func TestValidateEgressRequiresAllowlist(t *testing.T) {
	engine := NewEngine(StreamConfig{})

	if err := engine.validateEgress("https://api.openai.com/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted a target with no allowlist")
	}
}

func TestValidateEgressMatchesNormalizedHost(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("https://api.openai.com/v1/chat/completions"); err != nil {
		t.Fatalf("validateEgress rejected allowed host: %v", err)
	}
}

func TestValidateEgressRejectsImplicitSubdomain(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("https://tenant.api.openai.com/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted implicit subdomain without wildcard")
	}
}

func TestValidateEgressAllowsExplicitWildcardSubdomain(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"*.openai.com"},
	})

	if err := engine.validateEgress("https://api.openai.com/v1/chat/completions"); err != nil {
		t.Fatalf("validateEgress rejected explicit wildcard subdomain: %v", err)
	}
}

func TestValidateEgressRejectsSubstringBypass(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("https://api.openai.com.evil.example/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted substring host bypass")
	}
}

func TestValidateEgressRejectsNonHTTPS(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("http://api.openai.com/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted non-HTTPS egress")
	}
}

func TestValidateEgressRejectsUserinfoAndFragment(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	tests := []string{
		"https://user:password@api.openai.com/v1/chat/completions",
		"https://api.openai.com/v1/chat/completions#unexpected",
		"https://api.openai.com/v1/chat/completions#",
		"https://api.openai.com:/v1/chat/completions",
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			if err := engine.validateEgress(target); err == nil {
				t.Fatalf("validateEgress accepted unsafe target %q", target)
			}
		})
	}
}

func TestValidateEgressRequiresExactNonDefaultPort(t *testing.T) {
	hostOnly := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})
	if err := hostOnly.validateEgress("https://api.openai.com:8443/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress let a host-only rule authorize a non-default port")
	}

	exactPort := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com:8443"},
	})
	if err := exactPort.validateEgress("https://api.openai.com:8443/v1/chat/completions"); err != nil {
		t.Fatalf("validateEgress rejected exact non-default port: %v", err)
	}
}

func TestValidateEgressRequiresExactIPLiteralAndPort(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"127.0.0.1:8443"},
	})
	if err := engine.validateEgress("https://127.0.0.1:8443/v1/chat/completions"); err != nil {
		t.Fatalf("validateEgress rejected exact IP literal and port: %v", err)
	}
	if err := engine.validateEgress("https://127.0.0.1:443/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted an IP literal on a different port")
	}
}

func TestNewEngineRequiresTLS13ForUpstreamTransport(t *testing.T) {
	engine := NewEngine(StreamConfig{})

	transport, ok := engine.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", engine.client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
}

func TestDialContextRejectsAnyUnsafeDNSAnswerBeforeDial(t *testing.T) {
	unsafeAddresses := []string{
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"0.0.0.0",
		"224.0.0.1",
		"192.0.2.1",
		"192.31.196.1",
		"192.52.193.1",
		"192.88.99.1",
		"192.175.48.1",
		"::1",
		"fc00::1",
		"fe80::1",
		"ff02::1",
		"100:0:0:1::1",
		"2001:100::1",
		"2001:db8::1",
		"2620:4f:8000::1",
		"3000::1",
		"3ffe::1",
		"4000::1",
		"6000::1",
	}
	for _, unsafeAddress := range unsafeAddresses {
		t.Run(unsafeAddress, func(t *testing.T) {
			resolver := &staticIPResolver{addresses: []netip.Addr{
				netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr(unsafeAddress),
			}}
			dialer := &recordingContextDialer{err: errors.New("dial should not run")}
			engine := NewEngine(StreamConfig{AllowedDomains: []string{"api.openai.com"}})
			engine.resolver = resolver
			engine.dialer = dialer

			if _, err := engine.dialContext(context.Background(), "tcp", "api.openai.com:443"); err == nil {
				t.Fatal("dialContext accepted an unsafe DNS answer")
			}
			if len(dialer.addresses) != 0 {
				t.Fatalf("dialContext dialed %v before rejecting unsafe DNS answer", dialer.addresses)
			}
		})
	}
}

func TestDialContextDialsValidatedIPWithoutReresolving(t *testing.T) {
	stopErr := errors.New("stop after recording validated address")
	resolver := &staticIPResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	dialer := &recordingContextDialer{err: stopErr}
	engine := NewEngine(StreamConfig{AllowedDomains: []string{"api.openai.com"}})
	engine.resolver = resolver
	engine.dialer = dialer

	if _, err := engine.dialContext(context.Background(), "tcp", "api.openai.com:443"); !errors.Is(err, stopErr) {
		t.Fatalf("dialContext error = %v, want recording dialer error", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}
	if got, want := dialer.addresses, []string{"93.184.216.34:443"}; !slicesEqual(got, want) {
		t.Fatalf("dial addresses = %v, want %v", got, want)
	}
}

func TestDialContextAllowsOnlyExplicitExactIPLiteral(t *testing.T) {
	stopErr := errors.New("stop after recording explicit IP")
	resolver := &staticIPResolver{err: errors.New("IP literal must not use DNS")}
	dialer := &recordingContextDialer{err: stopErr}
	engine := NewEngine(StreamConfig{AllowedDomains: []string{"127.0.0.1:8443"}})
	engine.resolver = resolver
	engine.dialer = dialer

	if _, err := engine.dialContext(context.Background(), "tcp", "127.0.0.1:8443"); !errors.Is(err, stopErr) {
		t.Fatalf("dialContext error = %v, want recording dialer error", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want 0", resolver.calls)
	}
	if got, want := dialer.addresses, []string{"127.0.0.1:8443"}; !slicesEqual(got, want) {
		t.Fatalf("dial addresses = %v, want %v", got, want)
	}

	dialer.addresses = nil
	if _, err := engine.dialContext(context.Background(), "tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("dialContext accepted an IP literal on an unauthorized port")
	}
	if len(dialer.addresses) != 0 {
		t.Fatalf("dialContext dialed unauthorized IP endpoint %v", dialer.addresses)
	}
}

func TestProxyRequestResolvesAndDialsValidatedIPWhileTLSUsesOriginalHostname(t *testing.T) {
	type providerObservation struct {
		serverName    string
		host          string
		authorization string
	}
	observations := make(chan providerObservation, 2)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation := providerObservation{host: r.Host, authorization: r.Header.Get("Authorization")}
		if r.TLS != nil {
			observation.serverName = r.TLS.ServerName
		}
		observations <- observation
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"provider-response","choices":[]}`)
	}))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	certificate := upstream.Certificate()
	if len(certificate.DNSNames) == 0 {
		t.Fatal("httptest TLS certificate has no DNS name for hostname verification")
	}
	providerHost := certificate.DNSNames[0]
	_, providerPort, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split upstream listener address: %v", err)
	}
	providerAuthority := net.JoinHostPort(providerHost, providerPort)

	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	resolver := &staticIPResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	dialer := &redirectingContextDialer{target: upstream.Listener.Addr().String()}
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{providerAuthority},
		RootCAs:        roots,
	})
	engine.resolver = resolver
	engine.dialer = dialer
	transport := engine.client.Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	engine.client.Transport = transport

	targetURL := "https://" + providerAuthority + "/v1/chat/completions"
	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o"}`))
		recorder := httptest.NewRecorder()
		apiKey := utils.NewSecureBytes([]byte("provider-secret"))
		result, err := engine.ProxyRequest(req.Context(), recorder, req, targetURL, apiKey, false)
		if err != nil {
			t.Fatalf("request %d: ProxyRequest returned error: %v", requestNumber, err)
		}
		if result.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", requestNumber, result.StatusCode, http.StatusOK)
		}
	}

	if resolver.calls != 2 {
		t.Fatalf("resolver calls = %d, want one per fresh connection", resolver.calls)
	}
	for index, host := range resolver.hosts {
		if host != providerHost {
			t.Fatalf("resolver host %d = %q, want original hostname %q", index, host, providerHost)
		}
	}
	for index, network := range resolver.networks {
		if network != "ip" {
			t.Fatalf("resolver network %d = %q, want ip", index, network)
		}
	}
	expectedDialAuthority := net.JoinHostPort("93.184.216.34", providerPort)
	if got, want := dialer.addresses, []string{expectedDialAuthority, expectedDialAuthority}; !slicesEqual(got, want) {
		t.Fatalf("dial addresses = %v, want validated IP authorities %v", got, want)
	}
	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		observation := <-observations
		if observation.serverName != providerHost {
			t.Fatalf("request %d: TLS SNI = %q, want original hostname %q", requestNumber, observation.serverName, providerHost)
		}
		if observation.host != providerAuthority {
			t.Fatalf("request %d: provider Host = %q, want %q", requestNumber, observation.host, providerAuthority)
		}
		if observation.authorization != "Bearer provider-secret" {
			t.Fatalf("request %d: authorization = %q, want provider credential", requestNumber, observation.authorization)
		}
	}
}

type staticIPResolver struct {
	addresses []netip.Addr
	err       error
	calls     int
	networks  []string
	hosts     []string
}

func (r *staticIPResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls++
	r.networks = append(r.networks, network)
	r.hosts = append(r.hosts, host)
	return append([]netip.Addr(nil), r.addresses...), r.err
}

type recordingContextDialer struct {
	addresses []string
	err       error
}

func (d *recordingContextDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, address)
	return nil, d.err
}

type redirectingContextDialer struct {
	target    string
	addresses []string
}

func (d *redirectingContextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, address)
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestProxyRequestTLS13EndToEnd(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("upstream TLS version = %v, want TLS 1.3", r.TLS)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer provider-secret" {
			t.Errorf("authorization = %q, want provider credential", got)
		}
		for _, header := range []string{"X-Api-Key", "X-Admin-Token", "X-Forwarded-For"} {
			if got := r.Header.Get(header); got != "" {
				t.Errorf("sensitive client header %s reached upstream: %q", header, got)
			}
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request body: %v", err)
		}
		if got, want := string(body), `{"model":"gpt-4o","messages":[]}`; got != want {
			t.Errorf("upstream body = %q, want %q", got, want)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(requestid.Header, "provider-request-1")
		w.Header().Set("Set-Cookie", "provider-session=secret")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"chatcmpl-test","choices":[]}`)
	}))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{upstream.Listener.Addr().String()},
	})
	transport := engine.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	transport.TLSClientConfig.RootCAs = roots
	engine.client.Transport = transport

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "client-secret")
	req.Header.Set("X-Admin-Token", "admin-secret")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	recorder := httptest.NewRecorder()
	apiKey := utils.NewSecureBytes([]byte("provider-secret"))

	result, err := engine.ProxyRequest(req.Context(), recorder, req, upstream.URL+"/v1/chat/completions", apiKey, false)
	if err != nil {
		t.Fatalf("ProxyRequest returned error: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if apiKey.Len() != 0 {
		t.Fatal("provider credential was not zeroed after upstream response headers")
	}

	response := recorder.Result()
	defer func() { _ = response.Body.Close() }()
	if got := response.Header.Get("X-Upstream-Request-Id"); got != "provider-request-1" {
		t.Fatalf("upstream request id = %q, want provider-request-1", got)
	}
	if got := response.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("unsafe upstream cookie reached client: %q", got)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if got, want := string(body), `{"id":"chatcmpl-test","choices":[]}`; got != want {
		t.Fatalf("response body = %q, want %q", got, want)
	}
}

func TestProxyRequestClassifiesUpstreamTransportFailure(t *testing.T) {
	engine := NewEngine(StreamConfig{AllowedDomains: []string{"api.openai.com"}})
	engine.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	apiKey := utils.NewSecureBytes([]byte("provider-secret"))

	_, err := engine.ProxyRequest(req.Context(), httptest.NewRecorder(), req, "https://api.openai.com/v1/chat/completions", apiKey, false)
	if !errors.Is(err, ErrUpstreamTransport) {
		t.Fatalf("ProxyRequest error = %v, want ErrUpstreamTransport", err)
	}
	if apiKey.Len() != 0 {
		t.Fatal("provider credential was not zeroed after transport failure")
	}
}

func TestProxyRequestRejectsUnsafeProviderCredentialBeforeTransport(t *testing.T) {
	tests := []struct {
		name       string
		credential []byte
	}{
		{name: "embedded newline", credential: []byte("sk-first\nsk-second")},
		{name: "embedded carriage return", credential: []byte("sk-first\rsk-second")},
		{name: "NUL", credential: []byte{'s', 'k', 0, 'x'}},
		{name: "control", credential: []byte{'s', 'k', 0x1f, 'x'}},
		{name: "DEL", credential: []byte{'s', 'k', 0x7f, 'x'}},
		{name: "non ASCII", credential: []byte("sk-密钥")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transportCalled := false
			engine := NewEngine(StreamConfig{AllowedDomains: []string{"api.openai.com"}})
			engine.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalled = true
				return nil, errors.New("transport must not be called")
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
			apiKey := utils.NewSecureBytes(append([]byte(nil), tt.credential...))
			secret := string(tt.credential)

			result, err := engine.ProxyRequest(
				req.Context(),
				httptest.NewRecorder(),
				req,
				"https://api.openai.com/v1/chat/completions",
				apiKey,
				false,
			)
			if result != nil || err == nil {
				t.Fatalf("ProxyRequest result=%v error=%v, want pre-transport rejection", result, err)
			}
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Fatal("ProxyRequest reflected the rejected provider credential")
			}
			if transportCalled {
				t.Fatal("ProxyRequest reached the transport with an unsafe credential")
			}
			if apiKey.Len() != 0 {
				t.Fatal("ProxyRequest did not zero the rejected provider credential")
			}
		})
	}
}

func TestProxyRequestDoesNotClassifyClientCancellationAsProviderFailure(t *testing.T) {
	engine := NewEngine(StreamConfig{AllowedDomains: []string{"api.openai.com"}})
	engine.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, req.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`)).WithContext(ctx)
	apiKey := utils.NewSecureBytes([]byte("provider-secret"))

	_, err := engine.ProxyRequest(ctx, httptest.NewRecorder(), req, "https://api.openai.com/v1/chat/completions", apiKey, false)
	if err == nil {
		t.Fatal("ProxyRequest accepted a canceled client context")
	}
	if errors.Is(err, ErrUpstreamTransport) {
		t.Fatalf("client cancellation was classified as provider transport failure: %v", err)
	}
	if apiKey.Len() != 0 {
		t.Fatal("provider credential was not zeroed after client cancellation")
	}
}

func TestProxyRequestDoesNotClassifyClientCancellationAfterResponseHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	engine := NewEngine(StreamConfig{AllowedDomains: []string{"api.openai.com"}})
	engine.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       &cancelingReadCloser{cancel: cancel},
		}, nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`)).WithContext(ctx)
	apiKey := utils.NewSecureBytes([]byte("provider-secret"))

	result, err := engine.ProxyRequest(ctx, httptest.NewRecorder(), req, "https://api.openai.com/v1/chat/completions", apiKey, false)
	if result == nil || result.StatusCode != http.StatusOK {
		t.Fatalf("result = %#v, want upstream 200 result", result)
	}
	if err == nil {
		t.Fatal("ProxyRequest accepted a canceled response read")
	}
	if errors.Is(err, ErrUpstreamRead) || errors.Is(err, ErrUpstreamTransport) {
		t.Fatalf("client cancellation was classified as provider failure: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type cancelingReadCloser struct {
	cancel context.CancelFunc
}

func (r *cancelingReadCloser) Read([]byte) (int, error) {
	r.cancel()
	return 0, context.Canceled
}

func (r *cancelingReadCloser) Close() error { return nil }

func TestForwardResponsePrefersClientWriteFailureWhenReadAlsoFails(t *testing.T) {
	engine := NewEngine(StreamConfig{})
	upstreamErr := errors.New("upstream read failed")
	clientErr := errors.New("client write failed")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: &readOnceErrorCloser{
			body: []byte(`{"partial":true}`),
			err:  upstreamErr,
		},
	}
	w := &failingResponseWriter{header: make(http.Header), err: clientErr}

	err := engine.forwardResponse(w, resp)
	if err == nil || !errors.Is(err, clientErr) {
		t.Fatalf("forwardResponse error = %v, want client write failure", err)
	}
	if errors.Is(err, ErrUpstreamRead) {
		t.Fatalf("client write failure was classified as upstream read failure: %v", err)
	}
}

func TestForwardResponseClassifiesUpstreamReadFailure(t *testing.T) {
	engine := NewEngine(StreamConfig{})
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       &readOnceErrorCloser{err: errors.New("upstream read failed")},
	}

	err := engine.forwardResponse(httptest.NewRecorder(), resp)
	if !errors.Is(err, ErrUpstreamRead) {
		t.Fatalf("forwardResponse error = %v, want ErrUpstreamRead", err)
	}
}

type readOnceErrorCloser struct {
	body []byte
	err  error
	done bool
}

func (r *readOnceErrorCloser) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.body), r.err
}

func (r *readOnceErrorCloser) Close() error { return nil }

type failingResponseWriter struct {
	header http.Header
	err    error
}

func (w *failingResponseWriter) Header() http.Header       { return w.header }
func (w *failingResponseWriter) WriteHeader(int)           {}
func (w *failingResponseWriter) Write([]byte) (int, error) { return 0, w.err }

func TestStreamSSEForwardsLargeDataLine(t *testing.T) {
	engine := NewEngine(StreamConfig{})
	largeContent := strings.Repeat("x", oversizedScannerDefaultLineSize)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			`data: {"choices":[{"delta":{"content":"` + largeContent + `"}}]}` + "\n" +
				`data: [DONE]` + "\n",
		)),
	}

	recorder := httptest.NewRecorder()
	tokens, err := engine.streamSSE(recorder, resp)
	if err != nil {
		t.Fatalf("streamSSE returned error for large data line: %v", err)
	}
	if tokens != 1 {
		t.Fatalf("tokens = %d, want 1", tokens)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, largeContent) {
		t.Fatal("streamSSE did not forward the large SSE data line")
	}
	if !strings.Contains(body, "data: [DONE]") {
		t.Fatal("streamSSE did not forward the done marker")
	}
}

func TestStreamSSERejectsOversizedDataLine(t *testing.T) {
	engine := NewEngine(StreamConfig{})
	largeContent := strings.Repeat("x", sseScannerMaxLineSize+1)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			`data: {"choices":[{"delta":{"content":"` + largeContent + `"}}]}` + "\n",
		)),
	}

	recorder := httptest.NewRecorder()
	if _, err := engine.streamSSE(recorder, resp); !errors.Is(err, ErrUpstreamRead) {
		t.Fatalf("streamSSE error = %v, want ErrUpstreamRead", err)
	}
}

func TestCopyHeadersAllowsOnlySafeProviderRequestHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("Accept", "application/json")
	src.Set("Content-Type", "application/json")
	src.Set("Authorization", "Bearer client")
	src.Set("X-Api-Key", "client-key")
	src.Set("X-Admin-Token", "admin-token")
	src.Set("OpenAI-Organization", "org-client")
	src.Set("OpenAI-Project", "proj-client")
	src.Set("X-Request-Id", "req-client")
	src.Set("X-Forwarded-For", "203.0.113.1")
	src.Set("X-Forwarded-Host", "internal.example")
	src.Set("X-Forwarded-Proto", "http")
	src.Set("Forwarded", "for=203.0.113.1")
	src.Set("Keep-Alive", "timeout=5")
	src.Set("Te", "trailers")
	src.Set("Trailer", "Expires")
	src.Set("Transfer-Encoding", "chunked")
	src.Set("Upgrade", "websocket")
	src.Set("User-Agent", "aegis-test")

	dst := http.Header{}
	copyHeaders(dst, src)

	for _, header := range []string{
		"Authorization",
		"X-Api-Key",
		"X-Admin-Token",
		"OpenAI-Organization",
		"OpenAI-Project",
		"X-Request-Id",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Forwarded",
		"Keep-Alive",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		if got := dst.Get(header); got != "" {
			t.Fatalf("copyHeaders forwarded sensitive header %s=%q", header, got)
		}
	}
	if got := dst.Get("Accept"); got != "application/json" {
		t.Fatalf("copyHeaders stripped safe Accept header: %q", got)
	}
	if got := dst.Get("Content-Type"); got != "application/json" {
		t.Fatalf("copyHeaders stripped safe Content-Type header: %q", got)
	}
	if got := dst.Get("User-Agent"); got != "aegis-test" {
		t.Fatalf("copyHeaders stripped safe User-Agent header: %q", got)
	}
}

func TestForwardResponseAllowsOnlySafeUpstreamHeaders(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":                       []string{"application/json"},
			"X-Request-Id":                       []string{"req-upstream", "bad/upstream", strings.Repeat("a", requestid.MaxLength+1)},
			"RateLimit-Remaining":                []string{"60"},
			"X-Ratelimit-Remaining-Requests":     []string{"59"},
			"Retry-After":                        []string{"1"},
			"Set-Cookie":                         []string{"session=upstream"},
			"Connection":                         []string{"close"},
			"Transfer-Encoding":                  []string{"chunked"},
			"Proxy-Authenticate":                 []string{"Basic realm=\"upstream\""},
			"Proxy-Authorization":                []string{"Bearer upstream"},
			"Keep-Alive":                         []string{"timeout=5"},
			"Te":                                 []string{"trailers"},
			"Trailer":                            []string{"Expires"},
			"Upgrade":                            []string{"websocket"},
			"OpenAI-Organization":                []string{"org-upstream"},
			"X-Provider-Account":                 []string{"provider-account"},
			"X-Debug-Trace":                      []string{"debug-context"},
			"WWW-Authenticate":                   []string{"Bearer realm=\"upstream\""},
			"Server":                             []string{"upstream-server"},
			"Access-Control-Allow-Credentials":   []string{"true"},
			"Access-Control-Allow-Origin":        []string{"https://upstream.example"},
			"Access-Control-Expose-Headers":      []string{"Set-Cookie"},
			"Content-Security-Policy":            []string{"default-src 'none'"},
			"Strict-Transport-Security":          []string{"max-age=31536000"},
			"X-Accel-Redirect":                   []string{"/internal/secret"},
			"X-Amzn-Trace-Id":                    []string{"Root=1-trace"},
			"X-Internal-Request-Id":              []string{"internal-req"},
			"X-Openai-Assistance-Conversation":   []string{"conversation"},
			"X-Openai-Organization":              []string{"org-upstream"},
			"X-Openai-Project":                   []string{"proj-upstream"},
			"X-RateLimit-Policy":                 []string{"internal-policy"},
			"X-Upstream-Authorization-Challenge": []string{"challenge"},
		},
		Body: io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}

	recorder := httptest.NewRecorder()
	if err := engine.forwardResponse(recorder, resp); err != nil {
		t.Fatalf("forwardResponse returned error: %v", err)
	}

	result := recorder.Result()
	defer func() {
		_ = result.Body.Close()
	}()
	for _, header := range []string{
		"Set-Cookie",
		"Connection",
		"Transfer-Encoding",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Keep-Alive",
		"Te",
		"Trailer",
		"Upgrade",
		"OpenAI-Organization",
		"X-Provider-Account",
		"X-Debug-Trace",
		"WWW-Authenticate",
		"Server",
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Origin",
		"Access-Control-Expose-Headers",
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Accel-Redirect",
		"X-Amzn-Trace-Id",
		"X-Internal-Request-Id",
		"X-Openai-Assistance-Conversation",
		"X-Openai-Organization",
		"X-Openai-Project",
		"X-RateLimit-Policy",
		"X-Upstream-Authorization-Challenge",
	} {
		if got := result.Header.Get(header); got != "" {
			t.Fatalf("forwardResponse copied unsafe header %s=%q", header, got)
		}
	}
	if got := result.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	if got := result.Header.Get("X-Request-Id"); got != "" {
		t.Fatalf("gateway request id was overwritten by upstream value: %q", got)
	}
	if got := result.Header.Values("X-Upstream-Request-Id"); len(got) != 1 || got[0] != "req-upstream" {
		t.Fatalf("upstream request ids = %v, want only safe upstream id", got)
	}
	if got := result.Header.Get("RateLimit-Remaining"); got != "60" {
		t.Fatalf("generic remaining limit = %q, want 60", got)
	}
	if got := result.Header.Get("X-Ratelimit-Remaining-Requests"); got != "59" {
		t.Fatalf("remaining requests = %q, want 59", got)
	}
	if got := result.Header.Get("Retry-After"); got != "1" {
		t.Fatalf("retry after = %q, want 1", got)
	}
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q, want upstream body", body)
	}
}
