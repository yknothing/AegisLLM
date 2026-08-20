package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
)

const (
	testCACommonName    = "AegisLLM Test CA"
	testCAFileMode      = 0o600
	testCANotBeforeSkew = time.Minute
	testCACertTTL       = time.Hour
	testCASerialNumber  = 1
)

func TestNewRejectsInvalidServerBounds(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.ServerConfig)
		wantErr string
	}{
		{
			name: "zero read timeout",
			mutate: func(serverCfg *config.ServerConfig) {
				serverCfg.ReadTimeout = 0
			},
			wantErr: "server.read_timeout must be positive",
		},
		{
			name: "negative write timeout",
			mutate: func(serverCfg *config.ServerConfig) {
				serverCfg.WriteTimeout = -1
			},
			wantErr: "server.write_timeout must be positive",
		},
		{
			name: "zero shutdown timeout",
			mutate: func(serverCfg *config.ServerConfig) {
				serverCfg.ShutdownTimeout = 0
			},
			wantErr: "server.shutdown_timeout must be positive",
		},
		{
			name: "body size above maximum",
			mutate: func(serverCfg *config.ServerConfig) {
				serverCfg.MaxRequestBodySize = config.MaxRequestBodySizeLimit + 1
			},
			wantErr: "server.max_request_body_size must not exceed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Server: testValidServerConfig()}
			tt.mutate(&cfg.Server)

			_, err := New(cfg, slog.Default())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewConfiguresBoundedHTTPHeaders(t *testing.T) {
	srv, err := New(&config.Config{Server: testValidServerConfig()}, slog.Default())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if srv.httpServer.MaxHeaderBytes != maxHTTPHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.httpServer.MaxHeaderBytes, maxHTTPHeaderBytes)
	}
}

func TestBuildTLSConfigWithoutCAUsesTLS13WithoutClientCert(t *testing.T) {
	srv := testServerWithTLS(config.TLSConfig{Enabled: true})

	tlsConfig, err := srv.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig returned error: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsConfig.MinVersion)
	}
	if tlsConfig.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v, want NoClientCert without ca_file", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs != nil {
		t.Fatal("ClientCAs is set without ca_file")
	}
}

func TestServerExposesOnlySupportedDataPlaneRoute(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCalled bool
	}{
		{name: "supported chat completion", method: http.MethodPost, path: "/v1/chat/completions", wantStatus: http.StatusNoContent, wantCalled: true},
		{name: "wrong method", method: http.MethodGet, path: "/v1/chat/completions", wantStatus: http.StatusMethodNotAllowed},
		{name: "unsupported v1 path", method: http.MethodPost, path: "/v1/models", wantStatus: http.StatusNotFound},
		{name: "arbitrary v1 path", method: http.MethodDelete, path: "/v1/anything", wantStatus: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			cfg := &config.Config{Server: testValidServerConfig()}
			srv, err := New(cfg, slog.Default(), WithMiddleware(func(ctx *RequestContext, next func()) {
				called = true
				ctx.StatusCode = http.StatusNoContent
				ctx.Writer.WriteHeader(http.StatusNoContent)
			}))
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}

			recorder := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.path, nil))

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if called != tt.wantCalled {
				t.Fatalf("pipeline called = %t, want %t", called, tt.wantCalled)
			}
		})
	}
}

func TestBuildTLSConfigWithCARequiresVerifiedClientCert(t *testing.T) {
	caPath := writeTestCACert(t)
	srv := testServerWithTLS(config.TLSConfig{
		Enabled: true,
		CAFile:  caPath,
	})

	tlsConfig, err := srv.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig returned error: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsConfig.MinVersion)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs == nil {
		t.Fatal("ClientCAs is nil with ca_file")
	}
}

func TestBuildTLSConfigRejectsInvalidCAFile(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("not a pem certificate"), testCAFileMode); err != nil {
		t.Fatalf("write invalid CA: %v", err)
	}
	srv := testServerWithTLS(config.TLSConfig{
		Enabled: true,
		CAFile:  caPath,
	})

	if _, err := srv.buildTLSConfig(); err == nil {
		t.Fatal("buildTLSConfig accepted an invalid CA file")
	}
}

func TestRunClosesActiveHandlersBeforeShutdownHooksAfterTimeout(t *testing.T) {
	serverAddress := reserveServerAddress(t)
	handlerStarted := make(chan struct{})
	handlerExited := make(chan struct{})
	hookObservedHandlerExit := make(chan bool, 1)
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.Address = serverAddress
	cfg.Server.ShutdownTimeout = 20 * time.Millisecond
	srv, err := New(cfg, slog.Default(),
		WithMiddleware(func(ctx *RequestContext, _ func()) {
			close(handlerStarted)
			<-ctx.Request.Context().Done()
			close(handlerExited)
		}),
		WithShutdownHook(func() error {
			select {
			case <-handlerExited:
				hookObservedHandlerExit <- true
			default:
				hookObservedHandlerExit <- false
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() { _ = srv.httpServer.Close() })

	runCtx, cancelRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	waitForServerHealth(t, serverAddress)

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		request, requestErr := http.NewRequest(http.MethodPost, "http://"+serverAddress+"/v1/chat/completions", nil)
		if requestErr != nil {
			return
		}
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr == nil {
			_ = response.Body.Close()
		}
	}()

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancelRun()

	select {
	case err := <-runErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Run error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after shutdown timeout")
	}
	if !<-hookObservedHandlerExit {
		t.Fatal("shutdown hook ran before the active handler exited")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("active request did not terminate after forced server close")
	}
}

func TestRunBoundsForcedDrainAndSkipsHooksWhenHandlerDoesNotExit(t *testing.T) {
	serverAddress := reserveServerAddress(t)
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(releaseHandler)
		}
	}()
	hookCalled := make(chan struct{}, 1)
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.Address = serverAddress
	cfg.Server.ShutdownTimeout = 20 * time.Millisecond
	srv, err := New(cfg, slog.Default(),
		WithMiddleware(func(_ *RequestContext, _ func()) {
			close(handlerStarted)
			<-releaseHandler
		}),
		WithShutdownHook(func() error {
			hookCalled <- struct{}{}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() { _ = srv.httpServer.Close() })

	runCtx, cancelRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	waitForServerHealth(t, serverAddress)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, requestErr := http.Post("http://"+serverAddress+"/v1/chat/completions", "application/json", nil)
		if requestErr == nil {
			_ = response.Body.Close()
		}
	}()

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancelRun()

	var gotErr error
	select {
	case gotErr = <-runErr:
	case <-time.After(300 * time.Millisecond):
		close(releaseHandler)
		released = true
		select {
		case cleanupErr := <-runErr:
			t.Fatalf("Run exceeded its bounded forced-drain phase; returned only after handler release: %v", cleanupErr)
		case <-time.After(time.Second):
			t.Fatal("Run remained blocked after the test released the handler")
		}
	}
	if !errors.Is(gotErr, errHandlerDrainTimeout) {
		t.Fatalf("Run error = %v, want explicit forced-drain timeout", gotErr)
	}
	if !errors.Is(gotErr, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want original graceful shutdown deadline", gotErr)
	}
	select {
	case <-hookCalled:
		t.Fatal("shutdown hook ran while an active handler still retained resources")
	default:
	}

	close(releaseHandler)
	released = true
	drained := srv.handlers.startDraining()
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not exit after test release")
	}
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("server handler did not exit after test release")
	}
	select {
	case <-hookCalled:
		t.Fatal("shutdown hook ran after Run had skipped unsafe resource cleanup")
	default:
	}
}

func TestRunWaitsForActiveHandlerDuringGracefulShutdown(t *testing.T) {
	serverAddress := reserveServerAddress(t)
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	handlerExited := make(chan struct{})
	hookObservedHandlerExit := make(chan bool, 1)
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.Address = serverAddress
	cfg.Server.ShutdownTimeout = time.Second
	srv, err := New(cfg, slog.Default(),
		WithMiddleware(func(ctx *RequestContext, _ func()) {
			close(handlerStarted)
			select {
			case <-releaseHandler:
			case <-ctx.Request.Context().Done():
			}
			close(handlerExited)
			ctx.Writer.WriteHeader(http.StatusNoContent)
		}),
		WithShutdownHook(func() error {
			select {
			case <-handlerExited:
				hookObservedHandlerExit <- true
			default:
				hookObservedHandlerExit <- false
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() { _ = srv.httpServer.Close() })

	runCtx, cancelRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	waitForServerHealth(t, serverAddress)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, requestErr := http.Post("http://"+serverAddress+"/v1/chat/completions", "application/json", nil)
		if requestErr == nil {
			_ = response.Body.Close()
		}
	}()

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancelRun()
	select {
	case <-hookObservedHandlerExit:
		t.Fatal("shutdown hook ran while the active handler was blocked")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseHandler)

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error during graceful shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not complete graceful shutdown")
	}
	if !<-hookObservedHandlerExit {
		t.Fatal("shutdown hook ran before the active handler exited")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not complete during graceful shutdown")
	}
}

func TestRunClosesResourcesAfterServeError(t *testing.T) {
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.Address = "invalid-address"
	hookCalled := false
	srv, err := New(cfg, slog.Default(), WithShutdownHook(func() error {
		hookCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := srv.Run(context.Background()); err == nil {
		t.Fatal("Run returned nil for invalid listen address")
	}
	if !hookCalled {
		t.Fatal("shutdown hook was not called after serve error")
	}
}

func TestRunBoundsShutdownHookPhaseAndSkipsLaterHooks(t *testing.T) {
	releaseHook := make(chan struct{})
	defer close(releaseHook)
	laterHookCalled := make(chan struct{}, 1)
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.Address = "invalid-address"
	cfg.Server.ShutdownTimeout = 20 * time.Millisecond
	srv, err := New(cfg, slog.Default(),
		WithShutdownHook(func() error {
			<-releaseHook
			return nil
		}),
		WithShutdownHook(func() error {
			laterHookCalled <- struct{}{}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(context.Background()) }()

	var gotErr error
	select {
	case gotErr = <-runErr:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Run remained blocked in a shutdown hook")
	}
	if !errors.Is(gotErr, errShutdownHookTimeout) {
		t.Fatalf("Run error = %v, want shutdown-hook timeout", gotErr)
	}
	if !strings.Contains(gotErr.Error(), "process termination required") {
		t.Fatalf("Run error = %v, want explicit process-termination requirement", gotErr)
	}
	select {
	case <-laterHookCalled:
		t.Fatal("later shutdown hook ran after a prior hook timed out")
	default:
	}
}

func TestRunRecoversShutdownHookPanicWithoutLeakingPanicValue(t *testing.T) {
	const panicCanary = "CANARY-shutdown-hook-secret-74b28e6c"
	laterHookCalled := false
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.Address = "invalid-address"
	srv, err := New(cfg, slog.Default(),
		WithShutdownHook(func() error {
			panic(panicCanary)
		}),
		WithShutdownHook(func() error {
			laterHookCalled = true
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	gotErr := srv.Run(context.Background())
	if !errors.Is(gotErr, errShutdownHookPanic) {
		t.Fatalf("Run error = %v, want recovered shutdown-hook panic", gotErr)
	}
	if !strings.Contains(gotErr.Error(), "process termination required") {
		t.Fatalf("Run error = %v, want explicit process-termination requirement", gotErr)
	}
	if strings.Contains(gotErr.Error(), panicCanary) {
		t.Fatalf("Run error leaked panic value: %v", gotErr)
	}
	if laterHookCalled {
		t.Fatal("later shutdown hook ran after a prior hook panicked")
	}
}

func TestRunPreservesShutdownHookOrderAfterOrdinaryError(t *testing.T) {
	wantErr := errors.New("close failed")
	var order []int
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.Address = "invalid-address"
	srv, err := New(cfg, slog.Default(),
		WithShutdownHook(func() error {
			order = append(order, 1)
			return wantErr
		}),
		WithShutdownHook(func() error {
			order = append(order, 2)
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	gotErr := srv.Run(context.Background())
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("Run error = %v, want shutdown-hook error", gotErr)
	}
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("shutdown hook order = %v, want [1 2]", order)
	}
}

func testValidServerConfig() config.ServerConfig {
	return config.ServerConfig{
		Address:            ":0",
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       120 * time.Second,
		ShutdownTimeout:    15 * time.Second,
		MaxRequestBodySize: config.DefaultMaxRequestBodySize,
	}
}

func waitForServerHealth(t *testing.T, address string) {
	t.Helper()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + address + "/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("server did not become healthy")
}

func reserveServerAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve server address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release server address: %v", err)
	}
	return address
}

func testServerWithTLS(tlsConfig config.TLSConfig) *Server {
	return &Server{
		cfg: &config.Config{
			Server: config.ServerConfig{
				TLS: tlsConfig,
			},
		},
		logger: slog.Default(),
	}
}

func writeTestCACert(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(testCASerialNumber),
		Subject:               pkix.Name{CommonName: testCACommonName},
		NotBefore:             now.Add(-testCANotBeforeSkew),
		NotAfter:              now.Add(testCACertTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(caPath, caPEM, testCAFileMode); err != nil {
		t.Fatalf("write CA certificate: %v", err)
	}
	return caPath
}
