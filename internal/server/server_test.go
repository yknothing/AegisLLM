package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
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

func testValidServerConfig() config.ServerConfig {
	return config.ServerConfig{
		Address:            ":0",
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       120 * time.Second,
		ShutdownTimeout:    15 * time.Second,
		MaxRequestBodySize: config.DefaultMaxRequestBodySize,
	}
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
