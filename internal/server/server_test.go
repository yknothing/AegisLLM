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
	"os"
	"path/filepath"
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
