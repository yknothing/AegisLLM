//go:build darwin || linux

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
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
)

func TestNewPreloadsTLSKeyPair(t *testing.T) {
	certPath, keyPath, _, _ := writeTestServerTLSFiles(t)
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.TLS = config.TLSConfig{
		Enabled:    true,
		CertFile:   certPath,
		KeyFile:    keyPath,
		MinVersion: "1.3",
	}

	srv, err := New(cfg, slog.Default())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if len(srv.httpServer.TLSConfig.Certificates) != 1 {
		t.Fatalf("preloaded TLS certificates = %d, want 1", len(srv.httpServer.TLSConfig.Certificates))
	}
}

func TestRunUsesPreloadedTLSKeyPairWithoutReopeningConfiguredPaths(t *testing.T) {
	certPath, keyPath, certPEM, _ := writeTestServerTLSFiles(t)
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.TLS = config.TLSConfig{
		Enabled:    true,
		CertFile:   certPath,
		KeyFile:    keyPath,
		MinVersion: "1.3",
	}

	srv, err := New(cfg, slog.Default())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if len(srv.httpServer.TLSConfig.Certificates) != 1 {
		t.Fatalf("preloaded TLS certificates = %d, want 1", len(srv.httpServer.TLSConfig.Certificates))
	}
	serverAddress := reserveServerAddress(t)
	srv.httpServer.Addr = serverAddress
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove configured certificate after New: %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove configured private key after New: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test server root certificate")
	}
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		}},
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	t.Cleanup(func() {
		cancelRun()
		_ = srv.httpServer.Close()
	})
	waitForTLSServerHealth(t, client, serverAddress)
	cancelRun()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error after source TLS files were removed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not complete TLS shutdown")
	}
}

func TestParseTLSKeyPairZeroesRawPrivateKeyPEM(t *testing.T) {
	_, _, certPEM, keyPEM := writeTestServerTLSFiles(t)

	if _, err := parseTLSKeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("parseTLSKeyPair returned error: %v", err)
	}
	for i, b := range keyPEM {
		if b != 0 {
			t.Fatalf("private-key PEM byte %d was not zeroed", i)
		}
	}
}

func TestParseTLSKeyPairZeroesRawPrivateKeyPEMOnFailure(t *testing.T) {
	_, _, certPEM, _ := writeTestServerTLSFiles(t)
	invalidKeyPEM := []byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n")

	if _, err := parseTLSKeyPair(certPEM, invalidKeyPEM); err == nil {
		t.Fatal("parseTLSKeyPair accepted an invalid private key")
	}
	for i, b := range invalidKeyPEM {
		if b != 0 {
			t.Fatalf("failed private-key PEM byte %d was not zeroed", i)
		}
	}
}

func TestNewRejectsUnsafeTLSFiles(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, tlsConfig *config.TLSConfig)
		wantErr string
	}{
		{
			name: "certificate final component symlink",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				link := filepath.Join(t.TempDir(), "server-cert-link.pem")
				if err := os.Symlink(tlsConfig.CertFile, link); err != nil {
					t.Fatalf("create certificate symlink: %v", err)
				}
				tlsConfig.CertFile = link
			},
			wantErr: "opening TLS certificate file",
		},
		{
			name: "private key final component symlink",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				link := filepath.Join(t.TempDir(), "server-key-link.pem")
				if err := os.Symlink(tlsConfig.KeyFile, link); err != nil {
					t.Fatalf("create private-key symlink: %v", err)
				}
				tlsConfig.KeyFile = link
			},
			wantErr: "opening TLS private key file",
		},
		{
			name: "client CA final component symlink",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				link := filepath.Join(t.TempDir(), "client-ca-link.pem")
				if err := os.Symlink(tlsConfig.CertFile, link); err != nil {
					t.Fatalf("create client-CA symlink: %v", err)
				}
				tlsConfig.CAFile = link
			},
			wantErr: "opening TLS client CA file",
		},
		{
			name: "certificate group writable",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				if err := os.Chmod(tlsConfig.CertFile, 0o664); err != nil {
					t.Fatalf("chmod certificate: %v", err)
				}
			},
			wantErr: "TLS certificate file permissions",
		},
		{
			name: "private key group readable",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				if err := os.Chmod(tlsConfig.KeyFile, 0o640); err != nil {
					t.Fatalf("chmod private key: %v", err)
				}
			},
			wantErr: "TLS private key file permissions",
		},
		{
			name: "client CA other writable",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				if err := os.Chmod(tlsConfig.CertFile, 0o646); err != nil {
					t.Fatalf("chmod client CA: %v", err)
				}
				tlsConfig.CAFile = tlsConfig.CertFile
			},
			wantErr: "TLS client CA file permissions",
		},
		{
			name: "certificate is not regular",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				tlsConfig.CertFile = t.TempDir()
			},
			wantErr: "TLS certificate file must be a regular file",
		},
		{
			name: "certificate exceeds size limit",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				if err := os.WriteFile(tlsConfig.CertFile, make([]byte, maxTLSCertificatePEMBytes+1), 0o644); err != nil {
					t.Fatalf("write oversized certificate: %v", err)
				}
			},
			wantErr: "TLS certificate file exceeds",
		},
		{
			name: "private key exceeds size limit",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				if err := os.WriteFile(tlsConfig.KeyFile, make([]byte, maxTLSPrivateKeyPEMBytes+1), 0o600); err != nil {
					t.Fatalf("write oversized private key: %v", err)
				}
			},
			wantErr: "TLS private key file exceeds",
		},
		{
			name: "client CA exceeds size limit",
			mutate: func(t *testing.T, tlsConfig *config.TLSConfig) {
				caPath := filepath.Join(t.TempDir(), "oversized-ca.pem")
				if err := os.WriteFile(caPath, make([]byte, maxTLSCAPEMBytes+1), 0o644); err != nil {
					t.Fatalf("write oversized client CA: %v", err)
				}
				tlsConfig.CAFile = caPath
			},
			wantErr: "TLS client CA file exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPath, keyPath, _, _ := writeTestServerTLSFiles(t)
			cfg := &config.Config{Server: testValidServerConfig()}
			cfg.Server.TLS = config.TLSConfig{
				Enabled:    true,
				CertFile:   certPath,
				KeyFile:    keyPath,
				MinVersion: "1.3",
			}
			tt.mutate(t, &cfg.Server.TLS)

			_, err := New(cfg, slog.Default())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewRejectsTLSFIFOWithoutBlocking(t *testing.T) {
	certPath, _, _, _ := writeTestServerTLSFiles(t)
	fifoPath := filepath.Join(t.TempDir(), "server-key.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("create private-key FIFO: %v", err)
	}
	cfg := &config.Config{Server: testValidServerConfig()}
	cfg.Server.TLS = config.TLSConfig{
		Enabled:    true,
		CertFile:   certPath,
		KeyFile:    fifoPath,
		MinVersion: "1.3",
	}

	result := make(chan error, 1)
	go func() {
		_, err := New(cfg, slog.Default())
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "TLS private key file must be a regular file") {
			t.Fatalf("New error = %v, want non-regular private-key rejection", err)
		}
	case <-time.After(100 * time.Millisecond):
		// Unblock an implementation that opened the FIFO synchronously so this
		// RED test does not leave a goroutine behind.
		writer, err := os.OpenFile(fifoPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatalf("unblock private-key FIFO reader: %v", err)
		}
		_ = writer.Close()
		<-result
		t.Fatal("New blocked while opening a non-regular TLS file")
	}
}

func writeTestServerTLSFiles(t *testing.T) (certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "AegisLLM Test Server"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server-cert.pem")
	keyPath = filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write server certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}
	return certPath, keyPath, certPEM, keyPEM
}

func waitForTLSServerHealth(t *testing.T, client *http.Client, address string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("https://" + address + "/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("TLS server did not become healthy")
}
