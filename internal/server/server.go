// Package server implements the Aegis HTTP server with middleware pipeline.
//
// The server is the microkernel of Aegis. Its sole responsibility is to:
// 1. Accept incoming HTTP connections (optionally with mTLS)
// 2. Dispatch requests through the middleware pipeline
// 3. Handle graceful shutdown
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/yknothing/AegisLLM/internal/config"
)

// Option is a functional option for configuring the server.
type Option func(*Server)

// WithMiddleware adds a custom middleware to the pipeline.
// This enables dependency injection and plugin-based extensibility.
func WithMiddleware(m Middleware) Option {
	return func(s *Server) {
		s.extraMiddleware = append(s.extraMiddleware, m)
	}
}

// Server is the core Aegis gateway server.
type Server struct {
	httpServer      *http.Server
	pipeline        *Pipeline
	cfg             *config.Config
	logger          *slog.Logger
	extraMiddleware []Middleware
}

// New creates a new Aegis server with the configured middleware pipeline.
// Accepts functional options for dependency injection and extensibility.
func New(cfg *config.Config, logger *slog.Logger, opts ...Option) (*Server, error) {
	srv := &Server{
		cfg:    cfg,
		logger: logger,
	}

	// Apply functional options
	for _, opt := range opts {
		opt(srv)
	}

	pipeline, err := NewPipeline(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("building pipeline: %w", err)
	}

	// Register extra middleware from options
	for _, m := range srv.extraMiddleware {
		pipeline.Use(m)
	}

	srv.pipeline = pipeline

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", pipeline.ServeHTTP)
	mux.HandleFunc("/health", srv.healthHandler)

	srv.httpServer = &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Configure mTLS if enabled
	if cfg.Server.TLS.Enabled {
		tlsConfig, err := srv.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("configuring TLS: %w", err)
		}
		srv.httpServer.TLSConfig = tlsConfig
	}

	return srv, nil
}

// Run starts the server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		var err error
		if s.cfg.Server.TLS.Enabled {
			err = s.httpServer.ListenAndServeTLS(
				s.cfg.Server.TLS.CertFile,
				s.cfg.Server.TLS.KeyFile,
			)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("initiating graceful shutdown")
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			s.cfg.Server.ShutdownTimeout,
		)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// healthHandler returns a simple health check response.
// SECURITY: This endpoint intentionally reveals no internal state.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// buildTLSConfig creates a TLS configuration with mutual authentication.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load CA certificate for client verification (mTLS)
	if s.cfg.Server.TLS.CAFile != "" {
		caCert, err := os.ReadFile(s.cfg.Server.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}
