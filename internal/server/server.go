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

// WithShutdownHook registers a callback run during server shutdown.
func WithShutdownHook(hook func() error) Option {
	return func(s *Server) {
		s.shutdownHooks = append(s.shutdownHooks, hook)
	}
}

// Server is the core Aegis gateway server.
type Server struct {
	httpServer      *http.Server
	pipeline        *Pipeline
	cfg             *config.Config
	logger          *slog.Logger
	extraMiddleware []Middleware
	shutdownHooks   []func() error
}

// New creates a new Aegis server with the configured middleware pipeline.
// Accepts functional options for dependency injection and extensibility.
func New(cfg *config.Config, logger *slog.Logger, opts ...Option) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if err := config.ValidateServerConfig(cfg.Server); err != nil {
		return nil, err
	}

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
	mux.HandleFunc("POST /v1/chat/completions", pipeline.ServeHTTP)
	mux.HandleFunc("GET /health", srv.healthHandler)

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
func (s *Server) Run(ctx context.Context) (err error) {
	defer func() {
		if closeErr := s.closeResources(); closeErr != nil {
			if err == nil {
				err = closeErr
			} else {
				s.logger.Error("failed to close server resources", "error", closeErr)
			}
		}
	}()

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

func (s *Server) closeResources() error {
	var closeErr error
	for _, hook := range s.shutdownHooks {
		if err := hook(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
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
