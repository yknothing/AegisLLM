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
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/utils"
)

const (
	maxHTTPHeaderBytes              = 64 * 1024
	maxTLSCertificatePEMBytes int64 = 1 << 20
	maxTLSPrivateKeyPEMBytes  int64 = 1 << 20
	maxTLSCAPEMBytes          int64 = 4 << 20
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

// WithShutdownHook registers a callback run sequentially during server
// shutdown. A timeout or panic stops later hooks and requires process exit.
func WithShutdownHook(hook func() error) Option {
	return func(s *Server) {
		s.shutdownHooks = append(s.shutdownHooks, hook)
	}
}

// WithHandler mounts an extra ServeMux pattern on the data-plane listener.
func WithHandler(pattern string, handler http.Handler) Option {
	return func(s *Server) {
		s.extraHandlers = append(s.extraHandlers, routeBinding{pattern: pattern, handler: handler})
	}
}

// WithAdminHandler mounts the loopback Admin API (ADR-007).
func WithAdminHandler(handler http.Handler) Option {
	return func(s *Server) {
		s.adminHandler = handler
	}
}

type routeBinding struct {
	pattern string
	handler http.Handler
}

// Server is the core Aegis gateway server.
type Server struct {
	httpServer      *http.Server
	adminServer     *http.Server
	pipeline        *Pipeline
	handlers        *handlerLifecycle
	cfg             *config.Config
	logger          *slog.Logger
	extraMiddleware []Middleware
	extraHandlers   []routeBinding
	adminHandler    http.Handler
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
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodPost, gatewayconst.PathChatCompletions), pipeline.ServeHTTP)
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodGet, gatewayconst.PathHealth), srv.healthHandler)
	for _, route := range srv.extraHandlers {
		if strings.TrimSpace(route.pattern) == "" || route.handler == nil {
			return nil, errors.New("server extra handler is incomplete")
		}
		mux.Handle(route.pattern, route.handler)
	}
	srv.handlers = newHandlerLifecycle()

	srv.httpServer = &http.Server{
		Addr:           cfg.Server.Address,
		Handler:        srv.handlers.wrap(mux),
		ReadTimeout:    cfg.Server.ReadTimeout,
		WriteTimeout:   cfg.Server.WriteTimeout,
		MaxHeaderBytes: maxHTTPHeaderBytes,
	}
	if err := srv.bindAdminListener(); err != nil {
		return nil, err
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
	closeResourcesOnReturn := true
	defer func() {
		if !closeResourcesOnReturn {
			return
		}
		if closeErr := s.closeResources(); closeErr != nil {
			if err != nil {
				s.logger.Error("failed to close server resources", "error", closeErr)
			}
			err = errors.Join(err, closeErr)
		}
	}()

	errCh := make(chan error, 2)

	go serveHTTP(s.httpServer, s.cfg.Server.TLS.Enabled, errCh)
	if s.adminServer != nil {
		go serveHTTP(s.adminServer, false, errCh)
	}

	select {
	case <-ctx.Done():
		s.logger.Info("initiating graceful shutdown")
		drained := s.handlers.startDraining()
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			s.cfg.Server.ShutdownTimeout,
		)
		defer cancel()
		shutdownErr := s.shutdownListeners(shutdownCtx)
		if shutdownErr == nil && handlersDrained(drained) {
			return nil
		}

		if closeErr := s.closeListeners(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
			s.logger.Error("failed to force close server connections", "error", closeErr)
		}
		// ShutdownTimeout bounds the graceful phase above. After force-closing
		// connections, handlers get at most one additional, equally bounded
		// phase to observe cancellation and release in-use resources.
		if !waitForHandlers(drained, s.cfg.Server.ShutdownTimeout) {
			// Active handlers may still own secrets. Leave resource hooks untouched
			// so the caller can fail closed by terminating the process.
			closeResourcesOnReturn = false
			return errors.Join(shutdownErr, handlerDrainTimeoutError(s.cfg.Server.ShutdownTimeout))
		}
		return shutdownErr
	case err := <-errCh:
		drained := s.handlers.startDraining()
		if closeErr := s.closeListeners(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
			s.logger.Error("failed to close server connections after serve error", "error", closeErr)
		}
		if !waitForHandlers(drained, s.cfg.Server.ShutdownTimeout) {
			// Active handlers may still own secrets. Leave resource hooks untouched
			// so the caller can fail closed by terminating the process.
			closeResourcesOnReturn = false
			return errors.Join(err, handlerDrainTimeoutError(s.cfg.Server.ShutdownTimeout))
		}
		return err
	}
}

var errHandlerDrainTimeout = errors.New("active handlers did not exit after forced close")

func serveHTTP(srv *http.Server, useTLS bool, errCh chan<- error) {
	var err error
	if useTLS {
		// The certificate and private key were securely loaded during New.
		// Empty paths prevent net/http from reopening mutable filesystem paths.
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- err
	}
}

func (s *Server) bindAdminListener() error {
	if s.cfg.Admin.Enabled {
		if s.adminHandler == nil {
			return errors.New("admin.enabled requires an admin handler")
		}
		s.adminServer = &http.Server{
			Addr:           s.cfg.Admin.Address,
			Handler:        s.handlers.wrap(s.adminHandler),
			ReadTimeout:    s.cfg.Server.ReadTimeout,
			WriteTimeout:   s.cfg.Server.WriteTimeout,
			MaxHeaderBytes: maxHTTPHeaderBytes,
		}
		return nil
	}
	if s.adminHandler != nil {
		return errors.New("admin handler requires admin.enabled=true")
	}
	return nil
}

func (s *Server) shutdownListeners(ctx context.Context) error {
	err := s.httpServer.Shutdown(ctx)
	if s.adminServer != nil {
		err = errors.Join(err, s.adminServer.Shutdown(ctx))
	}
	return err
}

func (s *Server) closeListeners() error {
	err := s.httpServer.Close()
	if s.adminServer != nil {
		err = errors.Join(err, s.adminServer.Close())
	}
	return err
}

func handlerDrainTimeoutError(timeout time.Duration) error {
	return fmt.Errorf(
		"%w within %s; resource shutdown hooks skipped and process termination required",
		errHandlerDrainTimeout,
		timeout,
	)
}

type handlerLifecycle struct {
	mu       sync.Mutex
	drained  chan struct{}
	active   int
	draining bool
}

func newHandlerLifecycle() *handlerLifecycle {
	drained := make(chan struct{})
	close(drained)
	return &handlerLifecycle{drained: drained}
}

func (l *handlerLifecycle) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.begin() {
			http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
			return
		}
		defer l.done()
		next.ServeHTTP(w, r)
	})
}

func (l *handlerLifecycle) begin() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.draining {
		return false
	}
	if l.active == 0 {
		l.drained = make(chan struct{})
	}
	l.active++
	return true
}

func (l *handlerLifecycle) done() {
	l.mu.Lock()
	l.active--
	if l.active == 0 {
		close(l.drained)
	}
	l.mu.Unlock()
}

func (l *handlerLifecycle) startDraining() <-chan struct{} {
	l.mu.Lock()
	l.draining = true
	drained := l.drained
	l.mu.Unlock()
	return drained
}

func handlersDrained(drained <-chan struct{}) bool {
	select {
	case <-drained:
		return true
	default:
		return false
	}
}

func waitForHandlers(drained <-chan struct{}, timeout time.Duration) bool {
	if handlersDrained(drained) {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-drained:
		return true
	case <-timer.C:
		return handlersDrained(drained)
	}
}

var (
	errShutdownHookTimeout = errors.New("server shutdown hooks exceeded their deadline")
	errShutdownHookPanic   = errors.New("server shutdown hook panicked")
)

func (s *Server) closeResources() error {
	deadline := time.Now().Add(s.cfg.Server.ShutdownTimeout)
	var closeErr error
	for index, hook := range s.shutdownHooks {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.Join(closeErr, shutdownHookTimeoutError(index, s.cfg.Server.ShutdownTimeout))
		}

		timer := time.NewTimer(remaining)
		result := make(chan error, 1)
		go func(index int, hook func() error) {
			result <- callShutdownHook(index, hook)
		}(index, hook)

		select {
		case hookErr := <-result:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if !time.Now().Before(deadline) {
				return errors.Join(closeErr, hookErr, shutdownHookTimeoutError(index, s.cfg.Server.ShutdownTimeout))
			}
			if errors.Is(hookErr, errShutdownHookPanic) {
				return errors.Join(closeErr, hookErr)
			}
			if hookErr != nil && closeErr == nil {
				closeErr = hookErr
			}
		case <-timer.C:
			return errors.Join(closeErr, shutdownHookTimeoutError(index, s.cfg.Server.ShutdownTimeout))
		}
	}
	return closeErr
}

func callShutdownHook(index int, hook func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf(
				"%w at position %d; later hooks skipped and process termination required",
				errShutdownHookPanic,
				index+1,
			)
		}
	}()
	return hook()
}

func shutdownHookTimeoutError(index int, timeout time.Duration) error {
	return fmt.Errorf(
		"%w: the %s shutdown phase ended before hook at position %d completed; later hooks skipped and process termination required",
		errShutdownHookTimeout,
		timeout,
		index+1,
	)
}

// healthHandler returns a simple health check response.
// SECURITY: This endpoint intentionally reveals no internal state.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// buildTLSConfig creates a TLS configuration with mutual authentication.
// SECURITY: Raw certificate, CA, and private-key PEM buffers are zeroed after
// parsing. The parsed private key remains in tls.Config for the server lifetime.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load CA certificate for client verification (mTLS)
	if s.cfg.Server.TLS.CAFile != "" {
		caCert, err := readTLSFile(
			s.cfg.Server.TLS.CAFile,
			"TLS client CA",
			maxTLSCAPEMBytes,
			0o022,
		)
		if err != nil {
			return nil, err
		}
		defer utils.MemZero(caCert)
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// ValidateServerConfig guarantees both paths are populated when TLS is
	// enabled through New. Keeping this conditional lets focused config tests
	// exercise the client-auth policy without constructing a server keypair.
	if s.cfg.Server.TLS.CertFile != "" || s.cfg.Server.TLS.KeyFile != "" {
		certPEM, err := readTLSFile(
			s.cfg.Server.TLS.CertFile,
			"TLS certificate",
			maxTLSCertificatePEMBytes,
			0o022,
		)
		if err != nil {
			return nil, err
		}
		defer utils.MemZero(certPEM)

		keyPEM, err := readTLSFile(
			s.cfg.Server.TLS.KeyFile,
			"TLS private key",
			maxTLSPrivateKeyPEMBytes,
			0o077,
		)
		if err != nil {
			return nil, err
		}
		keyPair, err := parseTLSKeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{keyPair}
	}

	return tlsCfg, nil
}

// readTLSFile securely reads a bounded regular TLS file from one validated file
// descriptor. The caller owns the returned buffer and must zero it after use.
func readTLSFile(path, label string, maxBytes int64, disallowedPermissions os.FileMode) ([]byte, error) {
	file, err := openTLSFileNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s file: %w", label, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("checking %s file: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s file must be a regular file", label)
	}
	if permissions := info.Mode().Perm(); permissions&disallowedPermissions != 0 {
		return nil, fmt.Errorf("%s file permissions %o are unsafe", label, permissions)
	}
	if info.Size() < 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("%s file exceeds the %d-byte size limit", label, maxBytes)
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		utils.MemZero(contents)
		return nil, fmt.Errorf("reading %s file: %w", label, err)
	}
	if int64(len(contents)) > maxBytes {
		utils.MemZero(contents)
		return nil, fmt.Errorf("%s file exceeds the %d-byte size limit", label, maxBytes)
	}
	return contents, nil
}

// parseTLSKeyPair transfers the parsed private key into a tls.Certificate and
// always zeroes the caller-provided raw private-key PEM before returning.
func parseTLSKeyPair(certPEM, keyPEM []byte) (tls.Certificate, error) {
	defer utils.MemZero(keyPEM)
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing TLS certificate and private key: %w", err)
	}
	return keyPair, nil
}
