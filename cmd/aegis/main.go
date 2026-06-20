// Package main is the entry point for the Aegis LLM Gateway.
//
// Aegis is a security-first LLM API gateway that provides unified access,
// key management, rate limiting, and planned cost-control architecture for
// multiple LLM providers.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/runtime"
	"github.com/yknothing/AegisLLM/internal/utils"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("aegis %s (commit: %s, built: %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	// Initialize structured logger (zero-PII by design)
	logger := utils.NewAuditLogger(os.Stdout, slog.LevelInfo)
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Create server with graceful shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := runtime.NewServer(cfg, logger)
	if err != nil {
		slog.Error("failed to initialize server", "error", err)
		os.Exit(1)
	}

	// Handle OS signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig.String())
		cancel()
	}()

	// Start serving
	slog.Info("aegis gateway starting",
		"version", version,
		"address", cfg.Server.Address,
	)

	if err := srv.Run(ctx); err != nil {
		slog.Error("server exited with error", "error", err)
		os.Exit(1)
	}

	slog.Info("aegis gateway stopped gracefully")
}
