// Package main provides the entry point for the newt application.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fosrl/newt/internal/app"
	pkglogger "github.com/fosrl/newt/pkg/logger"
	"github.com/fosrl/newt/pkg/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	handled, err := handleSubcommand(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	// Load configuration from env and flags
	cfg, err := app.LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Setup logger
	logger := pkglogger.New(cfg.LogLevel)
	logger.Info("newt starting", "version", version.Short())

	// Create application
	application, err := app.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}

	// Setup context with signal handling
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run application (blocks until signal)
	if err := application.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("application error", "error", err)
	}

	// Graceful shutdown with timeout
	logger.Info("initiating graceful shutdown")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := application.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutdown error", "error", err)
	}

	logger.Info("shutdown complete")
	return nil
}
