// Package main provides the entry point for the newt application.
package main

import (
	"context"
	"errors"
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
	handled, err := handleSubcommand(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if handled {
		return
	}

	if isWindowsService() {
		runService(serviceName, false, os.Args[1:])
		return
	}

	if handleServiceCommand() {
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
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

	return runApplication(context.Background(), application, logger, true)
}

//nolint:unused // used by Windows service entrypoints
func runWithArgs(ctx context.Context, args []string) error {
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	os.Args = append([]string{originalArgs[0]}, args...)

	cfg, err := app.LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := pkglogger.New(cfg.LogLevel)
	logger.Info("newt starting", "version", version.Short())

	application, err := app.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}

	return runApplication(ctx, application, logger, false)
}

func runApplication(parent context.Context, application *app.App, logger interface {
	Info(string, ...any)
	Warn(string, ...any)
	Error(string, ...any)
}, handleSignals bool) error {
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- application.Run(runCtx)
	}()

	if handleSignals {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		select {
		case err := <-runErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("application error", "error", err)
			}
			return nil
		case sig := <-sigCh:
			logger.Info("initiating graceful shutdown", "signal", sig.String())
		}
	} else {
		select {
		case err := <-runErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("application error", "error", err)
			}
			return nil
		case <-parent.Done():
			logger.Info("initiating graceful shutdown")
		}
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()

	if err := application.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutdown error", "error", err)
	}

	cancelRun()

	if err := <-runErrCh; err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("application error", "error", err)
	}

	logger.Info("shutdown complete")
	return nil
}
