package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Component represents a runnable service with lifecycle management.
// Components are started by a Supervisor and should respect context cancellation.
type Component interface {
	// Name returns the component's identifier for logging and debugging.
	Name() string

	// Start begins the component's operation. It should block until ctx is
	// cancelled or an error occurs. The component must respect context
	// cancellation and return promptly when ctx.Done() is closed.
	Start(ctx context.Context) error
}

// Supervisor manages multiple components with proper startup/shutdown ordering.
// Components are started in the order they were added and stopped in reverse order.
type Supervisor struct {
	components []Component
	logger     *slog.Logger

	// ShutdownTimeout is the maximum time to wait for each component to stop.
	// Defaults to 30 seconds if not set.
	ShutdownTimeout time.Duration
}

// NewSupervisor creates a new Supervisor with the given logger.
func NewSupervisor(logger *slog.Logger) *Supervisor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Supervisor{
		logger:          logger,
		ShutdownTimeout: 30 * time.Second,
	}
}

// Add registers a component to be managed by the supervisor.
// Components are started in the order they are added.
func (s *Supervisor) Add(c Component) {
	s.components = append(s.components, c)
}

// Run starts all components and waits for shutdown signal.
// Components are started in order. If any component fails to start or
// fails during operation, all components are stopped.
//
// The supervisor respects ctx cancellation - when ctx is cancelled,
// all components are gracefully stopped in reverse order.
func (s *Supervisor) Run(ctx context.Context) error {
	if len(s.components) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	group := NewGroup(ctx)

	// Start all components
	for _, c := range s.components {
		s.logger.Info("starting component", "name", c.Name())

		group.Go(func(ctx context.Context) error {
			err := c.Start(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				s.logger.Error("component failed",
					"name", c.Name(),
					"error", err,
				)
			} else {
				s.logger.Debug("component stopped", "name", c.Name())
			}
			return err
		})
	}

	// Wait for all components to finish
	return group.Wait()
}

// Shutdown gracefully stops all components in reverse order.
// This is typically called after Run returns to ensure proper cleanup.
// The context controls the total shutdown timeout.
func (s *Supervisor) Shutdown(ctx context.Context) error {
	var errs []error

	// Stop in reverse order
	for i := len(s.components) - 1; i >= 0; i-- {
		c := s.components[i]

		// Check if component implements Shutdowner interface
		if shutdowner, ok := c.(Shutdowner); ok {
			s.logger.Debug("shutting down component", "name", c.Name())

			// Create timeout context for this component
			componentCtx, cancel := context.WithTimeout(ctx, s.ShutdownTimeout)
			if err := shutdowner.Shutdown(componentCtx); err != nil {
				s.logger.Warn("component shutdown error",
					"name", c.Name(),
					"error", err,
				)
				errs = append(errs, fmt.Errorf("%s: %w", c.Name(), err))
			}
			cancel()
		}
	}

	return errors.Join(errs...)
}

// Shutdowner is an optional interface that components can implement
// to perform custom cleanup when the supervisor is shutting down.
type Shutdowner interface {
	// Shutdown performs cleanup and should return within the context deadline.
	Shutdown(ctx context.Context) error
}

// FuncComponent wraps a function as a Component for simple cases.
type FuncComponent struct {
	name    string
	startFn func(ctx context.Context) error
	stopFn  func(ctx context.Context) error
}

// NewFuncComponent creates a Component from a start function.
func NewFuncComponent(name string, start func(ctx context.Context) error) *FuncComponent {
	return &FuncComponent{
		name:    name,
		startFn: start,
	}
}

// WithShutdown adds a shutdown function to the FuncComponent.
func (f *FuncComponent) WithShutdown(stop func(ctx context.Context) error) *FuncComponent {
	f.stopFn = stop
	return f
}

// Name returns the component name.
func (f *FuncComponent) Name() string {
	return f.name
}

// Start runs the start function.
func (f *FuncComponent) Start(ctx context.Context) error {
	return f.startFn(ctx)
}

// Shutdown runs the stop function if set.
func (f *FuncComponent) Shutdown(ctx context.Context) error {
	if f.stopFn != nil {
		return f.stopFn(ctx)
	}
	return nil
}
