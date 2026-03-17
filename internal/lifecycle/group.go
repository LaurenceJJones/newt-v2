// Package lifecycle provides goroutine lifecycle management with proper
// context propagation, panic recovery, and clean shutdown semantics.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
)

// Group manages a collection of goroutines with proper lifecycle control.
// It ensures all goroutines complete before returning from Wait().
// If any goroutine returns an error or panics, the entire group is cancelled.
type Group struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	wg     sync.WaitGroup

	errOnce sync.Once
	err     error
}

// NewGroup creates a new goroutine group derived from the parent context.
// The group's context will be cancelled when any goroutine fails or when
// the parent context is cancelled.
func NewGroup(ctx context.Context) *Group {
	ctx, cancel := context.WithCancelCause(ctx)
	return &Group{
		ctx:    ctx,
		cancel: cancel,
	}
}

// Context returns the group's context. This context is cancelled when
// any goroutine in the group fails or when Cancel is called.
func (g *Group) Context() context.Context {
	return g.ctx
}

// Go spawns a goroutine that will be tracked by this group.
// The function receives the group's context and should respect cancellation.
// If fn returns a non-nil error (other than context.Canceled), the entire
// group is cancelled and the error is recorded.
//
// Panics in fn are recovered and converted to errors.
func (g *Group) Go(fn func(ctx context.Context) error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				err := fmt.Errorf("panic recovered: %v\n%s", r, stack)
				g.setError(err)
			}
		}()

		if err := fn(g.ctx); err != nil {
			// Don't treat context cancellation as an error worth propagating
			if !errors.Is(err, context.Canceled) {
				g.setError(err)
			}
		}
	}()
}

// GoWithRecover spawns a goroutine like Go, but allows the caller to
// provide a custom panic handler. The handler receives the recovered
// value and the stack trace.
func (g *Group) GoWithRecover(fn func(ctx context.Context) error, onPanic func(recovered any, stack []byte)) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				if onPanic != nil {
					onPanic(r, stack)
				}
				err := fmt.Errorf("panic recovered: %v", r)
				g.setError(err)
			}
		}()

		if err := fn(g.ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				g.setError(err)
			}
		}
	}()
}

// Wait blocks until all goroutines complete.
// Returns the first non-nil error encountered (if any).
func (g *Group) Wait() error {
	g.wg.Wait()
	return g.err
}

// Cancel cancels all goroutines in the group with the given cause.
// This is useful for initiating graceful shutdown.
func (g *Group) Cancel(cause error) {
	g.cancel(cause)
}

// setError records the first error and cancels the group.
func (g *Group) setError(err error) {
	g.errOnce.Do(func() {
		g.err = err
		g.cancel(err)
	})
}

// Err returns the error that caused the group to be cancelled, if any.
// This may return nil even after Wait() completes if all goroutines
// completed successfully.
func (g *Group) Err() error {
	return g.err
}

// Done returns a channel that is closed when the group's context is cancelled.
// This is a convenience wrapper around g.Context().Done().
func (g *Group) Done() <-chan struct{} {
	return g.ctx.Done()
}
