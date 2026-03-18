package relay

import (
	"net"
	"sync/atomic"
	"testing"
)

func TestWrapWriteCounterCountsWrites(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()

	var counter atomic.Int64
	wrapped := WrapWriteCounter(left, &counter)

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8)
		n, _ := right.Read(buf)
		done <- append([]byte(nil), buf[:n]...)
	}()

	if _, err := wrapped.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(<-done); got != "hello" {
		t.Fatalf("unexpected payload: %q", got)
	}
	if got := counter.Load(); got != 5 {
		t.Fatalf("unexpected count: %d", got)
	}
}
