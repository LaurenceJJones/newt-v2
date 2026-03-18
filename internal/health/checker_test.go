package health

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	pkglogger "github.com/fosrl/newt/pkg/logger"
)

func testLogger() *slog.Logger { return pkglogger.Discard() }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCheckerUsesHostHeaderAsRequestHost(t *testing.T) {
	hostSeen := ""
	target := DefaultTarget()
	target.ID = 1
	target.Scheme = "http"
	target.Hostname = "127.0.0.1"
	target.Port = 8080
	target.Method = "GET"
	target.Interval = time.Second
	target.UnhealthyInterval = time.Second
	target.Timeout = 2 * time.Second
	target.Path = "/"
	target.Headers = map[string]string{
		"Host": "virtual.example.test",
	}

	checker := NewChecker(target, false, testLogger())
	checker.ctx = context.Background()
	checker.client = &http.Client{
		Timeout: target.Timeout,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hostSeen = r.Host
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	checker.check()

	if hostSeen != "virtual.example.test" {
		t.Fatalf("expected request host to be overridden, got %q", hostSeen)
	}
}
