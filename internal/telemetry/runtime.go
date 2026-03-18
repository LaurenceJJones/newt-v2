package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
)

var (
	metricsMu     sync.RWMutex
	activeMetrics *Metrics
	asyncBytes    atomic.Bool
)

func SetMetrics(m *Metrics) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	activeMetrics = m
}

func ClearMetrics(m *Metrics) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if activeMetrics == m {
		activeMetrics = nil
	}
}

func SetAsyncBytes(enabled bool) {
	asyncBytes.Store(enabled)
}

func currentMetrics() *Metrics {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return activeMetrics
}

func RecordProxyConnection(protocol, target string) {
	if m := currentMetrics(); m != nil {
		m.RecordProxyConnection(context.Background(), protocol, target)
	}
}

func RecordProxyError(protocol, errorType string) {
	if m := currentMetrics(); m != nil {
		m.RecordProxyError(context.Background(), protocol, errorType)
	}
}

func AddProxyBytes(protocol, target string, bytesIn, bytesOut int64) {
	if m := currentMetrics(); m != nil {
		m.AddProxyBytes(context.Background(), protocol, target, bytesIn, bytesOut, asyncBytes.Load())
	}
}

func AddActiveProxyTargets(protocol string, delta int64) {
	if m := currentMetrics(); m != nil {
		m.AddActiveProxyTargets(context.Background(), protocol, delta)
	}
}
