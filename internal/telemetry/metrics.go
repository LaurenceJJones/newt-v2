package telemetry

import (
	"context"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds all application metrics instruments.
type Metrics struct {
	meter metric.Meter

	// Connection metrics
	ConnectionAttempts metric.Int64Counter
	ConnectionErrors   metric.Int64Counter
	ActiveConnections  metric.Int64UpDownCounter

	// Tunnel metrics
	TunnelLatency   metric.Float64Histogram
	TunnelBytesIn   metric.Int64Counter
	TunnelBytesOut  metric.Int64Counter
	TunnelPacketsIn metric.Int64Counter
	TunnelPacketsOut metric.Int64Counter

	// Proxy metrics
	ProxyConnections   metric.Int64Counter
	ProxyBytesIn       metric.Int64Counter
	ProxyBytesOut      metric.Int64Counter
	ProxyErrors        metric.Int64Counter
	ActiveProxyTargets metric.Int64UpDownCounter

	// Health check metrics
	HealthCheckRuns     metric.Int64Counter
	HealthCheckFailures metric.Int64Counter
	HealthCheckLatency  metric.Float64Histogram

	// Async byte counters for efficient batch updates
	asyncCounters *asyncCounterSet
}

// NewMetrics creates metrics instruments from the given meter.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{
		meter:         meter,
		asyncCounters: newAsyncCounterSet(),
	}

	var err error

	// Connection metrics
	m.ConnectionAttempts, err = meter.Int64Counter("newt.connection.attempts",
		metric.WithDescription("Number of connection attempts"),
		metric.WithUnit("{attempt}"))
	if err != nil {
		return nil, err
	}

	m.ConnectionErrors, err = meter.Int64Counter("newt.connection.errors",
		metric.WithDescription("Number of connection errors"),
		metric.WithUnit("{error}"))
	if err != nil {
		return nil, err
	}

	m.ActiveConnections, err = meter.Int64UpDownCounter("newt.connection.active",
		metric.WithDescription("Number of active connections"),
		metric.WithUnit("{connection}"))
	if err != nil {
		return nil, err
	}

	// Tunnel metrics
	m.TunnelLatency, err = meter.Float64Histogram("newt.tunnel.latency",
		metric.WithDescription("Tunnel ping latency"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(1, 5, 10, 25, 50, 100, 250, 500, 1000))
	if err != nil {
		return nil, err
	}

	m.TunnelBytesIn, err = meter.Int64Counter("newt.tunnel.bytes.in",
		metric.WithDescription("Bytes received through tunnel"),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	m.TunnelBytesOut, err = meter.Int64Counter("newt.tunnel.bytes.out",
		metric.WithDescription("Bytes sent through tunnel"),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	m.TunnelPacketsIn, err = meter.Int64Counter("newt.tunnel.packets.in",
		metric.WithDescription("Packets received through tunnel"),
		metric.WithUnit("{packet}"))
	if err != nil {
		return nil, err
	}

	m.TunnelPacketsOut, err = meter.Int64Counter("newt.tunnel.packets.out",
		metric.WithDescription("Packets sent through tunnel"),
		metric.WithUnit("{packet}"))
	if err != nil {
		return nil, err
	}

	// Proxy metrics
	m.ProxyConnections, err = meter.Int64Counter("newt.proxy.connections",
		metric.WithDescription("Total proxy connections"),
		metric.WithUnit("{connection}"))
	if err != nil {
		return nil, err
	}

	m.ProxyBytesIn, err = meter.Int64Counter("newt.proxy.bytes.in",
		metric.WithDescription("Bytes received through proxy"),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	m.ProxyBytesOut, err = meter.Int64Counter("newt.proxy.bytes.out",
		metric.WithDescription("Bytes sent through proxy"),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	m.ProxyErrors, err = meter.Int64Counter("newt.proxy.errors",
		metric.WithDescription("Proxy errors"),
		metric.WithUnit("{error}"))
	if err != nil {
		return nil, err
	}

	m.ActiveProxyTargets, err = meter.Int64UpDownCounter("newt.proxy.targets.active",
		metric.WithDescription("Number of active proxy targets"),
		metric.WithUnit("{target}"))
	if err != nil {
		return nil, err
	}

	// Health check metrics
	m.HealthCheckRuns, err = meter.Int64Counter("newt.healthcheck.runs",
		metric.WithDescription("Health check run count"),
		metric.WithUnit("{run}"))
	if err != nil {
		return nil, err
	}

	m.HealthCheckFailures, err = meter.Int64Counter("newt.healthcheck.failures",
		metric.WithDescription("Health check failure count"),
		metric.WithUnit("{failure}"))
	if err != nil {
		return nil, err
	}

	m.HealthCheckLatency, err = meter.Float64Histogram("newt.healthcheck.latency",
		metric.WithDescription("Health check latency"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(10, 50, 100, 250, 500, 1000, 2500, 5000))
	if err != nil {
		return nil, err
	}

	return m, nil
}

// RecordTunnelLatency records a tunnel ping latency measurement.
func (m *Metrics) RecordTunnelLatency(ctx context.Context, latencyMs float64, tunnelID string) {
	m.TunnelLatency.Record(ctx, latencyMs,
		metric.WithAttributes(attribute.String("tunnel_id", tunnelID)))
}

// RecordProxyConnection records a new proxy connection.
func (m *Metrics) RecordProxyConnection(ctx context.Context, protocol, target string) {
	m.ProxyConnections.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("protocol", protocol),
			attribute.String("target", target),
		))
}

// RecordProxyError records a proxy error.
func (m *Metrics) RecordProxyError(ctx context.Context, protocol, errorType string) {
	m.ProxyErrors.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("protocol", protocol),
			attribute.String("error_type", errorType),
		))
}

// RecordHealthCheck records a health check result.
func (m *Metrics) RecordHealthCheck(ctx context.Context, targetID string, success bool, latencyMs float64) {
	attrs := metric.WithAttributes(
		attribute.String("target_id", targetID),
		attribute.Bool("success", success),
	)

	m.HealthCheckRuns.Add(ctx, 1, attrs)
	if !success {
		m.HealthCheckFailures.Add(ctx, 1, attrs)
	}
	m.HealthCheckLatency.Record(ctx, latencyMs, attrs)
}

// AddTunnelBytes efficiently accumulates bytes for later batch flush.
// This is more efficient than calling Add on every packet.
func (m *Metrics) AddTunnelBytes(tunnelID string, bytesIn, bytesOut int64) {
	m.asyncCounters.add(tunnelID, bytesIn, bytesOut)
}

// FlushTunnelBytes flushes accumulated byte counts to the metrics.
func (m *Metrics) FlushTunnelBytes(ctx context.Context) {
	m.asyncCounters.flush(func(tunnelID string, bytesIn, bytesOut int64) {
		attrs := metric.WithAttributes(attribute.String("tunnel_id", tunnelID))
		m.TunnelBytesIn.Add(ctx, bytesIn, attrs)
		m.TunnelBytesOut.Add(ctx, bytesOut, attrs)
	})
}

// asyncCounterSet provides efficient accumulation of byte counts.
type asyncCounterSet struct {
	mu       sync.Mutex
	counters map[string]*asyncCounter
}

type asyncCounter struct {
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

func newAsyncCounterSet() *asyncCounterSet {
	return &asyncCounterSet{
		counters: make(map[string]*asyncCounter),
	}
}

func (s *asyncCounterSet) add(key string, bytesIn, bytesOut int64) {
	s.mu.Lock()
	counter, ok := s.counters[key]
	if !ok {
		counter = &asyncCounter{}
		s.counters[key] = counter
	}
	s.mu.Unlock()

	counter.bytesIn.Add(bytesIn)
	counter.bytesOut.Add(bytesOut)
}

func (s *asyncCounterSet) flush(fn func(key string, bytesIn, bytesOut int64)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, counter := range s.counters {
		bytesIn := counter.bytesIn.Swap(0)
		bytesOut := counter.bytesOut.Swap(0)
		if bytesIn > 0 || bytesOut > 0 {
			fn(key, bytesIn, bytesOut)
		}
	}
}
