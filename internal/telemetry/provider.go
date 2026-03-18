// Package telemetry provides OpenTelemetry metrics and tracing support.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Config holds telemetry configuration.
type Config struct {
	ServiceName    string
	ServiceVersion string
	Region         string
	PrometheusAddr string // Address for Prometheus metrics endpoint
	AsyncBytes     bool   // Enable async byte metric flushing
	PprofEnabled   bool   // Enable pprof handlers on the admin server
	OTLPEnabled    bool   // Enable OTLP export
	OTLPEndpoint   string // OTLP collector endpoint
}

// Provider manages OpenTelemetry providers and HTTP server.
type Provider struct {
	cfg    Config
	logger *slog.Logger

	meterProvider  *sdkmetric.MeterProvider
	tracerProvider *sdktrace.TracerProvider
	httpServer     *http.Server

	// Meter for creating instruments
	Meter   metric.Meter
	Metrics *Metrics
}

// NewProvider creates a new telemetry provider.
func NewProvider(cfg Config, logger *slog.Logger) (*Provider, error) {
	if logger == nil {
		logger = slog.Default()
	}

	p := &Provider{
		cfg:    cfg,
		logger: logger,
	}

	if err := p.init(); err != nil {
		return nil, fmt.Errorf("init telemetry: %w", err)
	}

	return p, nil
}

// init initializes the OpenTelemetry providers.
func (p *Provider) init() error {
	ctx := context.Background()

	// Create resource with service attributes
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(p.cfg.ServiceName),
		semconv.ServiceVersion(p.cfg.ServiceVersion),
	)

	// Setup metric provider
	var metricReaders []sdkmetric.Reader

	// Prometheus exporter
	promExporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("create prometheus exporter: %w", err)
	}
	metricReaders = append(metricReaders, promExporter)

	// OTLP exporter (if enabled)
	if p.cfg.OTLPEnabled && p.cfg.OTLPEndpoint != "" {
		otlpExporter, err := otlpmetricgrpc.New(ctx,
			otlpmetricgrpc.WithEndpoint(p.cfg.OTLPEndpoint),
			otlpmetricgrpc.WithInsecure(),
		)
		if err != nil {
			return fmt.Errorf("create otlp metric exporter: %w", err)
		}
		metricReaders = append(metricReaders,
			sdkmetric.NewPeriodicReader(otlpExporter, sdkmetric.WithInterval(15*time.Second)),
		)
	}

	// Build metric provider options
	mpOpts := []sdkmetric.Option{sdkmetric.WithResource(res)}
	for _, reader := range metricReaders {
		mpOpts = append(mpOpts, sdkmetric.WithReader(reader))
	}

	p.meterProvider = sdkmetric.NewMeterProvider(mpOpts...)
	otel.SetMeterProvider(p.meterProvider)
	p.Meter = p.meterProvider.Meter(p.cfg.ServiceName)

	metrics, err := NewMetrics(p.Meter)
	if err != nil {
		return fmt.Errorf("create metrics instruments: %w", err)
	}
	p.Metrics = metrics
	SetMetrics(metrics)
	SetAsyncBytes(p.cfg.AsyncBytes)

	// Setup tracer provider (if OTLP enabled)
	if p.cfg.OTLPEnabled && p.cfg.OTLPEndpoint != "" {
		traceExporter, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(p.cfg.OTLPEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return fmt.Errorf("create otlp trace exporter: %w", err)
		}

		p.tracerProvider = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithBatcher(traceExporter),
		)
		otel.SetTracerProvider(p.tracerProvider)
	}

	return nil
}

// Name returns the component name.
func (p *Provider) Name() string {
	return "telemetry"
}

// Start starts the HTTP server for Prometheus metrics.
func (p *Provider) Start(ctx context.Context) error {
	if p.cfg.PrometheusAddr == "" {
		// No address configured, just wait for context cancellation
		<-ctx.Done()
		return ctx.Err()
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if p.cfg.PprofEnabled {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	p.httpServer = &http.Server{
		Addr:              p.cfg.PrometheusAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	p.logger.Info("starting metrics server", "addr", p.cfg.PrometheusAddr)

	go p.flushLoop(ctx)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := p.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (p *Provider) flushLoop(ctx context.Context) {
	if p.Metrics == nil {
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.Metrics.FlushTunnelBytes(context.Background())
			p.Metrics.FlushProxyBytes(context.Background())
			return
		case <-ticker.C:
			p.Metrics.FlushTunnelBytes(context.Background())
			p.Metrics.FlushProxyBytes(context.Background())
		}
	}
}

// Shutdown gracefully shuts down the telemetry provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	var errs []error

	if p.Metrics != nil {
		p.Metrics.FlushTunnelBytes(context.Background())
		p.Metrics.FlushProxyBytes(context.Background())
	}

	// Shutdown HTTP server
	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown http server: %w", err))
		}
	}

	// Shutdown tracer provider
	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown tracer: %w", err))
		}
	}

	// Shutdown meter provider
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown meter: %w", err))
		}
	}

	ClearMetrics(p.Metrics)

	return errors.Join(errs...)
}
