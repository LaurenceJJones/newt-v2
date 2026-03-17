// Package app provides the main application orchestration for newt.
package app

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the complete application configuration.
// Configuration is loaded from environment variables first, then CLI flags override.
type Config struct {
	// Server connection
	Endpoint string // Pangolin server WebSocket URL
	ID       string // Newt client ID
	Secret   string // Authentication secret

	// WireGuard
	MTU           int    // Packet MTU (default 1280)
	DNS           string // DNS server IP (default 9.9.9.9)
	InterfaceName string // TUN interface name (default "newt")
	Port          uint16 // Client WireGuard port (0 = random)
	NativeMode    bool   // Use native WireGuard interface instead of userspace

	// TLS Configuration
	TLSClientCert string   // Path to client certificate
	TLSClientKey  string   // Path to client key
	TLSClientCAs  []string // Paths to CA certificates

	// Features
	DisableClients bool   // Disable WireGuard client support
	DockerSocket   string // Docker socket path for container discovery
	DockerEnforceNetworkValidation bool // Restrict docker results to validated host-container networks
	UpdownScript   string // Path to script for target add/remove events
	BlueprintFile  string // YAML configuration file for initial setup

	// Health
	HealthFile        string // Path to write health status file
	EnforceHealthCert bool   // Enforce health check certificate validation

	// Ping/connectivity
	PingInterval int // Tunnel ping interval in seconds (default 30)
	PingTimeout  int // Tunnel ping timeout in seconds (default 5)

	// Exit node selection
	PreferEndpoint string // Lock to specific exit node endpoint
	NoCloud        bool   // Disable cloud failover

	// Auth daemon (Linux only)
	AuthDaemonEnabled    bool   // Enable SSH-like authentication daemon
	AuthDaemonKey        string // Pre-shared key for auth daemon
	AuthDaemonAddr       string // Optional HTTPS bind address for auth daemon
	AuthDaemonPrincipals string // Path to principals file
	AuthDaemonCAPath     string // Path to CA certificate for auth daemon
	AuthDaemonHostCAPath string // Path to host CA certificate
	AuthDaemonRandomPass bool   // Generate random password for auth daemon

	// Telemetry
	MetricsEnabled bool   // Enable Prometheus metrics endpoint
	OTLPEnabled    bool   // Enable OpenTelemetry export
	AdminAddr      string // Address for metrics/admin server (default 127.0.0.1:2112)
	Region         string // Region label for metrics

	// Logging
	LogLevel string // Log level: DEBUG, INFO, WARN, ERROR, FATAL
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		MTU:              1280,
		DNS:              "9.9.9.9",
		InterfaceName:    "newt",
		PingInterval:     30,
		PingTimeout:      5,
		MetricsEnabled:   true,
		AdminAddr:        "127.0.0.1:2112",
		LogLevel:         "INFO",
		AuthDaemonCAPath: "/etc/ssh/ca.pem",
		AuthDaemonPrincipals: "/var/run/auth-daemon/principals",
	}
}

// LoadConfig loads configuration from environment variables and CLI flags.
// CLI flags override environment variables.
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// Load from environment first
	cfg.loadFromEnv()

	// Parse CLI flags (override env)
	cfg.parseFlags()

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadFromEnv loads configuration from environment variables.
func (c *Config) loadFromEnv() {
	// Server connection
	if v := os.Getenv("PANGOLIN_ENDPOINT"); v != "" {
		c.Endpoint = v
	}
	if v := os.Getenv("NEWT_ID"); v != "" {
		c.ID = v
	}
	if v := os.Getenv("NEWT_SECRET"); v != "" {
		c.Secret = v
	}

	// WireGuard
	if v := os.Getenv("MTU"); v != "" {
		if mtu, err := strconv.Atoi(v); err == nil {
			c.MTU = mtu
		}
	}
	if v := os.Getenv("DNS"); v != "" {
		c.DNS = v
	}
	if v := os.Getenv("INTERFACE"); v != "" {
		c.InterfaceName = v
	}
	if v := os.Getenv("PORT"); v != "" {
		if port, err := strconv.ParseUint(v, 10, 16); err == nil {
			c.Port = uint16(port)
		}
	}
	if v := os.Getenv("USE_NATIVE_INTERFACE"); v != "" {
		c.NativeMode = parseBool(v)
	}

	// TLS
	if v := os.Getenv("TLS_CLIENT_CERT"); v != "" {
		c.TLSClientCert = v
	}
	if v := os.Getenv("TLS_CLIENT_KEY"); v != "" {
		c.TLSClientKey = v
	}
	if v := os.Getenv("TLS_CLIENT_CAS"); v != "" {
		c.TLSClientCAs = strings.Split(v, ",")
	}

	// Features
	if v := os.Getenv("DISABLE_CLIENTS"); v != "" {
		c.DisableClients = parseBool(v)
	}
	if v := os.Getenv("DOCKER_SOCKET"); v != "" {
		c.DockerSocket = v
	}
	if v := os.Getenv("DOCKER_ENFORCE_NETWORK_VALIDATION"); v != "" {
		c.DockerEnforceNetworkValidation = parseBool(v)
	}
	if v := os.Getenv("UPDOWN_SCRIPT"); v != "" {
		c.UpdownScript = v
	}
	if v := os.Getenv("BLUEPRINT_FILE"); v != "" {
		c.BlueprintFile = v
	}

	// Health
	if v := os.Getenv("HEALTH_FILE"); v != "" {
		c.HealthFile = v
	}
	if v := os.Getenv("ENFORCE_HC_CERT"); v != "" {
		c.EnforceHealthCert = parseBool(v)
	}

	// Ping
	if v := os.Getenv("PING_INTERVAL"); v != "" {
		if interval, err := strconv.Atoi(v); err == nil {
			c.PingInterval = interval
		}
	}
	if v := os.Getenv("PING_TIMEOUT"); v != "" {
		if timeout, err := strconv.Atoi(v); err == nil {
			c.PingTimeout = timeout
		}
	}

	// Exit node
	if v := os.Getenv("PREFER_ENDPOINT"); v != "" {
		c.PreferEndpoint = v
	}
	if v := os.Getenv("NO_CLOUD"); v != "" {
		c.NoCloud = parseBool(v)
	}

	// Auth daemon
	if v := os.Getenv("AUTH_DAEMON_ENABLED"); v != "" {
		c.AuthDaemonEnabled = parseBool(v)
	}
	if v := os.Getenv("AD_KEY"); v != "" {
		c.AuthDaemonKey = v
	}
	if v := os.Getenv("AD_ADDR"); v != "" {
		c.AuthDaemonAddr = v
	}
	if v := os.Getenv("AD_PRINCIPALS_FILE"); v != "" {
		c.AuthDaemonPrincipals = v
	}
	if v := os.Getenv("AD_CA_PATH"); v != "" {
		c.AuthDaemonCAPath = v
	}
	if v := os.Getenv("AD_HOST_CA_PATH"); v != "" {
		c.AuthDaemonHostCAPath = v
	}
	if v := os.Getenv("AD_RANDOM_PASS"); v != "" {
		c.AuthDaemonRandomPass = parseBool(v)
	}

	// Telemetry
	if v := os.Getenv("NEWT_METRICS_PROMETHEUS_ENABLED"); v != "" {
		c.MetricsEnabled = parseBool(v)
	}
	if v := os.Getenv("NEWT_METRICS_OTLP_ENABLED"); v != "" {
		c.OTLPEnabled = parseBool(v)
	}
	if v := os.Getenv("NEWT_ADMIN_ADDR"); v != "" {
		c.AdminAddr = v
	}
	if v := os.Getenv("NEWT_REGION"); v != "" {
		c.Region = v
	}

	// Logging
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		c.LogLevel = strings.ToUpper(v)
	}
}

// parseFlags parses CLI flags and overrides current configuration.
func (c *Config) parseFlags() {
	// Server connection
	flag.StringVar(&c.Endpoint, "endpoint", c.Endpoint, "Pangolin server WebSocket URL")
	flag.StringVar(&c.ID, "id", c.ID, "Newt client ID")
	flag.StringVar(&c.Secret, "secret", c.Secret, "Authentication secret")

	// WireGuard
	flag.IntVar(&c.MTU, "mtu", c.MTU, "Packet MTU")
	flag.StringVar(&c.DNS, "dns", c.DNS, "DNS server IP")
	flag.StringVar(&c.InterfaceName, "interface", c.InterfaceName, "TUN interface name")
	port := flag.Uint("port", uint(c.Port), "Client WireGuard port (0 = random)")
	flag.BoolVar(&c.NativeMode, "native", c.NativeMode, "Use native WireGuard interface")

	// TLS
	flag.StringVar(&c.TLSClientCert, "tls-client-cert", c.TLSClientCert, "Path to client certificate")
	flag.StringVar(&c.TLSClientKey, "tls-client-key", c.TLSClientKey, "Path to client key")
	tlsCAs := flag.String("tls-client-cas", strings.Join(c.TLSClientCAs, ","), "Comma-separated paths to CA certificates")

	// Features
	flag.BoolVar(&c.DisableClients, "disable-clients", c.DisableClients, "Disable WireGuard client support")
	flag.StringVar(&c.DockerSocket, "docker-socket", c.DockerSocket, "Docker socket path")
	flag.BoolVar(&c.DockerEnforceNetworkValidation, "docker-enforce-network-validation", c.DockerEnforceNetworkValidation, "Enforce validation of containers on the newt network")
	flag.StringVar(&c.UpdownScript, "updown", c.UpdownScript, "Path to up/down script")
	flag.StringVar(&c.BlueprintFile, "blueprint-file", c.BlueprintFile, "Path to blueprint YAML file")

	// Health
	flag.StringVar(&c.HealthFile, "health-file", c.HealthFile, "Path to health status file")
	flag.BoolVar(&c.EnforceHealthCert, "enforce-hc-cert", c.EnforceHealthCert, "Enforce health check certificates")

	// Ping
	flag.IntVar(&c.PingInterval, "ping-interval", c.PingInterval, "Tunnel ping interval (seconds)")
	flag.IntVar(&c.PingTimeout, "ping-timeout", c.PingTimeout, "Tunnel ping timeout (seconds)")

	// Exit node
	flag.StringVar(&c.PreferEndpoint, "prefer-endpoint", c.PreferEndpoint, "Preferred exit node endpoint")
	flag.BoolVar(&c.NoCloud, "no-cloud", c.NoCloud, "Disable cloud failover")

	// Auth daemon
	flag.BoolVar(&c.AuthDaemonEnabled, "auth-daemon", c.AuthDaemonEnabled, "Enable auth daemon")
	flag.StringVar(&c.AuthDaemonKey, "ad-pre-shared-key", c.AuthDaemonKey, "Auth daemon pre-shared key")
	flag.StringVar(&c.AuthDaemonAddr, "ad-addr", c.AuthDaemonAddr, "Auth daemon HTTPS listen address (optional)")
	flag.StringVar(&c.AuthDaemonPrincipals, "ad-principals-file", c.AuthDaemonPrincipals, "Auth daemon principals file")
	flag.StringVar(&c.AuthDaemonCAPath, "ad-ca-path", c.AuthDaemonCAPath, "Auth daemon CA path")
	flag.StringVar(&c.AuthDaemonHostCAPath, "ad-host-ca-path", c.AuthDaemonHostCAPath, "Auth daemon host CA path")
	flag.BoolVar(&c.AuthDaemonRandomPass, "ad-random-pass", c.AuthDaemonRandomPass, "Generate random password")

	// Telemetry
	flag.BoolVar(&c.MetricsEnabled, "metrics", c.MetricsEnabled, "Enable Prometheus metrics")
	flag.BoolVar(&c.OTLPEnabled, "otlp", c.OTLPEnabled, "Enable OpenTelemetry export")
	flag.StringVar(&c.AdminAddr, "metrics-admin-addr", c.AdminAddr, "Metrics server address")
	flag.StringVar(&c.Region, "region", c.Region, "Region label for metrics")

	// Logging
	flag.StringVar(&c.LogLevel, "log-level", c.LogLevel, "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")

	flag.Parse()

	// Apply post-parse conversions
	c.Port = uint16(*port)
	if *tlsCAs != "" {
		c.TLSClientCAs = strings.Split(*tlsCAs, ",")
	}
}

// Validate checks that required configuration is present and valid.
func (c *Config) Validate() error {
	var errs []error

	if c.Endpoint == "" {
		errs = append(errs, errors.New("endpoint is required (--endpoint or PANGOLIN_ENDPOINT)"))
	}
	if c.ID == "" {
		errs = append(errs, errors.New("id is required (--id or NEWT_ID)"))
	}
	if c.Secret == "" {
		errs = append(errs, errors.New("secret is required (--secret or NEWT_SECRET)"))
	}

	// TLS validation
	if (c.TLSClientCert != "" || c.TLSClientKey != "") &&
		(c.TLSClientCert == "" || c.TLSClientKey == "") {
		errs = append(errs, errors.New("both tls-client-cert and tls-client-key must be specified"))
	}

	// MTU validation
	if c.MTU < 576 || c.MTU > 65535 {
		errs = append(errs, fmt.Errorf("mtu must be between 576 and 65535, got %d", c.MTU))
	}

	// Log level validation
	switch c.LogLevel {
	case "DEBUG", "INFO", "WARN", "ERROR", "FATAL":
		// valid
	default:
		errs = append(errs, fmt.Errorf("invalid log level: %s", c.LogLevel))
	}
	if c.AuthDaemonEnabled && c.AuthDaemonAddr != "" && c.AuthDaemonKey == "" {
		errs = append(errs, errors.New("auth daemon pre-shared key is required when ad-addr is set"))
	}

	return errors.Join(errs...)
}

// parseBool parses a boolean from various string representations.
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
