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
	DisableClients                 bool   // Disable WireGuard client support
	DockerSocket                   string // Docker socket path for container discovery
	DockerEnforceNetworkValidation bool   // Restrict docker results to validated host-container networks
	UpdownScript                   string // Path to script for target add/remove events
	BlueprintFile                  string // YAML configuration file for initial setup

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
	PprofEnabled   bool   // Enable pprof handlers on the admin server
	Region         string // Region label for metrics

	// Logging
	LogLevel string // Log level: DEBUG, INFO, WARN, ERROR, FATAL
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		MTU:                  1280,
		DNS:                  "9.9.9.9",
		InterfaceName:        "newt",
		PingInterval:         30,
		PingTimeout:          5,
		MetricsEnabled:       true,
		AdminAddr:            "127.0.0.1:2112",
		LogLevel:             "INFO",
		AuthDaemonCAPath:     "/etc/ssh/ca.pem",
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

func defaultFlagSet() *flag.FlagSet {
	return flag.CommandLine
}

// loadFromEnv loads configuration from environment variables.
func (c *Config) loadFromEnv() {
	c.loadConnectionEnv()
	c.loadWireGuardEnv()
	c.loadTLSEnv()
	c.loadFeatureEnv()
	c.loadHealthEnv()
	c.loadPingEnv()
	c.loadExitNodeEnv()
	c.loadAuthDaemonEnv()
	c.loadTelemetryEnv()
	c.loadLoggingEnv()
}

// parseFlags parses CLI flags and overrides current configuration.
func (c *Config) parseFlags() {
	c.parseFlagsWithSet(defaultFlagSet())
}

func (c *Config) parseFlagsWithSet(fs *flag.FlagSet) {
	c.registerConnectionFlags(fs)
	port := c.registerWireGuardFlags(fs)
	tlsCAs := c.registerTLSFlags(fs)
	c.registerFeatureFlags(fs)
	c.registerHealthFlags(fs)
	c.registerPingFlags(fs)
	c.registerExitNodeFlags(fs)
	c.registerAuthDaemonFlags(fs)
	c.registerTelemetryFlags(fs)
	c.registerLoggingFlags(fs)

	_ = fs.Parse(os.Args[1:])

	// Apply post-parse conversions
	c.Port = uint16(*port)
	if *tlsCAs != "" {
		c.TLSClientCAs = strings.Split(*tlsCAs, ",")
	}
}

func (c *Config) loadConnectionEnv() {
	envString("PANGOLIN_ENDPOINT", &c.Endpoint)
	envString("NEWT_ID", &c.ID)
	envString("NEWT_SECRET", &c.Secret)
}

func (c *Config) loadWireGuardEnv() {
	envInt("MTU", &c.MTU)
	envString("DNS", &c.DNS)
	envString("INTERFACE", &c.InterfaceName)
	envUint16("PORT", &c.Port)
	envBool("USE_NATIVE_INTERFACE", &c.NativeMode)
}

func (c *Config) loadTLSEnv() {
	envString("TLS_CLIENT_CERT", &c.TLSClientCert)
	envString("TLS_CLIENT_KEY", &c.TLSClientKey)
	if v := os.Getenv("TLS_CLIENT_CAS"); v != "" {
		c.TLSClientCAs = strings.Split(v, ",")
	}
}

func (c *Config) loadFeatureEnv() {
	envBool("DISABLE_CLIENTS", &c.DisableClients)
	envString("DOCKER_SOCKET", &c.DockerSocket)
	envBool("DOCKER_ENFORCE_NETWORK_VALIDATION", &c.DockerEnforceNetworkValidation)
	envString("UPDOWN_SCRIPT", &c.UpdownScript)
	envString("BLUEPRINT_FILE", &c.BlueprintFile)
}

func (c *Config) loadHealthEnv() {
	envString("HEALTH_FILE", &c.HealthFile)
	envBool("ENFORCE_HC_CERT", &c.EnforceHealthCert)
}

func (c *Config) loadPingEnv() {
	envInt("PING_INTERVAL", &c.PingInterval)
	envInt("PING_TIMEOUT", &c.PingTimeout)
}

func (c *Config) loadExitNodeEnv() {
	envString("PREFER_ENDPOINT", &c.PreferEndpoint)
	envBool("NO_CLOUD", &c.NoCloud)
}

func (c *Config) loadAuthDaemonEnv() {
	envBool("AUTH_DAEMON_ENABLED", &c.AuthDaemonEnabled)
	envString("AD_KEY", &c.AuthDaemonKey)
	envString("AD_ADDR", &c.AuthDaemonAddr)
	envString("AD_PRINCIPALS_FILE", &c.AuthDaemonPrincipals)
	envString("AD_CA_PATH", &c.AuthDaemonCAPath)
	envString("AD_HOST_CA_PATH", &c.AuthDaemonHostCAPath)
	envBool("AD_RANDOM_PASS", &c.AuthDaemonRandomPass)
}

func (c *Config) loadTelemetryEnv() {
	envBool("NEWT_METRICS_PROMETHEUS_ENABLED", &c.MetricsEnabled)
	envBool("NEWT_METRICS_OTLP_ENABLED", &c.OTLPEnabled)
	envString("NEWT_ADMIN_ADDR", &c.AdminAddr)
	envBool("NEWT_PPROF_ENABLED", &c.PprofEnabled)
	envString("NEWT_REGION", &c.Region)
}

func (c *Config) loadLoggingEnv() {
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		c.LogLevel = strings.ToUpper(v)
	}
}

func (c *Config) registerConnectionFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.Endpoint, "endpoint", c.Endpoint, "Pangolin server WebSocket URL")
	fs.StringVar(&c.ID, "id", c.ID, "Newt client ID")
	fs.StringVar(&c.Secret, "secret", c.Secret, "Authentication secret")
}

func (c *Config) registerWireGuardFlags(fs *flag.FlagSet) *uint {
	fs.IntVar(&c.MTU, "mtu", c.MTU, "Packet MTU")
	fs.StringVar(&c.DNS, "dns", c.DNS, "DNS server IP")
	fs.StringVar(&c.InterfaceName, "interface", c.InterfaceName, "TUN interface name")
	port := fs.Uint("port", uint(c.Port), "Client WireGuard port (0 = random)")
	fs.BoolVar(&c.NativeMode, "native", c.NativeMode, "Use native WireGuard interface")
	return port
}

func (c *Config) registerTLSFlags(fs *flag.FlagSet) *string {
	fs.StringVar(&c.TLSClientCert, "tls-client-cert", c.TLSClientCert, "Path to client certificate")
	fs.StringVar(&c.TLSClientKey, "tls-client-key", c.TLSClientKey, "Path to client key")
	tlsCAs := fs.String("tls-client-cas", strings.Join(c.TLSClientCAs, ","), "Comma-separated paths to CA certificates")
	return tlsCAs
}

func (c *Config) registerFeatureFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.DisableClients, "disable-clients", c.DisableClients, "Disable WireGuard client support")
	fs.StringVar(&c.DockerSocket, "docker-socket", c.DockerSocket, "Docker socket path")
	fs.BoolVar(&c.DockerEnforceNetworkValidation, "docker-enforce-network-validation", c.DockerEnforceNetworkValidation, "Enforce validation of containers on the newt network")
	fs.StringVar(&c.UpdownScript, "updown", c.UpdownScript, "Path to up/down script")
	fs.StringVar(&c.BlueprintFile, "blueprint-file", c.BlueprintFile, "Path to blueprint YAML file")
}

func (c *Config) registerHealthFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.HealthFile, "health-file", c.HealthFile, "Path to health status file")
	fs.BoolVar(&c.EnforceHealthCert, "enforce-hc-cert", c.EnforceHealthCert, "Enforce health check certificates")
}

func (c *Config) registerPingFlags(fs *flag.FlagSet) {
	fs.IntVar(&c.PingInterval, "ping-interval", c.PingInterval, "Tunnel ping interval (seconds)")
	fs.IntVar(&c.PingTimeout, "ping-timeout", c.PingTimeout, "Tunnel ping timeout (seconds)")
}

func (c *Config) registerExitNodeFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.PreferEndpoint, "prefer-endpoint", c.PreferEndpoint, "Preferred exit node endpoint")
	fs.BoolVar(&c.NoCloud, "no-cloud", c.NoCloud, "Disable cloud failover")
}

func (c *Config) registerAuthDaemonFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.AuthDaemonEnabled, "auth-daemon", c.AuthDaemonEnabled, "Enable auth daemon")
	fs.StringVar(&c.AuthDaemonKey, "ad-pre-shared-key", c.AuthDaemonKey, "Auth daemon pre-shared key")
	fs.StringVar(&c.AuthDaemonAddr, "ad-addr", c.AuthDaemonAddr, "Auth daemon HTTPS listen address (optional)")
	fs.StringVar(&c.AuthDaemonPrincipals, "ad-principals-file", c.AuthDaemonPrincipals, "Auth daemon principals file")
	fs.StringVar(&c.AuthDaemonCAPath, "ad-ca-path", c.AuthDaemonCAPath, "Auth daemon CA path")
	fs.StringVar(&c.AuthDaemonHostCAPath, "ad-host-ca-path", c.AuthDaemonHostCAPath, "Auth daemon host CA path")
	fs.BoolVar(&c.AuthDaemonRandomPass, "ad-random-pass", c.AuthDaemonRandomPass, "Generate random password")
}

func (c *Config) registerTelemetryFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.MetricsEnabled, "metrics", c.MetricsEnabled, "Enable Prometheus metrics")
	fs.BoolVar(&c.OTLPEnabled, "otlp", c.OTLPEnabled, "Enable OpenTelemetry export")
	fs.StringVar(&c.AdminAddr, "metrics-admin-addr", c.AdminAddr, "Metrics server address")
	fs.BoolVar(&c.PprofEnabled, "pprof", c.PprofEnabled, "Enable pprof handlers on the admin server")
	fs.StringVar(&c.Region, "region", c.Region, "Region label for metrics")
}

func (c *Config) registerLoggingFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
}

// Validate checks that required configuration is present and valid.
func (c *Config) Validate() error {
	var errs []error

	errs = append(errs, c.validateRequiredFields()...)
	errs = append(errs, c.validateTLS()...)
	errs = append(errs, c.validateWireGuard()...)
	errs = append(errs, c.validateLogging()...)
	errs = append(errs, c.validateAuthDaemon()...)

	return errors.Join(errs...)
}

func (c *Config) validateRequiredFields() []error {
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
	return errs
}

func (c *Config) validateTLS() []error {
	if (c.TLSClientCert != "" || c.TLSClientKey != "") &&
		(c.TLSClientCert == "" || c.TLSClientKey == "") {
		return []error{errors.New("both tls-client-cert and tls-client-key must be specified")}
	}
	return nil
}

func (c *Config) validateWireGuard() []error {
	if c.MTU < 576 || c.MTU > 65535 {
		return []error{fmt.Errorf("mtu must be between 576 and 65535, got %d", c.MTU)}
	}
	return nil
}

func (c *Config) validateLogging() []error {
	switch c.LogLevel {
	case "DEBUG", "INFO", "WARN", "ERROR", "FATAL":
		return nil
	default:
		return []error{fmt.Errorf("invalid log level: %s", c.LogLevel)}
	}
}

func (c *Config) validateAuthDaemon() []error {
	if c.AuthDaemonEnabled && c.AuthDaemonAddr != "" && c.AuthDaemonKey == "" {
		return []error{errors.New("auth daemon pre-shared key is required when ad-addr is set")}
	}
	return nil
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

func envString(name string, dest *string) {
	if v := os.Getenv(name); v != "" {
		*dest = v
	}
}

func envBool(name string, dest *bool) {
	if v := os.Getenv(name); v != "" {
		*dest = parseBool(v)
	}
}

func envInt(name string, dest *int) {
	if v := os.Getenv(name); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			*dest = parsed
		}
	}
}

func envUint16(name string, dest *uint16) {
	if v := os.Getenv(name); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 16); err == nil {
			*dest = uint16(parsed)
		}
	}
}
