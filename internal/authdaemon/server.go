package authdaemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/fosrl/newt/internal/control"
)

type Config struct {
	DisableHTTPS           bool
	ListenAddr             string
	PreSharedKey           string
	CACertPath             string
	HostCAPath             string
	PrincipalsFilePath     string
	Force                  bool
	GenerateRandomPassword bool
}

type ConnectionMetadata struct {
	SudoMode     string   `json:"sudoMode"`
	SudoCommands []string `json:"sudoCommands"`
	Homedir      bool     `json:"homedir"`
	Groups       []string `json:"groups"`
}

type ConnectionRequest struct {
	CaCert   string             `json:"caCert"`
	NiceId   string             `json:"niceId"`
	Username string             `json:"username"`
	Metadata ConnectionMetadata `json:"metadata"`
}

type Server struct {
	cfg           Config
	logger        *slog.Logger
	controlClient *control.Client
	server        *http.Server
	tlsCert       tls.Certificate
}

func NewServer(cfg Config, controlClient *control.Client, logger *slog.Logger) (*Server, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("auth-daemon is only supported on Linux, not %s", runtime.GOOS)
	}
	if cfg.CACertPath == "" {
		return nil, fmt.Errorf("CACertPath is required")
	}
	if cfg.PrincipalsFilePath == "" {
		return nil, fmt.Errorf("PrincipalsFilePath is required")
	}
	if !cfg.DisableHTTPS {
		if cfg.ListenAddr == "" {
			return nil, fmt.Errorf("ListenAddr is required when HTTPS is enabled")
		}
		if cfg.PreSharedKey == "" {
			return nil, fmt.Errorf("PreSharedKey is required when HTTPS is enabled")
		}
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:           cfg,
		logger:        logger,
		controlClient: controlClient,
	}
	if !cfg.DisableHTTPS {
		cert, err := generateTLSCert()
		if err != nil {
			return nil, err
		}
		s.tlsCert = cert
	}
	return s, nil
}

func (s *Server) Name() string {
	return "authdaemon"
}

func (s *Server) Start(ctx context.Context) error {
	if s.controlClient != nil {
		s.controlClient.Register(control.MsgPAMConnection, s.handlePAMConnection)
	}

	if s.cfg.DisableHTTPS {
		s.logger.Info("auth-daemon running (HTTPS disabled)")
		<-ctx.Done()
		s.cleanupPrincipalsFile()
		return ctx.Err()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/connection", s.handleConnection)

	s.server = &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.authMiddleware(mux),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{s.tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			s.logger.Warn("auth-daemon shutdown failed", "error", err)
		}
	}()

	s.logger.Info("auth-daemon listening", "addr", s.cfg.ListenAddr)
	err := s.server.ListenAndServeTLS("", "")
	s.cleanupPrincipalsFile()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return ctx.Err()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) GetCAPath() string {
	return s.cfg.CACertPath
}

func (s *Server) GetHostCAPath() string {
	return s.cfg.HostCAPath
}

func (s *Server) ProcessConnection(req ConnectionRequest) {
	s.logger.Info("auth-daemon connection", "nice_id", req.NiceId, "username", req.Username, "sudo_mode", req.Metadata.SudoMode)

	if s.cfg.CACertPath != "" {
		if err := writeCACertIfNotExists(s.cfg.CACertPath, req.CaCert, s.cfg.Force); err != nil {
			s.logger.Warn("auth-daemon write CA cert failed", "error", err)
		}
	}
	if err := ensureUser(req.Username, req.Metadata, s.cfg.GenerateRandomPassword); err != nil {
		s.logger.Warn("auth-daemon ensure user failed", "error", err)
	}
	if s.cfg.PrincipalsFilePath != "" {
		if err := writePrincipals(s.cfg.PrincipalsFilePath, req.Username, req.NiceId); err != nil {
			s.logger.Warn("auth-daemon write principals failed", "error", err)
		}
	}
}

func (s *Server) handlePAMConnection(msg control.Message) error {
	var data control.PAMConnectionData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("unmarshal pam data: %w", err)
	}

	s.ProcessConnection(ConnectionRequest{
		CaCert:   data.CACert,
		NiceId:   data.NiceID,
		Username: data.Username,
		Metadata: ConnectionMetadata{
			SudoMode:     data.Metadata.SudoMode,
			SudoCommands: data.Metadata.SudoCommands,
			Homedir:      data.Metadata.Homedir,
			Groups:       data.Metadata.Groups,
		},
	})
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	s.ProcessConnection(req)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		key := ""
		if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
			key = strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
		}
		if key == "" {
			key = strings.TrimSpace(r.Header.Get("X-Preshared-Key"))
		}
		if key == "" || subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.PreSharedKey)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cleanupPrincipalsFile() {
	if s.cfg.PrincipalsFilePath != "" {
		if err := os.Remove(s.cfg.PrincipalsFilePath); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("auth-daemon remove principals failed", "error", err)
		}
	}
}

func generateTLSCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("x509 key pair: %w", err)
	}
	return cert, nil
}
