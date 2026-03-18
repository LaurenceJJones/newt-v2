package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type readLoopConn interface {
	Close() error
}

// ClientConfig holds configuration for the control plane client.
type ClientConfig struct {
	// Endpoint is the Pangolin server WebSocket URL
	Endpoint string

	// ID is the newt client identifier
	ID string

	// Secret is the authentication secret
	Secret string

	// TLS configuration (optional)
	TLSConfig *tls.Config

	// ReconnectInterval is the delay between reconnection attempts
	ReconnectInterval time.Duration

	// PingInterval is the WebSocket ping interval
	PingInterval time.Duration

	// PongTimeout is the timeout for receiving pong responses
	PongTimeout time.Duration

	// WriteTimeout is the timeout for write operations
	WriteTimeout time.Duration
}

// DefaultClientConfig returns a ClientConfig with default values.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		ReconnectInterval: 3 * time.Second,
		PingInterval:      30 * time.Second,
		PongTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
}

// Client manages the WebSocket connection to the Pangolin control plane.
type Client struct {
	cfg    ClientConfig
	logger *slog.Logger

	// Connection state
	conn      atomic.Pointer[websocket.Conn]
	connected atomic.Bool
	token     atomic.Value // stores auth token

	// Handler registry
	handlers sync.Map // map[string]Handler

	// Connection callback
	onConnect    func()
	onDisconnect func(error)
	callbackMu   sync.RWMutex

	// Write serialization
	writeMu sync.Mutex

	// Config version tracking
	configVersion atomic.Int64
	processing    atomic.Bool
}

// OnConnect sets a callback that is called when the WebSocket connection is established.
func (c *Client) OnConnect(fn func()) {
	c.callbackMu.Lock()
	defer c.callbackMu.Unlock()
	c.onConnect = fn
}

// OnDisconnect sets a callback that is called when the WebSocket connection is lost.
func (c *Client) OnDisconnect(fn func(error)) {
	c.callbackMu.Lock()
	defer c.callbackMu.Unlock()
	c.onDisconnect = fn
}

// NewClient creates a new control plane client.
func NewClient(cfg ClientConfig, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ReconnectInterval == 0 {
		cfg.ReconnectInterval = 3 * time.Second
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 30 * time.Second
	}
	if cfg.PongTimeout == 0 {
		cfg.PongTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}

	return &Client{
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the component name.
func (c *Client) Name() string {
	return "control"
}

// Register adds a handler for a message type.
// Handlers are called synchronously in the message processing loop.
func (c *Client) Register(msgType string, h Handler) {
	c.handlers.Store(msgType, h)
}

// Connected returns whether the client is currently connected.
func (c *Client) Connected() bool {
	return c.connected.Load()
}

// Token returns the current control-plane auth token, if available.
func (c *Client) Token() string {
	if v := c.token.Load(); v != nil {
		if token, ok := v.(string); ok {
			return token
		}
	}
	return ""
}

// ConfigID returns the configured newt identifier.
func (c *Client) ConfigID() string {
	return c.cfg.ID
}

// Start connects to the server and processes messages until ctx is cancelled.
// This implements the lifecycle.Component interface.
func (c *Client) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			c.disconnect()
			return ctx.Err()
		default:
		}

		// Attempt to connect
		if err := c.connect(ctx); err != nil {
			c.logger.Warn("connection failed", "error", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.cfg.ReconnectInterval):
				continue
			}
		}

		// Connection established, run message loop
		c.markConnected()

		err := c.runMessageLoop(ctx)
		c.markDisconnected(err)

		if errors.Is(err, context.Canceled) {
			return err
		}

		c.disconnect()

		// Wait before reconnecting
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.cfg.ReconnectInterval):
		}
	}
}

func (c *Client) markConnected() {
	c.connected.Store(true)
	c.logger.Info("connected to control plane")

	c.callbackMu.RLock()
	onConnect := c.onConnect
	c.callbackMu.RUnlock()
	if onConnect != nil {
		onConnect()
	}
}

func (c *Client) markDisconnected(err error) {
	c.connected.Store(false)
	if errors.Is(err, context.Canceled) {
		return
	}

	c.logger.Warn("disconnected", "error", err)
	c.callbackMu.RLock()
	onDisconnect := c.onDisconnect
	c.callbackMu.RUnlock()
	if onDisconnect != nil {
		onDisconnect(err)
	}
}

// connect establishes a WebSocket connection to the server.
func (c *Client) connect(ctx context.Context) error {
	// First, get auth token
	token, err := c.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	c.token.Store(token)

	// Build WebSocket URL with token
	wsURL, err := c.buildWebSocketURL(token)
	if err != nil {
		return fmt.Errorf("build websocket url: %w", err)
	}

	// Connect WebSocket
	dialer := websocket.Dialer{
		TLSClientConfig:  c.cfg.TLSConfig,
		HandshakeTimeout: 30 * time.Second,
	}

	conn, resp, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return fmt.Errorf("dial: %w (status=%d body=%s)", err, resp.StatusCode, string(body))
		}
		return fmt.Errorf("dial: %w", err)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}

	// Configure connection
	conn.SetReadLimit(512 * 1024) // 512KB max message size

	c.conn.Store(conn)
	return nil
}

// authenticate obtains an auth token from the server.
func (c *Client) authenticate(ctx context.Context) (string, error) {
	// Parse endpoint to get auth URL
	u, err := url.Parse(c.cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}

	// Convert ws(s) to http(s) for auth endpoint
	scheme := "https"
	switch u.Scheme {
	case "ws":
		scheme = "http"
	}

	// Use the correct auth endpoint: /api/v1/auth/newt/get-token
	authURL := fmt.Sprintf("%s://%s/api/v1/auth/newt/get-token", scheme, u.Host)

	// Create request with correct field names
	reqBody := fmt.Sprintf(`{"newtId":"%s","secret":"%s"}`, c.cfg.ID, c.cfg.Secret)
	req, err := http.NewRequestWithContext(ctx, "POST", authURL,
		&stringReader{s: reqBody})
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "x-csrf-protection") // Required CSRF token

	// Use TLS config if provided
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if c.cfg.TLSConfig != nil {
		transport.TLSClientConfig = c.cfg.TLSConfig
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	// Parse response - the token is nested in data.token
	var authResp struct {
		Success bool `json:"success"`
		Data    struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	if !authResp.Success || authResp.Data.Token == "" {
		return "", errors.New("authentication failed or empty token")
	}

	return authResp.Data.Token, nil
}

// buildWebSocketURL constructs the WebSocket URL with auth token.
func (c *Client) buildWebSocketURL(token string) (string, error) {
	u, err := url.Parse(c.cfg.Endpoint)
	if err != nil {
		return "", err
	}

	// Ensure WebSocket scheme
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}

	// Set the WebSocket endpoint path
	u.Path = "/api/v1/ws"

	// Add token and client type to query
	q := u.Query()
	q.Set("token", token)
	q.Set("clientType", "newt")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// runMessageLoop reads and processes messages until an error occurs.
func (c *Client) runMessageLoop(ctx context.Context) error {
	conn := c.conn.Load()
	if conn == nil {
		return errors.New("not connected")
	}

	stopInterrupt := interruptReadOnCancel(ctx, conn)
	defer stopInterrupt()

	// Start ping routine
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		c.pingLoop(ctx, conn)
	}()

	defer func() {
		<-pingDone
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read message: %w", err)
		}

		msg, err := c.decodeMessage(msgType, data)
		if err != nil {
			c.logger.Warn("invalid message", "error", err)
			continue
		}

		// Track config version
		if msg.ConfigVersion > 0 {
			c.configVersion.Store(msg.ConfigVersion)
		}
		if msg.Type == MsgPong {
			continue
		}

		// Find and call handler
		if handler, ok := c.handlers.Load(msg.Type); ok {
			h := handler.(Handler)
			c.processing.Store(true)
			if err := h(msg); err != nil {
				c.logger.Error("handler error",
					"type", msg.Type,
					"error", err,
				)
			}
			c.processing.Store(false)
		} else {
			c.logger.Debug("unhandled message type", "type", msg.Type)
		}
	}
}

func interruptReadOnCancel(ctx context.Context, conn readLoopConn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}

func (c *Client) decodeMessage(msgType int, data []byte) (Message, error) {
	if msgType == websocket.BinaryMessage {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return Message{}, fmt.Errorf("create gzip reader: %w", err)
		}
		defer func() { _ = gr.Close() }()

		uncompressed, err := io.ReadAll(gr)
		if err != nil {
			return Message{}, fmt.Errorf("decompress message: %w", err)
		}
		data = uncompressed
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, fmt.Errorf("unmarshal message: %w", err)
	}
	return msg, nil
}

func (c *Client) sendPing(conn *websocket.Conn) error {
	if c.processing.Load() {
		c.logger.Debug("skipping ping while processing message")
		return nil
	}

	msg := Message{
		Type:          MsgPing,
		Data:          json.RawMessage(`{}`),
		ConfigVersion: c.configVersion.Load(),
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := conn.WriteJSON(msg); err != nil {
		return fmt.Errorf("write ping: %w", err)
	}
	return nil
}

// pingLoop sends periodic application ping messages to keep the connection alive.
func (c *Client) pingLoop(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(c.cfg.PingInterval)
	defer ticker.Stop()

	if err := c.sendPing(conn); err != nil {
		c.logger.Debug("ping failed", "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.sendPing(conn); err != nil {
				c.logger.Debug("ping failed", "error", err)
				return
			}
		}
	}
}

// Send transmits a message to the server.
func (c *Client) Send(ctx context.Context, msg Message) error {
	conn := c.conn.Load()
	if conn == nil {
		return errors.New("not connected")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Set write deadline from context or default
	deadline := time.Now().Add(c.cfg.WriteTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	if err := conn.WriteJSON(msg); err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	return nil
}

// SendData is a convenience method for sending a typed message.
func (c *Client) SendData(ctx context.Context, msgType string, data any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal data: %w", err)
	}

	return c.Send(ctx, Message{
		Type: msgType,
		Data: jsonData,
	})
}

// disconnect closes the current connection.
func (c *Client) disconnect() {
	conn := c.conn.Swap(nil)
	if conn != nil {
		// Send close message with best effort
		c.writeMu.Lock()
		_ = conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, ""),
			time.Now().Add(time.Second),
		)
		c.writeMu.Unlock()
		_ = conn.Close()
	}
}

// Shutdown gracefully disconnects from the server.
func (c *Client) Shutdown(ctx context.Context) error {
	c.disconnect()
	return nil
}

// stringReader is a simple io.Reader for strings.
type stringReader struct {
	s   string
	pos int
}

func (r *stringReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.pos:])
	r.pos += n
	return n, nil
}
