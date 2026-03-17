package holepunch

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/internal/bind"
)

type TestResult struct {
	Success  bool
	RTT      time.Duration
	Endpoint string
	Error    error
}

type TestConnectionOptions struct {
	Timeout time.Duration
	Retries int
}

func DefaultTestOptions() TestConnectionOptions {
	return TestConnectionOptions{
		Timeout: 5 * time.Second,
		Retries: 0,
	}
}

type HolepunchStatus struct {
	Endpoint  string
	Connected bool
	RTT       time.Duration
}

type HolepunchStatusCallback func(status HolepunchStatus)

type pendingRequest struct {
	endpoint  string
	sentAt    time.Time
	replyChan chan time.Duration
}

type cachedAddr struct {
	addr       *net.UDPAddr
	resolvedAt time.Time
}

type Tester struct {
	sharedBind *bind.SharedBind
	logger     *slog.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
	callback HolepunchStatusCallback

	pendingRequests sync.Map

	addrCache    map[string]*cachedAddr
	addrCacheMu  sync.RWMutex
	addrCacheTTL time.Duration
}

func NewTester(sharedBind *bind.SharedBind, logger *slog.Logger) *Tester {
	if logger == nil {
		logger = slog.Default()
	}
	return &Tester{
		sharedBind:   sharedBind,
		logger:       logger,
		addrCache:    make(map[string]*cachedAddr),
		addrCacheTTL: 5 * time.Minute,
	}
}

func (t *Tester) SetCallback(callback HolepunchStatusCallback) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.callback = callback
}

func (t *Tester) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return fmt.Errorf("tester already running")
	}
	if t.sharedBind == nil {
		return fmt.Errorf("shared bind is nil")
	}

	t.running = true
	t.stopChan = make(chan struct{})
	t.sharedBind.SetMagicResponseCallback(t.handleResponse)
	return nil
}

func (t *Tester) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return
	}

	t.running = false
	close(t.stopChan)
	if t.sharedBind != nil {
		t.sharedBind.SetMagicResponseCallback(nil)
	}
	t.pendingRequests.Range(func(key, value any) bool {
		if req, ok := value.(*pendingRequest); ok {
			close(req.replyChan)
		}
		t.pendingRequests.Delete(key)
		return true
	})

	t.addrCacheMu.Lock()
	t.addrCache = make(map[string]*cachedAddr)
	t.addrCacheMu.Unlock()
}

func (t *Tester) resolveEndpoint(endpoint string) (*net.UDPAddr, error) {
	t.addrCacheMu.RLock()
	cached, ok := t.addrCache[endpoint]
	ttl := t.addrCacheTTL
	t.addrCacheMu.RUnlock()
	if ok && time.Since(cached.resolvedAt) < ttl {
		return cached.addr, nil
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
		port = "21820"
	}

	if parsed := net.ParseIP(host); parsed == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("lookup ip for %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no ip addresses found for %s", host)
		}

		resolved := ""
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				resolved = v4.String()
				break
			}
		}
		if resolved == "" {
			resolved = ips[0].String()
		}
		host = resolved
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %s:%s: %w", host, port, err)
	}

	t.addrCacheMu.Lock()
	t.addrCache[endpoint] = &cachedAddr{
		addr:       addr,
		resolvedAt: time.Now(),
	}
	t.addrCacheMu.Unlock()
	return addr, nil
}

func (t *Tester) handleResponse(addr netip.AddrPort, echoData []byte) {
	value, ok := t.pendingRequests.LoadAndDelete(string(echoData))
	if !ok {
		t.logger.Debug("hole punch tester response without pending request", "from", addr.String())
		return
	}
	req := value.(*pendingRequest)
	rtt := time.Since(req.sentAt)
	t.logger.Debug("hole punch tester response received", "endpoint", req.endpoint, "from", addr.String(), "rtt", rtt)

	select {
	case req.replyChan <- rtt:
	default:
	}

	t.mu.RLock()
	callback := t.callback
	t.mu.RUnlock()
	if callback != nil {
		callback(HolepunchStatus{
			Endpoint:  req.endpoint,
			Connected: true,
			RTT:       rtt,
		})
	}

	_ = addr
}

func (t *Tester) TestEndpoint(endpoint string, timeout time.Duration) TestResult {
	result := TestResult{Endpoint: endpoint}

	t.mu.RLock()
	running := t.running
	sharedBind := t.sharedBind
	callback := t.callback
	t.mu.RUnlock()

	if !running {
		result.Error = fmt.Errorf("tester not running")
		return result
	}
	if sharedBind == nil || sharedBind.IsClosed() {
		result.Error = fmt.Errorf("shared bind is nil or closed")
		return result
	}

	remoteAddr, err := t.resolveEndpoint(endpoint)
	if err != nil {
		result.Error = err
		return result
	}

	randomData := make([]byte, bind.MagicPacketDataLen)
	if _, err := rand.Read(randomData); err != nil {
		result.Error = fmt.Errorf("generate random data: %w", err)
		return result
	}

	req := &pendingRequest{
		endpoint:  endpoint,
		sentAt:    time.Now(),
		replyChan: make(chan time.Duration, 1),
	}
	key := string(randomData)
	t.pendingRequests.Store(key, req)

	packet := make([]byte, bind.MagicTestRequestLen)
	copy(packet, bind.MagicTestRequest)
	copy(packet[len(bind.MagicTestRequest):], randomData)

	if _, err := sharedBind.WriteToUDP(packet, remoteAddr); err != nil {
		t.pendingRequests.Delete(key)
		result.Error = fmt.Errorf("send test packet: %w", err)
		return result
	}
	if local := sharedBind.GetUDPConn(); local != nil {
		t.logger.Debug("hole punch tester packet sent", "endpoint", endpoint, "local_addr", local.LocalAddr().String(), "remote_addr", remoteAddr.String())
	} else {
		t.logger.Debug("hole punch tester packet sent", "endpoint", endpoint, "remote_addr", remoteAddr.String())
	}

	select {
	case rtt, ok := <-req.replyChan:
		if ok {
			result.Success = true
			result.RTT = rtt
			return result
		}
		result.Error = fmt.Errorf("request cancelled")
	case <-time.After(timeout):
		t.pendingRequests.Delete(key)
		result.Error = fmt.Errorf("timeout waiting for response")
	}

	if callback != nil {
		callback(HolepunchStatus{
			Endpoint:  endpoint,
			Connected: false,
		})
	}

	return result
}
