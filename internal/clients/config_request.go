package clients

import (
	"context"
	"time"

	"github.com/fosrl/newt/internal/control"
)

// RequestConfig requests downstream client configuration from the control plane.
func (m *Manager) RequestConfig(ctx context.Context) error {
	if err := m.sendConfigRequest(ctx); err != nil {
		return err
	}

	m.startConfigRequestLoop()
	return nil
}

func (m *Manager) sendConfigRequest(ctx context.Context) error {
	if m.sendConfigRequestFn != nil {
		return m.sendConfigRequestFn(ctx)
	}
	return m.control.SendData(ctx, control.MsgClientWGGetConfig, control.ClientWGGetConfigData{
		PublicKey: m.PublicKey(),
		Port:      m.port,
	})
}

func (m *Manager) startConfigRequestLoop() {
	m.mu.Lock()
	if m.configRequestCancel != nil {
		m.configRequestCancel()
		m.mu.Unlock()
		m.configRequestWG.Wait()
		m.mu.Lock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.configRequestCancel = cancel
	m.configRequestWG.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.configRequestWG.Done()

		interval := m.configRequestEvery
		if interval <= 0 {
			interval = 2 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if m.sendConfigRequestFn == nil && (m.control == nil || !m.control.Connected()) {
					continue
				}
				sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := m.sendConfigRequest(sendCtx)
				sendCancel()
				if err != nil {
					m.logger.Debug("client WG config request failed", "error", err)
				}
			}
		}
	}()
}

func (m *Manager) stopConfigRequests() {
	m.mu.Lock()
	cancel := m.configRequestCancel
	m.configRequestCancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
		m.configRequestWG.Wait()
	}
}
