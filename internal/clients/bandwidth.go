package clients

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fosrl/newt/internal/control"
)

func (m *Manager) runBandwidthReporting(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.reportPeerBandwidth(ctx); err != nil {
				m.logger.Debug("failed to report peer bandwidth", "error", err)
			}
		}
	}
}

func (m *Manager) reportPeerBandwidth(ctx context.Context) error {
	bandwidths, err := m.calculatePeerBandwidth()
	if err != nil {
		return err
	}
	if len(bandwidths) == 0 {
		return nil
	}

	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return m.control.SendData(sendCtx, control.MsgReceiveBandwidth, map[string]any{
		"bandwidthData": bandwidths,
	})
}

func (m *Manager) calculatePeerBandwidth() ([]peerBandwidth, error) {
	m.mu.Lock()
	device := m.device
	m.mu.Unlock()

	if device == nil {
		return nil, nil
	}

	stats, err := device.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("get client WG stats: %w", err)
	}

	now := time.Now()
	bandwidths := make([]peerBandwidth, 0)

	m.mu.Lock()
	defer m.mu.Unlock()

	lines := strings.Split(stats, "\n")
	var currentPubKey string
	var rxBytes, txBytes int64
	devicePeers := make(map[string]struct{})

	processCurrent := func() {
		if currentPubKey == "" {
			return
		}
		if bw := m.processPeerBandwidth(currentPubKey, rxBytes, txBytes, now); bw != nil {
			bandwidths = append(bandwidths, *bw)
		}
	}

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "public_key="):
			processCurrent()
			currentPubKey = strings.TrimPrefix(line, "public_key=")
			devicePeers[currentPubKey] = struct{}{}
			rxBytes = 0
			txBytes = 0
		case strings.HasPrefix(line, "rx_bytes="):
			rxBytes, _ = strconv.ParseInt(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
		case strings.HasPrefix(line, "tx_bytes="):
			txBytes, _ = strconv.ParseInt(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
		}
	}
	processCurrent()

	for publicKey := range m.lastReadings {
		if _, ok := devicePeers[publicKey]; !ok {
			delete(m.lastReadings, publicKey)
		}
	}

	return bandwidths, nil
}

func (m *Manager) processPeerBandwidth(publicKey string, rxBytes, txBytes int64, now time.Time) *peerBandwidth {
	current := peerReading{
		BytesReceived:    rxBytes,
		BytesTransmitted: txBytes,
		LastChecked:      now,
	}

	last, ok := m.lastReadings[publicKey]
	m.lastReadings[publicKey] = current
	if !ok {
		return nil
	}

	if !current.LastChecked.After(last.LastChecked) {
		return nil
	}

	bytesInDiff := float64(current.BytesReceived - last.BytesReceived)
	bytesOutDiff := float64(current.BytesTransmitted - last.BytesTransmitted)
	if bytesInDiff < 0 {
		bytesInDiff = float64(current.BytesReceived)
	}
	if bytesOutDiff < 0 {
		bytesOutDiff = float64(current.BytesTransmitted)
	}
	if bytesInDiff == 0 && bytesOutDiff == 0 {
		return nil
	}

	return &peerBandwidth{
		PublicKey: normalizeIPCKeyToBase64(publicKey),
		BytesIn:   bytesInDiff / (1024 * 1024),
		BytesOut:  bytesOutDiff / (1024 * 1024),
	}
}

func normalizeIPCKeyToBase64(publicKey string) string {
	keyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return publicKey
	}
	return base64.StdEncoding.EncodeToString(keyBytes)
}
