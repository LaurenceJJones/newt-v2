// Package docker provides Docker container discovery and event monitoring.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	types "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"

	"github.com/fosrl/newt/internal/control"
)

// Discovery provides Docker container discovery and monitoring.
type Discovery struct {
	logger        *slog.Logger
	controlClient *control.Client
	socketPath    string
	networkName   string // Optional: only list containers on this network
	enforceNetworkValidation bool

	// Docker client
	mu     sync.RWMutex
	docker *client.Client

	// Cached containers
	containers sync.Map // map[string]ContainerInfo

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// ContainerInfo holds information about a Docker container.
type ContainerInfo struct {
	ID       string
	Name     string
	Image    string
	State    string
	Status   string
	Ports    []control.DockerContainerPortData
	Labels   map[string]string
	Created  int64
	Networks map[string]control.DockerNetworkData
	Hostname string
}

// NewDiscovery creates a new Docker discovery instance.
func NewDiscovery(socketPath string, networkName string, enforceNetworkValidation bool, controlClient *control.Client, logger *slog.Logger) *Discovery {
	if logger == nil {
		logger = slog.Default()
	}

	return &Discovery{
		logger:        logger,
		controlClient: controlClient,
		socketPath:    socketPath,
		networkName:   networkName,
		enforceNetworkValidation: enforceNetworkValidation,
	}
}

// Name returns the component name.
func (d *Discovery) Name() string {
	return "docker"
}

// Start begins Docker discovery and event monitoring.
func (d *Discovery) Start(ctx context.Context) error {
	d.ctx, d.cancel = context.WithCancel(ctx)

	// Register message handlers
	d.controlClient.Register(control.MsgSocketCheck, d.handleCheck)
	d.controlClient.Register(control.MsgSocketFetch, d.handleFetch)

	// Try to connect to Docker
	if err := d.connect(); err != nil {
		d.logger.Warn("docker not available", "error", err)
		// Continue running - docker might become available later
	}

	// Start event monitoring
	go d.monitorEvents()

	d.logger.Info("docker discovery started", "socket", d.socketPath)

	// Wait for context cancellation
	<-d.ctx.Done()

	d.disconnect()
	return d.ctx.Err()
}

// connect establishes connection to Docker.
func (d *Discovery) connect() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	opts := []client.Opt{
		client.WithAPIVersionNegotiation(),
	}

	if d.socketPath != "" {
		opts = append(opts, client.WithHost("unix://"+d.socketPath))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	// Test connection
	_, err = cli.Ping(d.ctx)
	if err != nil {
		cli.Close()
		return fmt.Errorf("ping docker: %w", err)
	}

	d.docker = cli
	return nil
}

// disconnect closes the Docker connection.
func (d *Discovery) disconnect() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.docker != nil {
		d.docker.Close()
		d.docker = nil
	}
}

// handleCheck handles the socket check message.
func (d *Discovery) handleCheck(msg control.Message) error {
	available := d.isAvailable()

	return d.controlClient.SendData(d.ctx, control.MsgSocketStatus, control.SocketStatusData{
		Available:  available,
		SocketPath: d.socketPath,
	})
}

// handleFetch handles the socket fetch message.
func (d *Discovery) handleFetch(msg control.Message) error {
	d.logger.Debug("handling socket fetch request")

	if d.socketPath == "" {
		d.logger.Debug("docker socket path not configured")
		return nil
	}

	containers, err := d.listContainers()
	if err != nil {
		d.logger.Warn("failed to list containers", "error", err)
		return d.controlClient.SendData(d.ctx, control.MsgSocketContainers, socketContainersPayload(nil, err))
	}

	d.logger.Debug("sending container list", "count", len(containers))
	return d.controlClient.SendData(d.ctx, control.MsgSocketContainers, socketContainersPayload(containers, nil))
}

// isAvailable returns whether Docker is available.
func (d *Discovery) isAvailable() bool {
	d.mu.RLock()
	cli := d.docker
	d.mu.RUnlock()

	if cli == nil {
		// Try to connect
		if err := d.connect(); err != nil {
			return false
		}
		return true
	}

	// Test connection
	_, err := cli.Ping(d.ctx)
	return err == nil
}

// listContainers returns containers using the legacy socket-fetch semantics.
func (d *Discovery) listContainers() ([]control.DockerContainerData, error) {
	d.mu.RLock()
	cli := d.docker
	d.mu.RUnlock()

	if cli == nil {
		return nil, fmt.Errorf("docker not connected")
	}

	filterArgs := filters.NewArgs()
	useContainerIPAddresses := true
	hostContainerID := ""

	hostContainer, err := getHostContainer(d.ctx, cli)
	if d.enforceNetworkValidation && err != nil {
		return nil, fmt.Errorf("network validation enforced, cannot validate due to: %w", err)
	}
	if hostContainer != nil {
		hostContainerID = hostContainer.ID
		for hostContainerNetworkName := range hostContainer.NetworkSettings.Networks {
			if d.enforceNetworkValidation {
				filterArgs.Add("network", hostContainerNetworkName)
			}
			if useContainerIPAddresses && hostContainerNetworkName != "bridge" {
				useContainerIPAddresses = false
			}
		}
	}

	containers, err := cli.ContainerList(d.ctx, container.ListOptions{
		All:     true,
		Filters: filterArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	result := make([]control.DockerContainerData, 0, len(containers))
	for _, c := range containers {
		if hostContainerID != "" && c.ID == hostContainerID {
			continue
		}
		// Check network if specified
		if d.networkName != "" {
			if _, ok := c.NetworkSettings.Networks[d.networkName]; !ok {
				continue
			}
		}

		hostname := ""
		inspect, err := cli.ContainerInspect(d.ctx, c.ID)
		if err == nil && inspect.Config != nil {
			hostname = inspect.Config.Hostname
		}

		ports := make([]control.DockerContainerPortData, 0, len(c.Ports))
		for _, p := range c.Ports {
			portData := control.DockerContainerPortData{
				PrivatePort: int(p.PrivatePort),
				Type:        p.Type,
			}
			if p.PublicPort > 0 {
				portData.PublicPort = int(p.PublicPort)
			}
			if p.IP != "" {
				portData.IP = p.IP
			}
			ports = append(ports, portData)
		}

		networks := make(map[string]control.DockerNetworkData)
		if c.NetworkSettings != nil && c.NetworkSettings.Networks != nil {
			for networkName, endpoint := range c.NetworkSettings.Networks {
				networkData := control.DockerNetworkData{
					NetworkID:           endpoint.NetworkID,
					EndpointID:          endpoint.EndpointID,
					Gateway:             endpoint.Gateway,
					IPPrefixLen:         endpoint.IPPrefixLen,
					IPv6Gateway:         endpoint.IPv6Gateway,
					GlobalIPv6Address:   endpoint.GlobalIPv6Address,
					GlobalIPv6PrefixLen: endpoint.GlobalIPv6PrefixLen,
					MacAddress:          endpoint.MacAddress,
					Aliases:             endpoint.Aliases,
					DNSNames:            endpoint.DNSNames,
				}
				if useContainerIPAddresses {
					networkData.IPAddress = endpoint.IPAddress
				}
				networks[networkName] = networkData
			}
		}

		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}

		result = append(result, control.DockerContainerData{
			ID:       c.ID[:12],
			Name:     name,
			Image:    c.Image,
			State:    c.State,
			Status:   c.Status,
			Ports:    ports,
			Labels:   c.Labels,
			Created:  c.Created,
			Networks: networks,
			Hostname: hostname,
		})

		// Cache container info
		d.containers.Store(c.ID, ContainerInfo{
			ID:       c.ID,
			Name:     name,
			Image:    c.Image,
			State:    c.State,
			Status:   c.Status,
			Ports:    ports,
			Labels:   c.Labels,
			Created:  c.Created,
			Networks: networks,
			Hostname: hostname,
		})
	}

	return result, nil
}

func getHostContainer(ctx context.Context, cli *client.Client) (*types.ContainerJSON, error) {
	hostContainerName, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to find hostname for container")
	}

	hostContainer, err := cli.ContainerInspect(ctx, hostContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to find host container")
	}

	return &hostContainer, nil
}

// monitorEvents watches Docker events for container changes.
func (d *Discovery) monitorEvents() {
	for {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		d.mu.RLock()
		cli := d.docker
		d.mu.RUnlock()

		if cli == nil {
			time.Sleep(5 * time.Second)
			continue
		}

		// Subscribe to events
		filterArgs := filters.NewArgs()
		filterArgs.Add("type", "container")

		eventsCh, errCh := cli.Events(d.ctx, events.ListOptions{
			Filters: filterArgs,
		})

		d.logger.Debug("subscribed to docker events")

	eventLoop:
		for {
			select {
			case <-d.ctx.Done():
				return
			case err := <-errCh:
				if err != nil {
					d.logger.Warn("docker events error", "error", err)
				}
				break eventLoop
			case event := <-eventsCh:
				d.handleEvent(event)
			}
		}

		// Wait before reconnecting
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// handleEvent processes a Docker event.
func (d *Discovery) handleEvent(event events.Message) {
	switch event.Action {
	case "start", "die", "stop", "kill", "pause", "unpause":
		d.logger.Debug("container event",
			"action", event.Action,
			"container", event.Actor.ID[:12],
		)

		// Refresh container list
		containers, err := d.listContainers()
		if err != nil {
			d.logger.Warn("refresh containers failed", "error", err)
			return
		}

		// Notify server using the legacy wrapped payload shape.
		_ = d.controlClient.SendData(d.ctx, control.MsgSocketContainers, socketContainersPayload(containers, nil))
	}
}

func socketContainersPayload(containers []control.DockerContainerData, err error) map[string]any {
	payload := map[string]any{}
	if containers == nil {
		payload["containers"] = []any{}
	} else {
		payload["containers"] = containers
	}
	if err != nil {
		payload["error"] = err.Error()
	}
	return payload
}

// Shutdown gracefully shuts down Docker discovery.
func (d *Discovery) Shutdown(ctx context.Context) error {
	if d.cancel != nil {
		d.cancel()
	}
	d.disconnect()
	return nil
}

// GetContainer returns information about a specific container.
func (d *Discovery) GetContainer(id string) (ContainerInfo, bool) {
	val, ok := d.containers.Load(id)
	if !ok {
		return ContainerInfo{}, false
	}
	return val.(ContainerInfo), true
}

// parseDockerMessage is a helper to parse JSON from docker messages.
func parseDockerMessage(data json.RawMessage, v any) error {
	return json.Unmarshal(data, v)
}
