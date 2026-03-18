// Package control provides the WebSocket control plane client for communicating
// with the Pangolin server.
package control

import "encoding/json"

// Message represents a control plane message.
type Message struct {
	Type          string          `json:"type"`
	Data          json.RawMessage `json:"data"`
	ConfigVersion int64           `json:"configVersion,omitempty"`
}

// Handler processes incoming messages for a specific type.
type Handler func(msg Message) error

// WgRegisterData is sent to the server to register this newt and request configuration.
type WgRegisterData struct {
	PublicKey           string               `json:"publicKey"`
	PingResults         []ExitNodePingResult `json:"pingResults,omitempty"`
	NewtVersion         string               `json:"newtVersion,omitempty"`
	BackwardsCompatible bool                 `json:"backwardsCompatible"`
}

// SocketStatusData is sent to the server to report Docker socket availability.
type SocketStatusData struct {
	Available  bool   `json:"available"`
	SocketPath string `json:"socketPath"`
}

// WgConnectData contains WireGuard connection parameters from the server.
type WgConnectData struct {
	Endpoint           string            `json:"endpoint"`
	RelayPort          uint16            `json:"relayPort"`
	ServerIP           string            `json:"serverIP"`
	PublicKey          string            `json:"publicKey"`
	TunnelIP           string            `json:"tunnelIP"`
	Targets            TargetsByType     `json:"targets"`
	HealthCheckTargets []HealthCheckData `json:"healthCheckTargets"`
}

// TargetsByType groups targets by protocol type.
type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

// TargetsData represents a list of targets sent in add/remove messages.
type TargetsData struct {
	Targets []string `json:"targets"`
}

// HealthCheckData matches the legacy healthcheck.Config wire shape.
type HealthCheckData struct {
	ID                int               `json:"id"`
	Enabled           bool              `json:"hcEnabled"`
	Path              string            `json:"hcPath"`
	Scheme            string            `json:"hcScheme"`
	Mode              string            `json:"hcMode"`
	Hostname          string            `json:"hcHostname"`
	Port              int               `json:"hcPort"`
	Interval          int               `json:"hcInterval"`
	UnhealthyInterval int               `json:"hcUnhealthyInterval"`
	Timeout           int               `json:"hcTimeout"`
	Headers           map[string]string `json:"hcHeaders"`
	Method            string            `json:"hcMethod"`
	Status            int               `json:"hcStatus"`
	TLSServerName     string            `json:"hcTlsServerName"`
}

// SyncData contains bulk configuration for targets and health checks.
type SyncData struct {
	Targets            TargetsByType     `json:"targets"`
	HealthCheckTargets []HealthCheckData `json:"healthCheckTargets"`
}

// DockerContainerData represents a Docker container.
type DockerContainerData struct {
	ID       string                         `json:"id"`
	Name     string                         `json:"name"`
	Image    string                         `json:"image"`
	State    string                         `json:"state"`
	Status   string                         `json:"status"`
	Ports    []DockerContainerPortData      `json:"ports"`
	Labels   map[string]string              `json:"labels"`
	Created  int64                          `json:"created"`
	Networks map[string]DockerNetworkData   `json:"networks"`
	Hostname string                         `json:"hostname"`
}

// DockerContainerPortData matches the legacy docker.Port wire shape.
type DockerContainerPortData struct {
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
	IP          string `json:"ip,omitempty"`
}

// DockerNetworkData matches the legacy docker.Network wire shape.
type DockerNetworkData struct {
	NetworkID           string   `json:"networkId"`
	EndpointID          string   `json:"endpointId"`
	Gateway             string   `json:"gateway,omitempty"`
	IPAddress           string   `json:"ipAddress,omitempty"`
	IPPrefixLen         int      `json:"ipPrefixLen,omitempty"`
	IPv6Gateway         string   `json:"ipv6Gateway,omitempty"`
	GlobalIPv6Address   string   `json:"globalIPv6Address,omitempty"`
	GlobalIPv6PrefixLen int      `json:"globalIPv6PrefixLen,omitempty"`
	MacAddress          string   `json:"macAddress,omitempty"`
	Aliases             []string `json:"aliases,omitempty"`
	DNSNames            []string `json:"dnsNames,omitempty"`
}

// PAMConnectionData represents PAM authentication data.
type PAMConnectionData struct {
	MessageID          int    `json:"messageId"`
	AgentPort          int    `json:"agentPort"`
	AgentHost          string `json:"agentHost"`
	ExternalAuthDaemon bool   `json:"externalAuthDaemon"`
	CACert             string `json:"caCert"`
	Username           string `json:"username"`
	NiceID             string `json:"niceId"`
	Metadata           struct {
		SudoMode     string   `json:"sudoMode"`
		SudoCommands []string `json:"sudoCommands"`
		Homedir      bool     `json:"homedir"`
		Groups       []string `json:"groups"`
	} `json:"metadata"`
}

// BlueprintData represents initial configuration from a blueprint file.
type BlueprintData struct {
	Targets            TargetsByType     `json:"targets"`
	HealthCheckTargets []HealthCheckData `json:"healthCheckTargets"`
}

// BlueprintApplyData is sent to request server-side blueprint application.
type BlueprintApplyData struct {
	Blueprint string `json:"blueprint"`
}

// BlueprintResultData contains the server result for a blueprint application.
type BlueprintResultData struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ClientWGConfig matches the legacy clients.WgConfig payload.
type ClientWGConfig struct {
	IpAddress string           `json:"ipAddress"`
	Peers     []ClientWGPeer   `json:"peers"`
	Targets   []ClientWGTarget `json:"targets"`
}

// ClientWGTarget matches the legacy clients.Target payload.
type ClientWGTarget struct {
	SourcePrefix   string              `json:"sourcePrefix"`
	SourcePrefixes []string            `json:"sourcePrefixes"`
	DestPrefix     string              `json:"destPrefix"`
	RewriteTo      string              `json:"rewriteTo,omitempty"`
	DisableIcmp    bool                `json:"disableIcmp,omitempty"`
	PortRange      []ClientWGPortRange `json:"portRange,omitempty"`
}

// ClientWGPortRange matches the legacy clients.PortRange payload.
type ClientWGPortRange struct {
	Min      uint16 `json:"min"`
	Max      uint16 `json:"max"`
	Protocol string `json:"protocol"`
}

// ClientWGPeer matches the legacy clients.Peer payload.
type ClientWGPeer struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIps"`
	Endpoint   string   `json:"endpoint"`
}

// ClientWGGetConfigData matches the legacy newt/wg/get-config request.
type ClientWGGetConfigData struct {
	PublicKey string `json:"publicKey"`
	Port      uint16 `json:"port"`
}

// Common message types sent from server to newt.
const (
	MsgPing            = "newt/ping"
	MsgWgConnect       = "newt/wg/connect"
	MsgWgReconnect     = "newt/wg/reconnect"
	MsgWgTerminate     = "newt/wg/terminate"
	MsgPingExitNodes   = "newt/ping/exitNodes"
	MsgTCPAdd          = "newt/tcp/add"
	MsgTCPRemove       = "newt/tcp/remove"
	MsgUDPAdd          = "newt/udp/add"
	MsgUDPRemove       = "newt/udp/remove"
	MsgSync            = "newt/sync"
	MsgHealthCheckAdd  = "newt/healthcheck/add"
	MsgHealthCheckRemove = "newt/healthcheck/remove"
	MsgHealthCheckEnable = "newt/healthcheck/enable"
	MsgHealthCheckDisable = "newt/healthcheck/disable"
	MsgHealthCheckStatusReq = "newt/healthcheck/status/request"
	MsgSocketCheck     = "newt/socket/check"
	MsgSocketFetch     = "newt/socket/fetch"
	MsgPAMConnection   = "newt/pam/connection"
	MsgBlueprintResults = "newt/blueprint/results"
	MsgBlueprintApply  = "newt/blueprint/apply"
	MsgClientWGReceiveConfig = "newt/wg/receive-config"
	MsgClientWGPeerAdd       = "newt/wg/peer/add"
	MsgClientWGPeerRemove    = "newt/wg/peer/remove"
	MsgClientWGPeerUpdate    = "newt/wg/peer/update"
	MsgClientWGTargetsAdd    = "newt/wg/targets/add"
	MsgClientWGTargetsRemove = "newt/wg/targets/remove"
	MsgClientWGTargetsUpdate = "newt/wg/targets/update"
	MsgClientWGSync          = "newt/wg/sync"
)

// Common message types sent from newt to server.
const (
	MsgWgRegister        = "newt/wg/register"
	MsgPingRequest       = "newt/ping/request"
	MsgPingResults       = "newt/ping/results"
	MsgHealthCheckStatus = "newt/healthcheck/status"
	MsgSocketStatus      = "newt/socket/status"
	MsgSocketContainers  = "newt/socket/containers"
	MsgDisconnecting     = "newt/disconnecting"
	MsgClientWGGetConfig = "newt/wg/get-config"
	MsgReceiveBandwidth  = "newt/receive-bandwidth"
)

// PingRequestData is sent to request exit nodes for latency testing.
type PingRequestData struct {
	NoCloud bool `json:"noCloud"`
}

// ExitNodesData contains the list of exit nodes from the server.
type ExitNodesData struct {
	ExitNodes []ExitNode `json:"exitNodes"`
}

// ExitNode represents an exit node for latency testing.
type ExitNode struct {
	ID                     int     `json:"exitNodeId"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	Weight                 float64 `json:"weight"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

// ExitNodePingResult contains the ping result for an exit node.
type ExitNodePingResult struct {
	ExitNodeID             int     `json:"exitNodeId"`
	LatencyMs              int64   `json:"latencyMs"`
	Weight                 float64 `json:"weight"`
	Error                  string  `json:"error,omitempty"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}
