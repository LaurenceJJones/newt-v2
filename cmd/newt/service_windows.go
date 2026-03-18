//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "NewtWireguardService"
	serviceDisplayName = "Newt WireGuard Tunnel Service"
	serviceDescription = "Newt WireGuard tunnel service for secure network connectivity"
)

func getServiceArgsPath() string {
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "newt")
	return filepath.Join(logDir, "service_args.json")
}

func saveServiceArgs(args []string) error {
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "newt")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("failed to marshal service args: %w", err)
	}

	if err := os.WriteFile(getServiceArgsPath(), data, 0o644); err != nil {
		return fmt.Errorf("failed to write service args: %w", err)
	}

	return nil
}

func loadServiceArgs() ([]string, error) {
	data, err := os.ReadFile(getServiceArgsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read service args: %w", err)
	}

	var args []string
	if err := json.Unmarshal(data, &args); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service args: %w", err)
	}

	return args, nil
}

type newtService struct {
	elog debug.Log
	ctx  context.Context
	stop context.CancelFunc
	args []string
}

func (s *newtService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	savedArgs, err := loadServiceArgs()
	if err != nil {
		s.elog.Error(1, fmt.Sprintf("failed to load service args: %v", err))
		savedArgs = []string{}
	}

	finalArgs := []string{}
	if len(args) > 0 {
		if len(args) == 1 && args[0] == serviceName {
		} else if len(args) > 1 && args[0] == serviceName {
			finalArgs = append(finalArgs, args[1:]...)
		} else {
			finalArgs = append(finalArgs, args...)
		}
	}
	if len(finalArgs) == 0 && len(savedArgs) > 0 {
		finalArgs = savedArgs
	}
	s.args = finalArgs

	done := make(chan struct{})
	go func() {
		s.runNewt()
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				if s.stop != nil {
					s.stop()
				}
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case <-done:
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

func (s *newtService) runNewt() {
	s.ctx, s.stop = context.WithCancel(context.Background())
	setupWindowsLogFile()

	if err := runWithArgs(s.ctx, s.args); err != nil && err != context.Canceled {
		s.elog.Error(1, fmt.Sprintf("newt service failed: %v", err))
	}
}

func runService(name string, isDebug bool, args []string) {
	var (
		elog debug.Log
		err  error
	)

	if isDebug {
		elog = debug.New(name)
		fmt.Printf("Starting %s service in debug mode\n", name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			fmt.Printf("Failed to open event log: %v\n", err)
			return
		}
	}
	defer elog.Close()

	run := svc.Run
	if isDebug {
		run = debug.Run
	}

	if err := run(name, &newtService{elog: elog, args: args}); err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", name, err))
		if isDebug {
			fmt.Printf("Service failed: %v\n", err)
		}
	}
}

func installService() error {
	exepath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err := m.CreateService(serviceName, exepath, mgr.Config{
		ServiceType:    0x10,
		StartType:      mgr.StartManual,
		ErrorControl:   mgr.ErrorNormal,
		DisplayName:    serviceDisplayName,
		Description:    serviceDescription,
		BinaryPathName: exepath,
	})
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		_ = s.Delete()
		return fmt.Errorf("failed to install event log: %w", err)
	}
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("failed to query service status: %w", err)
	}

	if status.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("failed to stop service: %w", err)
		}
		timeout := time.Now().Add(30 * time.Second)
		for status.State != svc.Stopped {
			if timeout.Before(time.Now()) {
				return fmt.Errorf("timeout waiting for service to stop")
			}
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				return fmt.Errorf("failed to query service status: %w", err)
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	if err := eventlog.Remove(serviceName); err != nil {
		return fmt.Errorf("failed to remove event log: %w", err)
	}
	return nil
}

func startService(args []string) error {
	if err := saveServiceArgs(args); err != nil {
		fmt.Printf("Warning: failed to save service args: %v\n", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	if err := s.Start(args...); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	return nil
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	timeout := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to stop")
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("failed to query service status: %w", err)
		}
	}
	return nil
}

func debugService(args []string) error {
	if len(args) > 0 {
		if err := saveServiceArgs(args); err != nil {
			return fmt.Errorf("failed to save service args: %w", err)
		}
	}
	runService(serviceName, true, args)
	return nil
}

func watchLogFile(end bool) error {
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "newt", "logs")
	logPath := filepath.Join(logDir, "newt.log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	var file *os.File
	var err error
	for i := 0; i < 30; i++ {
		file, err = os.Open(logPath)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("failed to open log file after waiting: %w", err)
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("failed to seek to end of file: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	buffer := make([]byte, 4096)
	for {
		select {
		case <-sigCh:
			if end {
				_ = stopService()
			}
			return nil
		case <-ticker.C:
			n, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				file.Close()
				file, err = os.Open(logPath)
				if err != nil {
					continue
				}
				continue
			}
			if n > 0 {
				fmt.Print(string(buffer[:n]))
			}
		}
	}
}

func getServiceStatus() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return "Not Installed", nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("failed to query service status: %w", err)
	}

	switch status.State {
	case svc.Stopped:
		return "Stopped", nil
	case svc.StartPending:
		return "Starting", nil
	case svc.StopPending:
		return "Stopping", nil
	case svc.Running:
		return "Running", nil
	case svc.ContinuePending:
		return "Continue Pending", nil
	case svc.PausePending:
		return "Pause Pending", nil
	case svc.Paused:
		return "Paused", nil
	default:
		return "Unknown", nil
	}
}

func showServiceConfig() {
	configPath := getServiceArgsPath()
	fmt.Printf("Service configuration file: %s\n", configPath)

	args, err := loadServiceArgs()
	if err != nil {
		fmt.Printf("No saved configuration found or error loading: %v\n", err)
		return
	}

	if len(args) == 0 {
		fmt.Println("No saved service arguments found")
		return
	}
	fmt.Printf("Saved service arguments: %v\n", args)
}

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

func setupWindowsLogFile() {
	logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "newt", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return
	}

	logFile := filepath.Join(logDir, "newt.log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return
	}

	os.Stdout = file
	os.Stderr = file
}

func handleServiceCommand() bool {
	if len(os.Args) < 2 {
		return false
	}

	switch os.Args[1] {
	case "install":
		err := installService()
		if err != nil {
			fmt.Printf("Failed to install service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service installed successfully")
		return true
	case "remove", "uninstall":
		err := removeService()
		if err != nil {
			fmt.Printf("Failed to remove service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service removed successfully")
		return true
	case "start":
		err := startService(os.Args[2:])
		if err != nil {
			fmt.Printf("Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service started successfully")
		return true
	case "stop":
		err := stopService()
		if err != nil {
			fmt.Printf("Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service stopped successfully")
		return true
	case "status":
		status, err := getServiceStatus()
		if err != nil {
			fmt.Printf("Failed to get service status: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service status: %s\n", status)
		return true
	case "debug":
		status, err := getServiceStatus()
		if err != nil {
			fmt.Printf("Failed to get service status: %v\n", err)
			os.Exit(1)
		}
		if status == "Not Installed" {
			if err := installService(); err != nil {
				fmt.Printf("Failed to install service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service installed successfully, now running in debug mode")
		}
		if err := debugService(os.Args[2:]); err != nil {
			fmt.Printf("Failed to debug service: %v\n", err)
			os.Exit(1)
		}
		return true
	case "logs":
		if err := watchLogFile(false); err != nil {
			fmt.Printf("Failed to watch log file: %v\n", err)
			os.Exit(1)
		}
		return true
	case "config":
		showServiceConfig()
		return true
	case "service-help":
		fmt.Println("Newt WireGuard Tunnel")
		fmt.Println("\nWindows Service Management:")
		fmt.Println("  install        Install the service")
		fmt.Println("  remove         Remove the service")
		fmt.Println("  start [args]   Start the service with optional arguments")
		fmt.Println("  stop           Stop the service")
		fmt.Println("  status         Show service status")
		fmt.Println("  debug [args]   Run service in debug mode with optional arguments")
		fmt.Println("  logs           Tail the service log file")
		fmt.Println("  config         Show current service configuration")
		fmt.Println("  service-help   Show this service help")
		fmt.Println("\nExamples:")
		fmt.Println("  newt start --endpoint https://example.com --id myid --secret mysecret")
		fmt.Println("  newt debug --endpoint https://example.com --id myid --secret mysecret")
		return true
	}

	return false
}
