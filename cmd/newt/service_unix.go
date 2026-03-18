//go:build !windows

package main

import "fmt"

const serviceName = "NewtWireguardService"

//nolint:unused // kept for Windows service parity surface
func installService() error {
	return fmt.Errorf("service management is only available on Windows")
}

//nolint:unused // kept for Windows service parity surface
func removeService() error {
	return fmt.Errorf("service management is only available on Windows")
}

//nolint:unused // kept for Windows service parity surface
func startService(args []string) error {
	_ = args
	return fmt.Errorf("service management is only available on Windows")
}

//nolint:unused // kept for Windows service parity surface
func stopService() error {
	return fmt.Errorf("service management is only available on Windows")
}

//nolint:unused // kept for Windows service parity surface
func getServiceStatus() (string, error) {
	return "", fmt.Errorf("service management is only available on Windows")
}

//nolint:unused // kept for Windows service parity surface
func debugService(args []string) error {
	_ = args
	return fmt.Errorf("debug service is only available on Windows")
}

func isWindowsService() bool {
	return false
}

func runService(name string, isDebug bool, args []string) {
	_, _, _ = name, isDebug, args
}

//nolint:unused // kept for Windows service parity surface
func watchLogFile(end bool) error {
	_ = end
	return fmt.Errorf("watching log file is only available on Windows")
}

//nolint:unused // kept for Windows service parity surface
func showServiceConfig() {
	fmt.Println("Service configuration is only available on Windows")
}

func handleServiceCommand() bool {
	return false
}
