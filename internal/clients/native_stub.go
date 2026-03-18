//go:build !linux

package clients

import (
	"fmt"
	"runtime"
)

func configureNativeInterface(name, cidr string, mtu int) error {
	return unsupportedNativeModeError(runtime.GOOS)
}

func unsupportedNativeModeError(goos string) error {
	return fmt.Errorf("native client interface mode is not supported on %s", goos)
}
