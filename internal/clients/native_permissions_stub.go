//go:build !linux || android

package clients

import "runtime"

func checkNativeInterfacePermissions() error {
	return unsupportedNativeModeError(runtime.GOOS)
}
