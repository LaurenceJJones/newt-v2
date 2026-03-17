// Package version provides build version information.
package version

import (
	"fmt"
	"runtime"
)

// Build information. These are set at compile time via ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info returns a formatted version string.
func Info() string {
	return fmt.Sprintf("newt %s (%s) built %s with %s",
		Version, Commit, BuildDate, runtime.Version())
}

// Short returns a short version string.
func Short() string {
	return Version
}
