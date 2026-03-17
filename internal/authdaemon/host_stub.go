//go:build !linux

package authdaemon

import "fmt"

var errLinuxOnly = fmt.Errorf("auth-daemon is only supported on Linux")

func writeCACertIfNotExists(path, contents string, force bool) error { return errLinuxOnly }
func writePrincipals(path, username, niceID string) error            { return errLinuxOnly }
func ensureUser(username string, meta ConnectionMetadata, generateRandomPassword bool) error {
	return errLinuxOnly
}
