//go:build linux

package clients

import (
	"fmt"
	"os/exec"
)

func configureNativeInterface(name, cidr string, mtu int) error {
	if name == "" {
		return fmt.Errorf("native interface name is required")
	}

	if out, err := exec.Command("ip", "addr", "replace", cidr, "dev", name).CombinedOutput(); err != nil {
		return fmt.Errorf("configure interface address: %w: %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("configure interface link: %w: %s", err, out)
	}
	return nil
}
