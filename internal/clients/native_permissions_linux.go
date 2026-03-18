//go:build linux && !android

package clients

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunDevice = "/dev/net/tun"
	ifnamsiz  = 16
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	tunSetIff = 0x400454ca
)

type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte
}

func checkNativeInterfacePermissions() error {
	if os.Geteuid() == 0 {
		return nil
	}

	caps := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}

	var data [2]unix.CapUserData
	if err := unix.Capget(&caps, &data[0]); err == nil {
		const capNetAdmin = 12
		if data[0].Effective&(1<<capNetAdmin) != 0 {
			return nil
		}
	}

	return tryCreateTestTun()
}

func tryCreateTestTun() error {
	f, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w (need root or CAP_NET_ADMIN capability)", tunDevice, err)
	}
	defer func() { _ = f.Close() }()

	var req ifReq
	copy(req.Name[:], "tuntest0")
	req.Flags = iffTun | iffNoPi

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(tunSetIff),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return fmt.Errorf("cannot create TUN interface (need root or CAP_NET_ADMIN capability): %v", errno)
	}

	return nil
}
