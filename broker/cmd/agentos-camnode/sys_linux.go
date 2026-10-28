//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// readBootloader reads the Raspberry Pi bootloader's device-tree node: the
// partition it booted and whether this boot is the one-shot tryboot, each
// a 32-bit big-endian cell (camnode ASSUMPTIONS CAM-bin-2).
func readBootloader(dir string) (part int, trial bool, err error) {
	cell := func(name string) (uint32, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(b) != 4 {
			return 0, errors.New("bootloader node unreadable: " + name)
		}
		return binary.BigEndian.Uint32(b), nil
	}
	p, err := cell("partition")
	if err != nil {
		return 0, false, err
	}
	t, err := cell("tryboot")
	if err != nil {
		return 0, false, err
	}
	return int(p), t == 1, nil
}

// reboot restarts the board with the firmware's tryboot flag, the
// equivalent of `reboot "0 tryboot"`.
func reboot() error {
	syscall.Sync()
	arg, err := syscall.BytePtrFromString("0 tryboot")
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_REBOOT, syscall.LINUX_REBOOT_MAGIC1, syscall.LINUX_REBOOT_MAGIC2,
		syscall.LINUX_REBOOT_CMD_RESTART2, uintptr(unsafe.Pointer(arg)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// restart restarts the board with no tryboot flag: the bootloader boots
// the default slot.
func restart() error {
	syscall.Sync()
	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
}

// keyBytes is EVIOCGKEY's bitmap size: KEY_MAX (0x2ff) + 1 bits.
const keyBytes = 0x300 / 8

// buttonHeld reports whether key is down on the input event device dev
// (a gpio-keys button) now, at the service's start: EVIOCGKEY, the ioctl
// _IOC(_IOC_READ, 'E', 0x18, len).
func buttonHeld(dev string, key uint16) (bool, error) {
	if int(key) >= keyBytes*8 {
		return false, errors.New("button key code out of range")
	}
	f, err := os.Open(dev)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var bits [keyBytes]byte
	req := uintptr(2<<30 | keyBytes<<16 | 'E'<<8 | 0x18)
	sc, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var errno syscall.Errno
	if err := sc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(&bits[0])))
	}); err != nil || errno != 0 {
		return false, errors.New("button state unreadable")
	}
	return bits[key/8]&(1<<(key%8)) != 0, nil
}
