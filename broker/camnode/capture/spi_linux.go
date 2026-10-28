//go:build linux

package capture

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// spidev ioctls (linux/spi/spidev.h): _IOW('k', 1, __u8) and
// _IOW('k', 4, __u32).
const (
	spiIocWrMode       = 0x40016b01
	spiIocWrMaxSpeedHz = 0x40046b04
	spiMode3           = 3 // the Lepton's VoSPI is SPI mode 3
)

// OpenSPI opens a spidev node, such as /dev/spidev0.0, for VoSPI: mode 3
// at hz. Each Read is one half-duplex transfer.
func OpenSPI(dev string, hz uint32) (*os.File, error) {
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	sc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}
	mode := uint8(spiMode3)
	var errno syscall.Errno
	if err := sc.Control(func(fd uintptr) {
		if _, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, spiIocWrMode, uintptr(unsafe.Pointer(&mode))); errno != 0 {
			return
		}
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, spiIocWrMaxSpeedHz, uintptr(unsafe.Pointer(&hz)))
	}); err != nil || errno != 0 {
		f.Close()
		return nil, errors.New("capture: cannot set the thermal core's SPI mode")
	}
	return f, nil
}
