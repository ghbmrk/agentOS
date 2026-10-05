package at

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// OpenSerial opens a USB serial interface in raw mode: no echo, no line
// editing, no CR/LF translation, 8 data bits, reads returning whatever has
// arrived. USB CDC ignores the baud rate; 115200 is set for adapters that
// do not.
func OpenSerial(path string) (io.ReadWriteCloser, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var t syscall.Termios
	if err := ioctl(f.Fd(), syscall.TCGETS, &t); err != nil {
		f.Close()
		return nil, err
	}
	// cfmakeraw
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR |
		syscall.ICRNL | syscall.IXON | syscall.IXOFF
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB | cbaud
	t.Cflag |= syscall.CS8 | syscall.CREAD | syscall.CLOCAL | syscall.B115200
	t.Ispeed, t.Ospeed = syscall.B115200, syscall.B115200
	t.Cc[syscall.VMIN], t.Cc[syscall.VTIME] = 1, 0
	if err := ioctl(f.Fd(), syscall.TCSETS, &t); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func ioctl(fd uintptr, req uintptr, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}

// cbaud is Linux's CBAUD mask, which package syscall does not export.
const cbaud = 0x100f
