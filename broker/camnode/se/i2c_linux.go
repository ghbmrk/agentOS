//go:build linux

package se

import (
	"errors"
	"os"
	"syscall"
)

// DefaultAddress is the Trust M's default 7-bit I2C address.
const DefaultAddress = 0x30

// i2cSlave is the i2c-dev ioctl that sets a file's target address.
const i2cSlave = 0x0703

// I2C is a Bus on a Linux i2c-dev node, such as /dev/i2c-1.
type I2C struct{ f *os.File }

// OpenI2C opens dev and sets the element's address on it.
func OpenI2C(dev string, addr uint16) (*I2C, error) {
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	sc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}
	var errno syscall.Errno
	if err := sc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, i2cSlave, uintptr(addr))
	}); err != nil || errno != 0 {
		f.Close()
		return nil, errors.New("se: cannot set the element's I2C address")
	}
	return &I2C{f}, nil
}

// errShort is a transfer the bus cut short.
var errShort = errors.New("se: short I2C transfer")

// Write is one write transaction.
func (b *I2C) Write(p []byte) error {
	n, err := b.f.Write(p)
	if err == nil && n != len(p) {
		err = errShort
	}
	return err
}

// Read is one read transaction.
func (b *I2C) Read(p []byte) error {
	n, err := b.f.Read(p)
	if err == nil && n != len(p) {
		err = errShort
	}
	return err
}

// Close closes the device node.
func (b *I2C) Close() error { return b.f.Close() }
