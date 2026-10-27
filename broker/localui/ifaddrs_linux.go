//go:build linux && (amd64 || arm64)

package localui

import (
	"errors"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"
)

// ifreqSize is struct ifreq's size on 64-bit Linux: a 16-byte name and a
// 24-byte union whose IPv4 sockaddr starts the union.
const ifreqSize = 40

// ifconf is struct ifconf on 64-bit Linux.
type ifconf struct {
	len int32
	_   [4]byte
	buf *byte
}

// boxAddrs lists the box's IPv4 addresses with SIOCGIFCONF over an AF_INET
// socket: the page's unit allows only AF_UNIX and AF_INET, so the netlink
// socket net.InterfaceAddrs opens is refused there (Security blocker 1 on
// 713fd31). The page's sources are IPv4 only, so IPv4 is all it needs.
func boxAddrs() ([]netip.Addr, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	for n := 64; n <= 4096; n *= 4 {
		buf := make([]byte, n*ifreqSize)
		c := ifconf{len: int32(len(buf)), buf: &buf[0]}
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFCONF, uintptr(unsafe.Pointer(&c)))
		runtime.KeepAlive(buf)
		if e != 0 {
			return nil, e
		}
		if int(c.len) >= len(buf) {
			continue // may be cut short: ask again with more room
		}
		var out []netip.Addr
		for off := 0; off+ifreqSize <= int(c.len); off += ifreqSize {
			sa := buf[off+16 : off+ifreqSize]
			if uint16(sa[0])|uint16(sa[1])<<8 != syscall.AF_INET {
				continue
			}
			out = append(out, netip.AddrFrom4([4]byte{sa[4], sa[5], sa[6], sa[7]}))
		}
		return out, nil
	}
	return nil, errors.New("localui: too many interfaces to list")
}
