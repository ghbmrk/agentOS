package offload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"syscall"
)

// The kernel's ethtool netlink family (include/uapi/linux/ethtool_netlink.h
// and genetlink.h). Verbose bitsets only: every bit is read and written by
// its name, so no table of bit numbers is kept here.
const (
	netlinkGeneric = 16 // NETLINK_GENERIC
	genlIDCtrl     = 0x10
	ctrlGetFamily  = 3 // CTRL_CMD_GETFAMILY
	ctrlFamilyID   = 1 // CTRL_ATTR_FAMILY_ID
	ctrlFamilyName = 2 // CTRL_ATTR_FAMILY_NAME

	featuresGet = 11 // ETHTOOL_MSG_FEATURES_GET
	featuresSet = 12 // ETHTOOL_MSG_FEATURES_SET

	headerDevName = 2 // ETHTOOL_A_HEADER_DEV_NAME

	featHeader = 1 // ETHTOOL_A_FEATURES_HEADER
	featWanted = 3 // ETHTOOL_A_FEATURES_WANTED
	featActive = 4 // ETHTOOL_A_FEATURES_ACTIVE

	bitsetNomask = 1 // ETHTOOL_A_BITSET_NOMASK
	bitsetBits   = 3 // ETHTOOL_A_BITSET_BITS
	bitsetValue  = 4 // ETHTOOL_A_BITSET_VALUE (compact form only)
	bitsBit      = 1 // ETHTOOL_A_BITSET_BITS_BIT
	bitName      = 2 // ETHTOOL_A_BITSET_BIT_NAME
	bitValue     = 3 // ETHTOOL_A_BITSET_BIT_VALUE

	nlaNested   = 1 << 15
	nlaTypeMask = 0x3fff
	nlmsgHdrLen = 16
	genlHdrLen  = 4
)

var ne = binary.NativeEndian

// conn is one generic netlink socket, opened in the calling thread's
// network namespace, with the ethtool family resolved.
type conn struct {
	fd     int
	seq    uint32
	family uint16
}

func dial() (*conn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkGeneric)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	c := &conn{fd: fd}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		c.close()
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	// A kernel that never answers fails the call rather than hang it.
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5}); err != nil {
		c.close()
		return nil, fmt.Errorf("netlink timeout: %w", err)
	}
	replies, err := c.do(genlIDCtrl, ctrlGetFamily, attr(ctrlFamilyName, cstr("ethtool")))
	if err != nil {
		c.close()
		return nil, fmt.Errorf("ethtool netlink family: %w", err)
	}
	for _, r := range replies {
		if b := find(r, ctrlFamilyID); len(b) == 2 {
			c.family = ne.Uint16(b)
		}
	}
	if c.family == 0 {
		c.close()
		return nil, errors.New("ethtool netlink family: no id in the reply")
	}
	return c, nil
}

func (c *conn) close() { syscall.Close(c.fd) }

// active reads dev's active features.
func (c *conn) active(dev string) (map[string]bool, error) {
	replies, err := c.do(c.family, featuresGet, header(dev))
	if err != nil {
		return nil, fmt.Errorf("features: %w", err)
	}
	if len(replies) != 1 {
		return nil, fmt.Errorf("features: %d replies", len(replies))
	}
	b := find(replies[0], featActive)
	if b == nil {
		return nil, errors.New("features: no active set in the reply")
	}
	return bitset(b)
}

// set asks for each named feature of dev on or off; the others are not
// in the request's mask and stay as they are.
func (c *conn) set(dev string, want map[string]bool) error {
	names := make([]string, 0, len(want))
	for f := range want {
		names = append(names, f)
	}
	slices.Sort(names)
	var bits []byte
	for _, f := range names {
		bit := attr(bitName, cstr(f))
		if want[f] {
			bit = append(bit, attr(bitValue, nil)...)
		}
		bits = append(bits, attr(bitsBit|nlaNested, bit)...)
	}
	req := append(header(dev), attr(featWanted|nlaNested, attr(bitsetBits|nlaNested, bits))...)
	if _, err := c.do(c.family, featuresSet, req); err != nil {
		return fmt.Errorf("features set: %w", err)
	}
	return nil
}

func header(dev string) []byte {
	return attr(featHeader|nlaNested, attr(headerDevName, cstr(dev)))
}

// do sends one request and returns the attributes of each reply up to
// the kernel's acknowledgement.
func (c *conn) do(family uint16, cmd uint8, attrs []byte) ([][]byte, error) {
	c.seq++
	msg := make([]byte, nlmsgHdrLen+genlHdrLen, nlmsgHdrLen+genlHdrLen+len(attrs))
	ne.PutUint32(msg[0:], uint32(nlmsgHdrLen+genlHdrLen+len(attrs)))
	ne.PutUint16(msg[4:], family)
	ne.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	ne.PutUint32(msg[8:], c.seq)
	msg[16] = cmd
	msg[17] = 1 // version
	msg = append(msg, attrs...)
	if err := syscall.Sendto(c.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	var replies [][]byte
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return nil, err
		}
		if n < nlmsgHdrLen {
			return nil, errors.New("short netlink message")
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != c.seq {
				continue
			}
			switch m.Header.Type {
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("short netlink error")
				}
				if e := int32(ne.Uint32(m.Data)); e != 0 {
					return nil, syscall.Errno(-e)
				}
				return replies, nil
			case syscall.NLMSG_DONE:
				return replies, nil
			case family:
				if len(m.Data) < genlHdrLen {
					return nil, errors.New("short generic netlink reply")
				}
				replies = append(replies, append([]byte(nil), m.Data[genlHdrLen:]...)) // buf is read into again
			}
		}
	}
}

// bitset reads a verbose bitset: the names of the bits that are set. A
// list (NOMASK) holds only the set bits; a value and mask pair marks each
// set bit with its value flag. A compact bitset is refused, since this
// package asked for none and could misread it as empty.
func bitset(b []byte) (map[string]bool, error) {
	if find(b, bitsetValue) != nil {
		return nil, errors.New("features: compact bitset in the reply")
	}
	list := find(b, bitsetNomask) != nil
	on := map[string]bool{}
	for _, bit := range all(find(b, bitsetBits), bitsBit) {
		name := find(bit, bitName)
		if len(name) == 0 || name[len(name)-1] != 0 {
			return nil, errors.New("features: a bit with no name")
		}
		if list || find(bit, bitValue) != nil {
			on[string(name[:len(name)-1])] = true
		}
	}
	return on, nil
}

// attr is one netlink attribute, padded to four bytes.
func attr(typ uint16, data []byte) []byte {
	n := 4 + len(data)
	b := make([]byte, (n+3)&^3)
	ne.PutUint16(b[0:], uint16(n))
	ne.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func cstr(s string) []byte { return append([]byte(s), 0) }

// each calls f with every well-formed attribute in b, in order; it stops
// at the first malformed one.
func each(b []byte, f func(typ uint16, data []byte)) {
	for len(b) >= 4 {
		n := int(ne.Uint16(b[0:]))
		if n < 4 || n > len(b) {
			return
		}
		f(ne.Uint16(b[2:])&nlaTypeMask, b[4:n])
		b = b[min((n+3)&^3, len(b)):]
	}
}

// find is the data of b's first attribute of typ (empty but not nil for a
// flag), or nil.
func find(b []byte, typ uint16) []byte {
	var got []byte
	each(b, func(t uint16, d []byte) {
		if got == nil && t == typ&nlaTypeMask {
			got = append([]byte{}, d...)
		}
	})
	return got
}

// all is the data of each of b's attributes of typ.
func all(b []byte, typ uint16) [][]byte {
	var got [][]byte
	each(b, func(t uint16, d []byte) {
		if t == typ&nlaTypeMask {
			got = append(got, d)
		}
	})
	return got
}
