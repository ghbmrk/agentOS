package offload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// The kernel's ethtool netlink family, by golang.org/x/sys/unix's names
// for include/uapi/linux/ethtool_netlink.h and genetlink.h. Verbose
// bitsets only: every bit is read and written by its name, so no table of
// bit numbers is kept here.
const nlaTypeMask = ^uint16(unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)

var ne = binary.NativeEndian

// conn is one netlink socket, opened in the calling thread's network
// namespace: a generic one with the ethtool family resolved (dial), or a
// route one (open) for the links.
type conn struct {
	fd     int
	seq    uint32
	family uint16
}

// open is a netlink socket of protocol proto, bound to a port of its own.
func open(proto int) (*conn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
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
	return c, nil
}

func dial() (*conn, error) {
	c, err := open(unix.NETLINK_GENERIC)
	if err != nil {
		return nil, err
	}
	replies, err := c.do(unix.GENL_ID_CTRL, unix.CTRL_CMD_GETFAMILY, attr(unix.CTRL_ATTR_FAMILY_NAME, cstr(unix.ETHTOOL_GENL_NAME)))
	if err != nil {
		c.close()
		return nil, fmt.Errorf("ethtool netlink family: %w", err)
	}
	for _, r := range replies {
		if b := find(r, unix.CTRL_ATTR_FAMILY_ID); len(b) == 2 {
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
	replies, err := c.do(c.family, unix.ETHTOOL_MSG_FEATURES_GET, header(dev))
	if err != nil {
		return nil, fmt.Errorf("features: %w", err)
	}
	if len(replies) != 1 {
		return nil, fmt.Errorf("features: %d replies", len(replies))
	}
	b := find(replies[0], unix.ETHTOOL_A_FEATURES_ACTIVE)
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
		bit := attr(unix.ETHTOOL_A_BITSET_BIT_NAME, cstr(f))
		if want[f] {
			bit = append(bit, attr(unix.ETHTOOL_A_BITSET_BIT_VALUE, nil)...)
		}
		bits = append(bits, attr(unix.ETHTOOL_A_BITSET_BITS_BIT|unix.NLA_F_NESTED, bit)...)
	}
	req := append(header(dev), attr(unix.ETHTOOL_A_FEATURES_WANTED|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, bits))...)
	if _, err := c.do(c.family, unix.ETHTOOL_MSG_FEATURES_SET, req); err != nil {
		return fmt.Errorf("features set: %w", err)
	}
	return nil
}

func header(dev string) []byte {
	return attr(unix.ETHTOOL_A_FEATURES_HEADER|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_HEADER_DEV_NAME, cstr(dev)))
}

// do sends one generic netlink request and returns the attributes of
// each reply up to the kernel's acknowledgement.
func (c *conn) do(family uint16, cmd uint8, attrs []byte) ([][]byte, error) {
	body := append([]byte{cmd, 1 /* version */, 0, 0}, attrs...)
	replies, err := c.request(family, syscall.NLM_F_ACK, body)
	if err != nil {
		return nil, err
	}
	for i, r := range replies {
		if len(r) < unix.GENL_HDRLEN {
			return nil, errors.New("short generic netlink reply")
		}
		replies[i] = r[unix.GENL_HDRLEN:]
	}
	return replies, nil
}

// request sends one message of type typ with body and returns the body of
// each reply of that type (RTM_NEWLINK answers RTM_GETLINK) up to the
// kernel's acknowledgement or a dump's end.
func (c *conn) request(typ, flags uint16, body []byte) ([][]byte, error) {
	c.seq++
	msg := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	ne.PutUint32(msg[0:], uint32(unix.NLMSG_HDRLEN+len(body)))
	ne.PutUint16(msg[4:], typ)
	ne.PutUint16(msg[6:], syscall.NLM_F_REQUEST|flags)
	ne.PutUint32(msg[8:], c.seq)
	msg = append(msg, body...)
	if err := syscall.Sendto(c.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	want := typ
	if typ == syscall.RTM_GETLINK {
		want = syscall.RTM_NEWLINK
	}
	return c.recv(want)
}

// recv reads the replies of type want to request c.seq up to the
// acknowledgement or a dump's end. Only the kernel's datagrams are read:
// one from any other sender (a process that found this socket's port) is
// dropped unread, so it can neither answer for the kernel nor end the
// request.
func (c *conn) recv(want uint16) ([][]byte, error) {
	var replies [][]byte
	buf := make([]byte, 1<<16)
	for {
		n, from, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return nil, err
		}
		if !fromKernel(from) {
			continue
		}
		if n < unix.NLMSG_HDRLEN {
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
			case want:
				replies = append(replies, append([]byte(nil), m.Data...)) // buf is read into again
			}
		}
	}
}

// fromKernel is whether a datagram's sender is the kernel (port 0).
func fromKernel(from syscall.Sockaddr) bool {
	sa, ok := from.(*syscall.SockaddrNetlink)
	return ok && sa.Pid == 0
}

// bitset reads a verbose bitset: the names of the bits that are set. A
// list (NOMASK) holds only the set bits; a value and mask pair marks each
// set bit with its value flag. A compact bitset is refused, since this
// package asked for none and could misread it as empty, and so is one
// with bytes that do not parse as attributes, whose bits past them would
// read as off.
func bitset(b []byte) (map[string]bool, error) {
	if !whole(b) {
		return nil, errors.New("features: a malformed bitset in the reply")
	}
	if find(b, unix.ETHTOOL_A_BITSET_VALUE) != nil {
		return nil, errors.New("features: compact bitset in the reply")
	}
	list := find(b, unix.ETHTOOL_A_BITSET_NOMASK) != nil
	bits := find(b, unix.ETHTOOL_A_BITSET_BITS)
	if !whole(bits) {
		return nil, errors.New("features: a malformed bitset in the reply")
	}
	on := map[string]bool{}
	for _, bit := range all(bits, unix.ETHTOOL_A_BITSET_BITS_BIT) {
		if !whole(bit) {
			return nil, errors.New("features: a malformed bit in the reply")
		}
		name := find(bit, unix.ETHTOOL_A_BITSET_BIT_NAME)
		if len(name) == 0 || name[len(name)-1] != 0 {
			return nil, errors.New("features: a bit with no name")
		}
		if list || find(bit, unix.ETHTOOL_A_BITSET_BIT_VALUE) != nil {
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
// at the first malformed one and reports whether b was read to its end.
func each(b []byte, f func(typ uint16, data []byte)) bool {
	for len(b) >= 4 {
		n := int(ne.Uint16(b[0:]))
		if n < 4 || n > len(b) {
			return false
		}
		f(ne.Uint16(b[2:])&nlaTypeMask, b[4:n])
		b = b[min((n+3)&^3, len(b)):]
	}
	return len(b) == 0
}

// whole is whether b is attributes to its last byte.
func whole(b []byte) bool { return each(b, func(uint16, []byte) {}) }

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
