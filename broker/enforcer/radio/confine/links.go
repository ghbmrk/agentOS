package confine

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// setupLinks brings lo up and creates each named dummy link, up and
// multicast, in the calling thread's network namespace (a held stack's,
// by inNetns), over one route netlink socket. A dummy link carries no
// traffic off the box: it gives a stack an infrastructure interface with
// a link-local address whose multicast loops back to the namespace's
// other sockets.
func setupLinks(links []string) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	if err := request(fd, 1, newLink("lo", "", syscall.IFF_UP, syscall.NLM_F_ACK)); err != nil {
		return fmt.Errorf("lo up: %w", err)
	}
	for i, name := range links {
		msg := newLink(name, "dummy", syscall.IFF_UP|syscall.IFF_MULTICAST,
			syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL)
		if err := request(fd, uint32(i+2), msg); err != nil {
			return fmt.Errorf("link %s: %w", name, err)
		}
	}
	return nil
}

// newLink is an RTM_NEWLINK body for the link name, setting flags (and
// only those), of kind when it creates one.
func newLink(name, kind string, flags uint32, nlflags uint16) []byte {
	b := make([]byte, syscall.SizeofIfInfomsg)
	b[0] = syscall.AF_UNSPEC
	binary.NativeEndian.PutUint32(b[8:], flags)  // ifi_flags
	binary.NativeEndian.PutUint32(b[12:], flags) // ifi_change
	b = attr(b, syscall.IFLA_IFNAME, append([]byte(name), 0))
	if kind != "" {
		b = attr(b, syscall.IFLA_LINKINFO, attr(nil, 1 /* IFLA_INFO_KIND */, []byte(kind)))
	}
	h := make([]byte, syscall.SizeofNlMsghdr, syscall.SizeofNlMsghdr+len(b))
	binary.NativeEndian.PutUint32(h[0:], uint32(syscall.SizeofNlMsghdr+len(b)))
	binary.NativeEndian.PutUint16(h[4:], syscall.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(h[6:], syscall.NLM_F_REQUEST|nlflags)
	return append(h, b...)
}

// attr appends one route attribute, padded to four bytes.
func attr(b []byte, typ uint16, data []byte) []byte {
	n := syscall.SizeofRtAttr + len(data)
	b = binary.NativeEndian.AppendUint16(b, uint16(n))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, data...)
	for n%4 != 0 {
		b, n = append(b, 0), n+1
	}
	return b
}

// request sends msg with sequence seq and waits for its acknowledgement.
func request(fd int, seq uint32, msg []byte) error {
	binary.NativeEndian.PutUint32(msg[8:], seq)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq || m.Header.Type != syscall.NLMSG_ERROR || len(m.Data) < 4 {
				continue
			}
			if e := int32(binary.NativeEndian.Uint32(m.Data)); e != 0 {
				return syscall.Errno(-e)
			}
			return nil
		}
	}
}
