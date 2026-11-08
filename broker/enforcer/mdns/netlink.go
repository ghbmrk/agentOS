package mdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"
)

// The relay reads its interfaces' indexes and addresses from the kernel
// over a route netlink socket of its own, never through net.Interface:
// the standard library's syscall.NetlinkRIB takes the first datagram
// whose sequence and port match, from whatever sender, so a local
// process that found its port could answer for the kernel and choose the
// prefixes the relay treats as a sender's own link (#5102, the class
// #5095 closed in enforcer/offload and radio/confine).

var ne = binary.NativeEndian

// route is one route netlink socket, opened in the calling thread's
// network namespace and bound to a port of its own.
type route struct {
	fd  int
	seq uint32
}

func openRoute() (*route, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return &route{fd: fd}, nil
}

func (r *route) close() { syscall.Close(r.fd) }

// index is the kernel's index of the link called name.
func (r *route) index(name string) (int, error) {
	body := make([]byte, syscall.SizeofIfInfomsg)
	body = append(body, rtattr(syscall.IFLA_IFNAME, append([]byte(name), 0))...)
	msgs, err := r.request(syscall.RTM_GETLINK, syscall.NLM_F_ACK, body, syscall.RTM_NEWLINK)
	if err != nil {
		return 0, fmt.Errorf("link %s: %w", name, err)
	}
	for _, m := range msgs {
		if len(m.Data) < syscall.SizeofIfInfomsg {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return 0, fmt.Errorf("link %s: %w", name, err)
		}
		for _, a := range attrs {
			if a.Attr.Type == syscall.IFLA_IFNAME && string(trimNul(a.Value)) == name {
				if i := int(int32(ne.Uint32(m.Data[4:8]))); i > 0 {
					return i, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("link %s: not in the kernel's reply", name)
}

// prefixes is each of the link index's addresses with its prefix length.
// An address is its local one (IFA_LOCAL) where the kernel gives one,
// else IFA_ADDRESS, which is the same address on a link that is not
// point-to-point.
func (r *route) prefixes(index int) ([]netip.Prefix, error) {
	msgs, err := r.request(syscall.RTM_GETADDR, syscall.NLM_F_DUMP, make([]byte, syscall.SizeofIfAddrmsg), syscall.RTM_NEWADDR)
	if err != nil {
		return nil, fmt.Errorf("addresses: %w", err)
	}
	var out []netip.Prefix
	for _, m := range msgs {
		if len(m.Data) < syscall.SizeofIfAddrmsg || int(ne.Uint32(m.Data[4:8])) != index {
			continue
		}
		bits := int(m.Data[1])
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, fmt.Errorf("addresses: %w", err)
		}
		var local, addr []byte
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.IFA_LOCAL:
				local = a.Value
			case syscall.IFA_ADDRESS:
				addr = a.Value
			}
		}
		if local == nil {
			local = addr
		}
		ip, ok := netip.AddrFromSlice(local)
		if !ok {
			continue
		}
		if p := netip.PrefixFrom(ip.Unmap(), bits); p.IsValid() {
			out = append(out, p)
		}
	}
	return out, nil
}

// request sends one message of type typ with body and returns each reply
// of type want up to the kernel's acknowledgement or a dump's end.
func (r *route) request(typ, flags uint16, body []byte, want uint16) ([]syscall.NetlinkMessage, error) {
	r.seq++
	msg := make([]byte, syscall.NLMSG_HDRLEN, syscall.NLMSG_HDRLEN+len(body))
	ne.PutUint32(msg[0:], uint32(syscall.NLMSG_HDRLEN+len(body)))
	ne.PutUint16(msg[4:], typ)
	ne.PutUint16(msg[6:], syscall.NLM_F_REQUEST|flags)
	ne.PutUint32(msg[8:], r.seq)
	msg = append(msg, body...)
	if err := syscall.Sendto(r.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	return r.recv(want)
}

// replyWait is how long one request may wait for all of the kernel's
// replies, however many other datagrams arrive meanwhile.
var replyWait = 5 * time.Second

var errNoReply = errors.New("no reply from the kernel in time")

// recv reads the replies of type want to request r.seq up to the
// acknowledgement or a dump's end. Only the kernel's datagrams are read:
// one from any other sender is dropped unread, so it can neither answer
// for the kernel nor end the request. The request fails once replyWait
// has passed, so neither a silent kernel nor a flood of other datagrams
// holds it.
func (r *route) recv(want uint16) ([]syscall.NetlinkMessage, error) {
	var replies []syscall.NetlinkMessage
	buf := make([]byte, 1<<16)
	end := time.Now().Add(replyWait)
	for {
		left := time.Until(end)
		if left <= 0 {
			return nil, errNoReply
		}
		tv := syscall.NsecToTimeval(max(left.Nanoseconds(), int64(time.Microsecond)))
		if err := syscall.SetsockoptTimeval(r.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, fmt.Errorf("netlink timeout: %w", err)
		}
		n, from, err := syscall.Recvfrom(r.fd, buf, 0)
		switch {
		case errors.Is(err, syscall.EINTR): // a signal to this thread (Go's preemption): read on
			continue
		case errors.Is(err, syscall.EAGAIN):
			return nil, errNoReply
		case err != nil:
			return nil, err
		}
		if sa, ok := from.(*syscall.SockaddrNetlink); !ok || sa.Pid != 0 {
			continue
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != r.seq {
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
				m.Data = append([]byte(nil), m.Data...) // buf is read into again
				replies = append(replies, m)
			}
		}
	}
}

// rtattr is one route attribute, padded to four bytes.
func rtattr(typ uint16, data []byte) []byte {
	n := syscall.SizeofRtAttr + len(data)
	b := make([]byte, (n+3)&^3)
	ne.PutUint16(b[0:], uint16(n))
	ne.PutUint16(b[2:], typ)
	copy(b[syscall.SizeofRtAttr:], data)
	return b
}

func trimNul(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == 0 {
		return b[:len(b)-1]
	}
	return b
}

// ifindex is the kernel's index of the link called name.
func ifindex(name string) (int, error) {
	r, err := openRoute()
	if err != nil {
		return 0, err
	}
	defer r.close()
	return r.index(name)
}

// prefixes is the enforcer's addresses on iface, each with its prefix;
// none if the kernel's answer cannot be read in time, so nothing is the
// sender's own.
func prefixes(iface string) []netip.Prefix {
	r, err := openRoute()
	if err != nil {
		return nil
	}
	defer r.close()
	i, err := r.index(iface)
	if err != nil {
		return nil
	}
	out, err := r.prefixes(i)
	if err != nil {
		return nil
	}
	return out
}
