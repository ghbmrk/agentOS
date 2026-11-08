package mdns

// REQ: NET-3

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"
)

// forge sends msgs to r's port from another netlink socket, as a local
// process that found the port would, each with sequence seq.
func forge(t *testing.T, r *route, seq uint32, msgs ...[]byte) {
	t.Helper()
	sa, err := syscall.Getsockname(r.fd)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*syscall.SockaddrNetlink).Pid
	f, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(f)
	if err := syscall.Bind(f, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	var b []byte
	for _, m := range msgs {
		ne.PutUint32(m[0:], uint32(len(m)))
		ne.PutUint32(m[8:], seq)
		ne.PutUint32(m[12:], port)
		b = append(b, m...)
	}
	if err := syscall.Sendto(f, b, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: port}); err != nil {
		t.Fatal(err)
	}
}

// nlmsg is a netlink message of type typ with body, its length and
// sequence filled by forge.
func nlmsg(typ uint16, body []byte) []byte {
	m := make([]byte, syscall.NLMSG_HDRLEN, syscall.NLMSG_HDRLEN+len(body))
	ne.PutUint16(m[4:], typ)
	return append(m, body...)
}

func ack() []byte     { return nlmsg(syscall.NLMSG_ERROR, make([]byte, 4+syscall.NLMSG_HDRLEN)) }
func dumpEnd() []byte { return nlmsg(syscall.NLMSG_DONE, make([]byte, 4)) }

// TestForgedDumpRefused (ENF-mdns-netlink-kernel, #5102): a datagram
// that does not come from the kernel is dropped unread on both requests
// the relay makes, so a local process that finds the socket's port can
// neither name a link's index nor choose the prefixes the relay treats as
// a sender's own link (ENF-f-m3), nor end a request early. Each forgery
// is queued before the request, ahead of the kernel's reply.
func TestForgedDumpRefused(t *testing.T) {
	r, err := openRoute()
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer r.close()
	lo, err := net.InterfaceByName("lo") // the test's reference only
	if err != nil {
		t.Skipf("no loopback here: %v", err)
	}

	// A forged link reply and acknowledgement for a name the kernel
	// does not have: the kernel's refusal stands.
	fake := make([]byte, syscall.SizeofIfInfomsg)
	ne.PutUint32(fake[4:], 999)
	fake = append(fake, rtattr(syscall.IFLA_IFNAME, []byte("agentos-none\x00"))...)
	forge(t, r, r.seq+1, nlmsg(syscall.RTM_NEWLINK, fake), ack())
	if i, err := r.index("agentos-none"); !errors.Is(err, syscall.ENODEV) {
		t.Fatalf("a forged link reply read as the kernel's: %d %v", i, err)
	}

	// A forged index for a link the kernel has.
	fake = make([]byte, syscall.SizeofIfInfomsg)
	ne.PutUint32(fake[4:], 999)
	fake = append(fake, rtattr(syscall.IFLA_IFNAME, []byte("lo\x00"))...)
	forge(t, r, r.seq+1, nlmsg(syscall.RTM_NEWLINK, fake), ack())
	i, err := r.index("lo")
	if err != nil || i != lo.Index {
		t.Fatalf("lo's index: %d %v, want the kernel's %d", i, err, lo.Index)
	}

	// A forged address dump for that link, ended before the kernel's.
	addr := make([]byte, syscall.SizeofIfAddrmsg)
	addr[0], addr[1] = syscall.AF_INET, 24
	ne.PutUint32(addr[4:], uint32(i))
	addr = append(addr, rtattr(syscall.IFA_LOCAL, []byte{198, 51, 100, 7})...)
	addr = append(addr, rtattr(syscall.IFA_ADDRESS, []byte{198, 51, 100, 7})...)
	forge(t, r, r.seq+1, nlmsg(syscall.RTM_NEWADDR, addr), dumpEnd())
	got, err := r.prefixes(i)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, netip.MustParsePrefix("127.0.0.1/8")) {
		t.Fatalf("the kernel's addresses on lo were not read: %v", got)
	}
	if slices.Contains(got, netip.MustParsePrefix("198.51.100.7/24")) {
		t.Fatalf("a forged address read as the kernel's: %v", got)
	}

	// And the relay's own entry points read the same from the kernel.
	if p := prefixes("lo"); !slices.Equal(p, got) {
		t.Fatalf("prefixes(lo) = %v, want %v", p, got)
	}
	if p := prefixes("agentos-none"); p != nil {
		t.Fatalf("an unknown link has prefixes: %v", p)
	}
	if j, err := ifindex("lo"); err != nil || j != lo.Index {
		t.Fatalf("ifindex(lo): %d %v", j, err)
	}
}

// TestFloodEndsRequest (ENF-mdns-netlink-kernel, #5102): datagrams from
// another sender that keep arriving do not hold a request past
// replyWait: it fails, and the relay then treats nothing as a sender's
// own link (prefixes is empty), rather than stall on the flood.
func TestFloodEndsRequest(t *testing.T) {
	defer func(w time.Duration) { replyWait = w }(replyWait)
	replyWait = 300 * time.Millisecond
	r, err := openRoute()
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer r.close()
	sa, err := syscall.Getsockname(r.fd)
	if err != nil {
		t.Fatal(err)
	}
	to := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: sa.(*syscall.SockaddrNetlink).Pid}
	f, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(f)
	if err := syscall.Bind(f, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	noop := nlmsg(syscall.NLMSG_NOOP, nil)
	ne.PutUint32(noop[0:], uint32(len(noop)))
	stop := make(chan struct{})
	flooding := make(chan struct{})
	go func() {
		defer close(flooding)
		for {
			select {
			case <-stop:
				return
			default:
			}
			syscall.Sendto(f, noop, 0, to) // a full queue refuses some: the rest keep coming
			time.Sleep(time.Millisecond)
		}
	}()
	defer func() { close(stop); <-flooding }()
	done := make(chan error, 1)
	start := time.Now()
	go func() { _, err := r.recv(syscall.RTM_NEWADDR); done <- err }() // a reply the kernel never sends
	select {
	case err := <-done:
		if !errors.Is(err, errNoReply) {
			t.Fatalf("a flooded request: %v", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("a flooded request took %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a flood of other datagrams held the request past replyWait")
	}
}
