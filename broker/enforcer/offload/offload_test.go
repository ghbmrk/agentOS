package offload

// REQ: NET-2

import (
	"errors"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func bit(name string, on bool) []byte {
	b := attr(unix.ETHTOOL_A_BITSET_BIT_NAME, cstr(name))
	if on {
		b = append(b, attr(unix.ETHTOOL_A_BITSET_BIT_VALUE, nil)...)
	}
	return attr(unix.ETHTOOL_A_BITSET_BITS_BIT|unix.NLA_F_NESTED, b)
}

// TestBitsetForms (ENF-cap-gro): both verbose forms read by name: a list
// holds only the set bits, a value and mask pair marks each set bit. A
// compact bitset, which this package never asks for, and a bit with no
// name are refused rather than read as nothing set, which would pass a
// merging port.
func TestBitsetForms(t *testing.T) {
	list := append(attr(unix.ETHTOOL_A_BITSET_NOMASK, nil), attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, append(bit("rx-gro", false), bit("rx-lro", false)...))...)
	got, err := bitset(list)
	if err != nil || len(got) != 2 || !got["rx-gro"] || !got["rx-lro"] {
		t.Fatalf("list: %v %v", got, err)
	}
	masked := attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, append(bit("rx-gro", true), bit("rx-lro", false)...))
	got, err = bitset(masked)
	if err != nil || len(got) != 1 || !got["rx-gro"] {
		t.Fatalf("value and mask: %v %v", got, err)
	}
	if got, err := bitset(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
	compact := append(attr(2, []byte{32, 0, 0, 0}), attr(unix.ETHTOOL_A_BITSET_VALUE, []byte{1, 0, 0, 0})...)
	if _, err := bitset(compact); err == nil {
		t.Fatal("a compact bitset was read")
	}
	unnamed := attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_BITSET_BITS_BIT|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_BITSET_BIT_VALUE, nil)))
	if _, err := bitset(append(attr(unix.ETHTOOL_A_BITSET_NOMASK, nil), unnamed...)); err == nil {
		t.Fatal("a bit with no name was read")
	}
	// A BITS nest cut short after its first bit: the bits past the cut
	// would read as off.
	cut := attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, append(bit("rx-lro", true), 40, 0, 1, 0)) // a bit claiming 40 bytes, 4 left
	if got, err := bitset(cut); err == nil {
		t.Fatalf("a cut bitset was read: %v", got)
	}
	if got, err := bitset(append(attr(unix.ETHTOOL_A_BITSET_NOMASK, nil), 1, 2)); err == nil {
		t.Fatalf("a bitset with bytes past its last attribute was read: %v", got)
	}
	// A bit whose own attributes run short of its end (2 stray bytes after
	// its name): read anyway, a value flag past them would read as off
	// (#5103 item 4).
	malformed := attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_BITSET_BITS_BIT|unix.NLA_F_NESTED, append(attr(unix.ETHTOOL_A_BITSET_BIT_NAME, cstr("rx-gro")), 1, 2)))
	if !whole(malformed) {
		t.Fatal("fixture: the BITS nest itself is not whole")
	}
	if got, err := bitset(append(attr(unix.ETHTOOL_A_BITSET_NOMASK, nil), malformed...)); err == nil {
		t.Fatalf("a malformed bit was read: %v", got)
	}
	unterminated := attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_BITSET_BITS_BIT|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_BITSET_BIT_NAME, []byte("rx-gro"))))
	if _, err := bitset(append(attr(unix.ETHTOOL_A_BITSET_NOMASK, nil), unterminated...)); err == nil {
		t.Fatal("a name with no terminator was read")
	}
}

// TestAttributes: attributes are padded to four bytes, nested types are
// read without their flag, and a malformed length ends the walk.
func TestAttributes(t *testing.T) {
	a := attr(unix.ETHTOOL_A_BITSET_BIT_NAME, cstr("rx"))
	if len(a) != 8 || ne.Uint16(a) != 7 {
		t.Fatalf("attr % x", a)
	}
	b := append(attr(unix.ETHTOOL_A_FEATURES_ACTIVE|unix.NLA_F_NESTED, a), attr(unix.ETHTOOL_A_FEATURES_WANTED, []byte{9})...)
	if got := find(b, unix.ETHTOOL_A_FEATURES_ACTIVE); string(got) != string(a) {
		t.Fatalf("nested: % x", got)
	}
	if got := find(b, unix.ETHTOOL_A_FEATURES_WANTED); len(got) != 1 || got[0] != 9 {
		t.Fatalf("after a nest: % x", got)
	}
	if got := find(attr(unix.ETHTOOL_A_FEATURES_HEADER, nil), unix.ETHTOOL_A_FEATURES_HEADER); got == nil || len(got) != 0 {
		t.Fatalf("a flag reads as present and empty: %v", got)
	}
	bad := append([]byte{200, 0, 4, 0}, attr(unix.ETHTOOL_A_FEATURES_WANTED, []byte{9})...)
	if find(bad, unix.ETHTOOL_A_FEATURES_WANTED) != nil {
		t.Fatal("read past a malformed length")
	}
}

// forge sends msgs, each with sequence seq, to c's port from another
// netlink socket of protocol proto: a local process, not the kernel.
func forge(t *testing.T, c *conn, proto int, seq uint32, msgs ...[]byte) {
	t.Helper()
	sa, err := syscall.Getsockname(c.fd)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*syscall.SockaddrNetlink).Pid
	f, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
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
	m := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	ne.PutUint16(m[4:], typ)
	return append(m, body...)
}

// TestForgedReplyRefused (ENF-gro-4): a datagram that does not come from
// the kernel is dropped unread, on both requests offload makes, so a
// local process that finds a socket's port can neither answer for the
// kernel nor end the request. A forged acknowledgement queued before a
// request the kernel refuses would read as success; a forged link dump
// queued before the kernel's would replace the kernel's links.
func TestForgedReplyRefused(t *testing.T) {
	if !inNetns(t) { // sending to another socket's port needs CAP_NET_ADMIN, as the forger would
		return
	}
	c, err := open(unix.NETLINK_GENERIC, time.Now().Add(replyWait))
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer c.close()
	forge(t, c, unix.NETLINK_GENERIC, c.seq+1, nlmsg(syscall.NLMSG_ERROR, make([]byte, 4+unix.NLMSG_HDRLEN)))
	got, err := c.do(unix.GENL_ID_CTRL, unix.CTRL_CMD_GETFAMILY, attr(unix.CTRL_ATTR_FAMILY_NAME, cstr("agentos-none")))
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("a forged acknowledgement read as the kernel's: %v %v", got, err)
	}

	r, err := open(unix.NETLINK_ROUTE, time.Now().Add(replyWait))
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	fake := make([]byte, syscall.SizeofIfInfomsg)
	ne.PutUint32(fake[4:], 999)
	fake = append(fake, attr(unix.IFLA_IFNAME, cstr("forged0"))...)
	forge(t, r, unix.NETLINK_ROUTE, r.seq+1, nlmsg(syscall.RTM_NEWLINK, fake), nlmsg(syscall.NLMSG_DONE, make([]byte, 4)))
	msgs, err := r.request(syscall.RTM_GETLINK, syscall.NLM_F_DUMP, make([]byte, syscall.SizeofIfInfomsg))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) == 0 {
		t.Fatal("the kernel's links were not read")
	}
	for _, m := range msgs {
		if ne.Uint32(m[4:8]) == 999 {
			t.Fatal("a forged link read as the kernel's")
		}
	}
}

// TestWalkFailsClosed (ENF-gro-3): a parent that is no link here, which
// only a dump the kernel did not send could hold, and a parent in
// another namespace other than a veth's peer are errors, never a port
// passed with its lower device unwalked; lower devices come first.
func TestWalkFailsClosed(t *testing.T) {
	links := []link{
		{index: 2, name: "eth0"},
		{index: 3, name: "mv0", kind: "macvlan", parent: 2},
		{index: 4, name: "vl0", kind: "vlan", parent: 9},
		{index: 5, name: "vc", kind: "veth", parent: 2, elsewhere: true},
		{index: 6, name: "mv1", kind: "macvlan", parent: 7, elsewhere: true},
	}
	if got, err := walk(links, []string{"mv0", "vc"}); err != nil || !slices.Equal(got, []string{"eth0", "mv0", "vc"}) {
		t.Fatalf("walk: %v %v", got, err)
	}
	if _, err := walk(links, []string{"vl0"}); err == nil || !strings.Contains(err.Error(), "vl0: its parent 9 is not a link here") {
		t.Fatalf("an unresolved parent: %v", err)
	}
	if _, err := walk(links, []string{"mv1"}); err == nil || !strings.Contains(err.Error(), "mv1: its parent is in another namespace") {
		t.Fatalf("a parent in another namespace: %v", err)
	}
}

// TestFloodEndsRequest (ENF-gro-4): datagrams from another sender that
// keep arriving do not hold a request past replyWait: it fails (and the
// daemon holds the port at its caps) rather than stall the reading.
func TestFloodEndsRequest(t *testing.T) {
	if !inNetns(t) { // sending to another socket's port needs CAP_NET_ADMIN, as the forger would
		return
	}
	defer func(w time.Duration) { replyWait = w }(replyWait)
	replyWait = 300 * time.Millisecond
	c, err := open(unix.NETLINK_ROUTE, time.Now().Add(replyWait))
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer c.close()
	sa, err := syscall.Getsockname(c.fd)
	if err != nil {
		t.Fatal(err)
	}
	to := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: sa.(*syscall.SockaddrNetlink).Pid}
	f, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
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
	go func() { _, err := c.recv(syscall.RTM_NEWLINK); done <- err }() // a reply the kernel never sends
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

// TestDumpEnd (ENF-gro-3, #5103 item 1): a dump ends only on the
// kernel's NLMSG_DONE for this request, and ends in error when the DONE
// carries one or when any of its messages is marked NLM_F_DUMP_INTR (the
// links changed while it was read), so a dump cut short or inconsistent
// never reads as every link.
func TestDumpEnd(t *testing.T) {
	msg := func(typ, flags uint16, seq uint32, data []byte) syscall.NetlinkMessage {
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: typ, Flags: flags, Seq: seq}, Data: data}
	}
	errno := func(e syscall.Errno) []byte {
		b := make([]byte, 4)
		ne.PutUint32(b, uint32(-int32(e)))
		return b
	}
	link := []byte{1, 2, 3, 4}
	var r reading
	done, err := r.take([]syscall.NetlinkMessage{msg(syscall.RTM_NEWLINK, syscall.NLM_F_MULTI, 7, link), msg(syscall.RTM_NEWLINK, 0, 6, link)}, 7, syscall.RTM_NEWLINK)
	if done || err != nil || len(r.replies) != 1 {
		t.Fatalf("a dump's first datagram: done %v, %v, %d replies (another request's message is not this one's)", done, err, len(r.replies))
	}
	if done, err = r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_DONE, 0, 6, errno(syscall.EBUSY)), msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, 7, make([]byte, 4))}, 7, syscall.RTM_NEWLINK); !done || err != nil || len(r.replies) != 1 {
		t.Fatalf("a clean end: done %v, %v, %d replies", done, err, len(r.replies))
	}

	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.RTM_NEWLINK, syscall.NLM_F_MULTI, 7, link), msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, 7, errno(syscall.ENOBUFS))}, 7, syscall.RTM_NEWLINK); !done || !errors.Is(err, syscall.ENOBUFS) {
		t.Fatalf("a dump that ends in error: done %v, %v", done, err)
	}
	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.RTM_NEWLINK, syscall.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, 7, link)}, 7, syscall.RTM_NEWLINK); done || err != nil {
		t.Fatalf("an interrupted dump ended before its end: done %v, %v", done, err)
	}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, 7, make([]byte, 4))}, 7, syscall.RTM_NEWLINK); !done || !errors.Is(err, errDumpIntr) {
		t.Fatalf("a dump with an interrupted message: done %v, %v", done, err)
	}
	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, 7, make([]byte, 4))}, 7, syscall.RTM_NEWLINK); !done || !errors.Is(err, errDumpIntr) {
		t.Fatalf("a dump whose end is marked interrupted: done %v, %v", done, err)
	}
	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, 7, []byte{0, 0, 0})}, 7, syscall.RTM_NEWLINK); !done || err == nil {
		t.Fatalf("a dump end with no error code: done %v, %v", done, err)
	}
	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_ERROR, 0, 7, append(errno(syscall.EPERM), make([]byte, unix.NLMSG_HDRLEN)...))}, 7, syscall.RTM_NEWLINK); !done || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("a refusal: done %v, %v", done, err)
	}
	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_ERROR, 0, 7, make([]byte, 4+unix.NLMSG_HDRLEN))}, 7, syscall.RTM_NEWLINK); !done || err != nil {
		t.Fatalf("an acknowledgement: done %v, %v", done, err)
	}
	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_ERROR, 0, 7, make([]byte, 4))}, 7, syscall.RTM_NEWLINK); !done || err != nil {
		t.Fatalf("an acknowledgement of its code alone: done %v, %v", done, err)
	}
	r = reading{}
	if done, err := r.take([]syscall.NetlinkMessage{msg(syscall.NLMSG_ERROR, 0, 7, []byte{0, 0})}, 7, syscall.RTM_NEWLINK); !done || err == nil {
		t.Fatalf("a short error: done %v, %v", done, err)
	}
}

// TestOneDeadlinePerCall (ENF-gro-4, #5103 item 3): every request of one
// call shares one deadline. Under a flood of other datagrams each request
// on a socket fails once the call's deadline has passed, not replyWait
// after it began, so three requests end within about one replyWait, not
// three; and an Off whose deadline has passed sets no device under a
// port with several, rather than give each request a fresh replyWait.
func TestOneDeadlinePerCall(t *testing.T) {
	if !inNetns(t) { // sending to another socket's port needs CAP_NET_ADMIN, as the forger would
		return
	}
	defer func(w time.Duration) { replyWait = w }(replyWait)
	replyWait = 500 * time.Millisecond
	start := time.Now()
	c, err := open(unix.NETLINK_ROUTE, start.Add(replyWait))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	sa, err := syscall.Getsockname(c.fd)
	if err != nil {
		t.Fatal(err)
	}
	to := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: sa.(*syscall.SockaddrNetlink).Pid}
	f, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
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
			syscall.Sendto(f, noop, 0, to)
			time.Sleep(time.Millisecond)
		}
	}()
	done := make(chan error, 1)
	go func() {
		for range 3 {
			c.seq++
			if _, err := c.recv(syscall.RTM_NEWLINK); !errors.Is(err, errNoReply) { // replies the kernel never sends
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a request under a flood: %v", err)
		}
	case <-time.After(5 * replyWait):
		t.Fatal("a flood held one call's requests past its deadline") // the flood goes on: the test binary ends here
	}
	close(stop)
	<-flooding
	if d := time.Since(start); d >= 2*replyWait {
		t.Fatalf("three flooded requests of one call took %v: each had its own deadline", d)
	}

	ip(t, "link", "add", "da", "type", "veth", "peer", "name", "db")
	ip(t, "link", "add", "br1", "type", "bridge")
	ip(t, "link", "set", "da", "master", "br1")
	ip(t, "link", "add", "dc", "type", "veth", "peer", "name", "dd")
	ip(t, "link", "set", "dc", "master", "br1")
	for _, d := range []string{"da", "db", "dc", "dd", "br1"} {
		if err := Set(d, map[string]bool{"rx-gro": true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := off(time.Now().Add(-time.Millisecond), "br1"); !errors.Is(err, errNoReply) {
		t.Fatalf("an Off past its deadline: %v", err)
	}
	for _, d := range []string{"da", "dc", "br1"} {
		if len(merging(t, d)) == 0 {
			t.Fatalf("%s was set by an Off past its deadline", d)
		}
	}
	if err := off(time.Now().Add(replyWait), "br1"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"da", "db", "dc", "dd", "br1"} {
		if on := merging(t, d); len(on) > 0 {
			t.Fatalf("%s still merging: %v", d, on)
		}
	}
}

// TestBitsetRefusesAMalformedBit (#5140): a bit with bytes past its
// last attribute is refused, not read by the name before them. Catches a
// bitset that reads a bit it did not parse whole.
func TestBitsetRefusesAMalformedBit(t *testing.T) {
	trailing := attr(unix.ETHTOOL_A_BITSET_BITS|unix.NLA_F_NESTED, attr(unix.ETHTOOL_A_BITSET_BITS_BIT|unix.NLA_F_NESTED,
		append(attr(unix.ETHTOOL_A_BITSET_BIT_NAME, []byte("rx-gro\x00")), 1, 2)))
	if got, err := bitset(append(attr(unix.ETHTOOL_A_BITSET_NOMASK, nil), trailing...)); err == nil {
		t.Fatalf("a bit with bytes past its attributes was read: %v", got)
	}
}
