package offload

// REQ: NET-2

import (
	"errors"
	"slices"
	"strings"
	"syscall"
	"testing"

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
	c, err := open(unix.NETLINK_GENERIC)
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer c.close()
	forge(t, c, unix.NETLINK_GENERIC, c.seq+1, nlmsg(syscall.NLMSG_ERROR, make([]byte, 4+unix.NLMSG_HDRLEN)))
	got, err := c.do(unix.GENL_ID_CTRL, unix.CTRL_CMD_GETFAMILY, attr(unix.CTRL_ATTR_FAMILY_NAME, cstr("agentos-none")))
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("a forged acknowledgement read as the kernel's: %v %v", got, err)
	}

	r, err := open(unix.NETLINK_ROUTE)
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
