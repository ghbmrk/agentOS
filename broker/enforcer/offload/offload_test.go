package offload

// REQ: NET-2

import (
	"errors"
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

// TestForgedReplyRefused (ENF-gro-4): a reply that does not come from the
// kernel is refused, so a local process that finds the daemon's netlink
// port cannot answer "nothing merges" for it.
func TestForgedReplyRefused(t *testing.T) {
	c := &conn{seq: 7}
	var err error
	if c.fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, unix.NETLINK_GENERIC); err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer c.close()
	if err := syscall.Bind(c.fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(c.fd)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*syscall.SockaddrNetlink).Pid
	forger, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, unix.NETLINK_GENERIC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(forger)
	if err := syscall.Bind(forger, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	// An acknowledgement of request 7 with no error: read as the kernel's,
	// it would end the request with no replies.
	ack := make([]byte, unix.NLMSG_HDRLEN+4+unix.NLMSG_HDRLEN)
	ne.PutUint32(ack[0:], uint32(len(ack)))
	ne.PutUint16(ack[4:], syscall.NLMSG_ERROR)
	ne.PutUint32(ack[8:], 7)
	if err := syscall.Sendto(forger, ack, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: port}); err != nil {
		t.Fatal(err)
	}
	if got, err := c.recv(0x20); !errors.Is(err, errNotKernel) {
		t.Fatalf("a forged acknowledgement read as the kernel's: %v %v", got, err)
	}
}
