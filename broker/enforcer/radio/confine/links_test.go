package confine

// REQ: NET-2

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// TestLinkAckOnlyFromKernel (#5095, the netlink sender check offload has):
// an acknowledgement another process sends to the link socket's port is
// dropped unread, so a link the kernel refused never reads as made.
func TestLinkAckOnlyFromKernel(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*syscall.SockaddrNetlink).Pid
	forger, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(forger)
	if err := syscall.Bind(forger, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, syscall.SizeofNlMsghdr+4+syscall.SizeofNlMsghdr) // error 0: success
	binary.NativeEndian.PutUint32(ack[0:], uint32(len(ack)))
	binary.NativeEndian.PutUint16(ack[4:], syscall.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(ack[8:], 1)
	if err := syscall.Sendto(forger, ack, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: port}); err != nil {
		t.Fatal(err)
	}
	// The kernel refuses a change to a link that does not exist (or, with
	// no CAP_NET_ADMIN, any change).
	if err := request(fd, 1, newLink("agentosnone0", "", syscall.IFF_UP, syscall.NLM_F_ACK)); err == nil {
		t.Fatal("a forged acknowledgement read as the kernel's")
	}
}
