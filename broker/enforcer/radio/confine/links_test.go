package confine

// REQ: NET-2

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestLinkAckOnlyFromKernel (#5095, the netlink sender check offload has):
// an acknowledgement another process sends to the link socket's port is
// dropped unread, so a link the kernel refused never reads as made.
func TestLinkAckOnlyFromKernel(t *testing.T) {
	if !inUserNetns(t) {
		return
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
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

// TestLinkAckFloodEnds: datagrams from another sender that keep arriving
// do not hold the wait for an acknowledgement past ackWait.
func TestLinkAckFloodEnds(t *testing.T) {
	if !inUserNetns(t) {
		return
	}
	defer func(w time.Duration) { ackWait = w }(ackWait)
	ackWait = 300 * time.Millisecond
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		t.Skipf("no netlink socket here: %v", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
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
	noop := make([]byte, syscall.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(noop[0:], uint32(len(noop)))
	binary.NativeEndian.PutUint16(noop[4:], syscall.NLMSG_NOOP)
	stop, flooding := make(chan struct{}), make(chan struct{})
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
	go func() { done <- ack(fd, 99) }() // an acknowledgement the kernel never sends
	select {
	case err := <-done:
		if !errors.Is(err, errNoAck) {
			t.Fatalf("a flooded wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a flood of other datagrams held the wait past ackWait")
	}
}

const netnsEnv = "AGENTOS_CONFINE_LINKS_NETNS"

// inUserNetns runs the calling test again in a fresh user and network
// namespace (unshare -rn) and reports whether this is that run. Sending to
// another netlink socket's port needs CAP_NET_ADMIN, as a forger would;
// CI fails rather than skips when the namespace cannot be made.
func inUserNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv(netnsEnv) == "1" {
		return true
	}
	required := os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1"
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		if required {
			t.Fatalf("no unprivileged user namespaces: %v", err)
		}
		t.Skipf("no unprivileged user namespaces: %v", err)
	}
	cmd := exec.Command("unshare", "-rn", "--", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), netnsEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("in a fresh namespace:\n%s", out)
	if err != nil {
		t.Fatalf("netns run failed: %v", err)
	}
	return false
}
