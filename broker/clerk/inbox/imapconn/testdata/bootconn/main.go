// Command bootconn is the CI boot probe's stand-in for the IMAP connection
// process (image/ci_boot.sh, #3015): run in place of agentos-imapconn by a
// drop-in that changes only the binary, so it runs under the shipped
// agentos-imapconn@.service's sandbox. On descriptor 3, the session's
// connection, it reads one line from bootprobe ("none", or "probe PID": a
// concurrent session's process, by its pid on the host), then sends one
// byte carrying its credentials, which the kernel gives bootprobe as its
// host pid and uid, and its report of what the sandbox lets it do. It then
// holds the session until the peer closes it, as the real process does.
// It is test tooling: the real process makes none of these checks.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
)

// Report is what one session's process found; bootprobe reads it.
type Report struct {
	// PID is its own pid as it sees it: 1 in its own pid namespace.
	PID int
	// Each is "" when the call succeeded, otherwise its error.
	Undumpable, Unix, Inet, Inet6, Netlink, ClerkDir, ClerkSock, Passwd, PeerMem string
	NoNewPrivs                                                                   bool
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func socket(family int) string {
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if family == syscall.AF_NETLINK {
		fd, err = syscall.Socket(family, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	}
	if err == nil {
		syscall.Close(fd)
	}
	return errText(err)
}

func open(path string) string {
	f, err := os.Open(path)
	if err == nil {
		f.Close()
	}
	return errText(err)
}

// peerMem reads a byte of the memory of process pid, by its /proc entry
// only (no ptrace call, which the seccomp filter refuses anyway).
func peerMem(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return err.Error()
	}
	defer f.Close()
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return err.Error()
	}
	var lo uint64
	fmt.Sscanf(string(maps), "%x-", &lo)
	if _, err := f.ReadAt(make([]byte, 1), int64(lo)); err != nil {
		return err.Error()
	}
	return ""
}

func main() {
	r := Report{Undumpable: errText(imapconn.Undumpable())}
	f := os.NewFile(3, "session")
	c, err := net.FileConn(f)
	f.Close()
	u, ok := c.(*net.UnixConn)
	if err != nil || !ok {
		os.Exit(2)
	}
	in := bufio.NewReader(u)
	line, err := in.ReadString('\n')
	if err != nil {
		os.Exit(2)
	}
	r.PID, r.Unix, r.Inet, r.Inet6, r.Netlink = os.Getpid(), socket(syscall.AF_UNIX), socket(syscall.AF_INET), socket(syscall.AF_INET6), socket(syscall.AF_NETLINK)
	r.ClerkDir, r.Passwd = open("/var/lib/agentos-mail"), open("/etc/passwd")
	if k, err := net.Dial("unix", "/run/agentos-mail/kernel.sock"); err == nil {
		k.Close()
	} else {
		r.ClerkSock = err.Error()
	}
	if s, err := os.ReadFile("/proc/self/status"); err == nil {
		r.NoNewPrivs = strings.Contains(string(s), "\nNoNewPrivs:\t1\n")
	}
	var pid int
	if _, err := fmt.Sscanf(line, "probe %d", &pid); err == nil {
		r.PeerMem = peerMem(pid)
	}
	cred := syscall.UnixCredentials(&syscall.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())})
	if _, _, err := u.WriteMsgUnix([]byte{'C'}, cred, nil); err != nil {
		os.Exit(1)
	}
	if json.NewEncoder(u).Encode(r) != nil {
		os.Exit(1)
	}
	io.Copy(io.Discard, in) // until the peer closes the session
}
