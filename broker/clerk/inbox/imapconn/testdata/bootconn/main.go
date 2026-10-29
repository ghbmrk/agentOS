// Command bootconn is the CI boot probe's stand-in for the IMAP connection
// process (image/ci_boot.sh, #3015): run in place of agentos-imapconn by a
// drop-in that changes only the binary, so it runs under the shipped
// agentos-imapconn@.service's sandbox. It reports on descriptor 3, the
// session's connection, what that sandbox lets it do, then holds the
// session until the peer closes it, as the real process does.
// It is test tooling: the real process makes none of these checks.
package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// Report is what one session's process found; bootprobe reads it.
type Report struct {
	UID, PID int
	// Each is "" when the call succeeded, otherwise its error.
	Inet, Inet6, Netlink, ClerkDir, ClerkSock, Passwd string
	NoNewPrivs                                        bool
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

func main() {
	f := os.NewFile(3, "session")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		os.Exit(2)
	}
	r := Report{UID: os.Getuid(), PID: os.Getpid(), Inet: socket(syscall.AF_INET), Inet6: socket(syscall.AF_INET6),
		Netlink: socket(syscall.AF_NETLINK), ClerkDir: open("/var/lib/agentos-mail"), Passwd: open("/etc/passwd")}
	if k, err := net.Dial("unix", "/run/agentos-mail/kernel.sock"); err == nil {
		k.Close()
	} else {
		r.ClerkSock = err.Error()
	}
	if s, err := os.ReadFile("/proc/self/status"); err == nil {
		r.NoNewPrivs = strings.Contains(string(s), "\nNoNewPrivs:\t1\n")
	}
	if json.NewEncoder(c).Encode(r) != nil {
		os.Exit(1)
	}
	io.Copy(io.Discard, c) // until the peer closes the session
}
