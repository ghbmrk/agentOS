// Command bootprobe is the CI boot probe for the IMAP connection process's
// launch (image/ci_boot.sh, #3015), run as the mail clerk's user against the
// image's agentos-imapconn.socket, whose instances run bootconn under the
// shipped sandbox. It holds a first session open while it opens a second,
// whose process tries to read the first's memory, and checks that each is a
// fresh process under a user other than the clerk's, in its own pid
// namespace, undumpable, with no network, none of the clerk's files and no
// new privileges, and that a session's process is gone once the clerk
// closes it. With -refused, run as any other user, it checks that the
// socket admits no one but the clerk.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

// These match the image's units (agentos-imapconn.socket, the mail clerk's
// -dir).
const (
	sock     = "/run/agentos-imapconn/conn.sock"
	clerkDir = "/var/lib/agentos-mail"
)

// Report is bootconn's.
type Report struct {
	PID                                                                          int
	Undumpable, Unix, Inet, Inet6, Netlink, ClerkDir, ClerkSock, Passwd, PeerMem string
	NoNewPrivs                                                                   bool
}

var failed bool

func say(ok bool, format string, a ...any) {
	v := "ok  "
	if !ok {
		v, failed = "FAIL", true
	}
	fmt.Printf("agentos-imapconn: %s %s\n", v, fmt.Sprintf(format, a...))
}

func alive(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return err == nil
}

// session is one open session: its process's report, and its host pid and
// uid, which the kernel gives from the credentials bootconn sends.
type session struct {
	c        *net.UnixConn
	r        Report
	pid, uid int
}

// open opens a session and sends it line ("none", or "probe PID").
func open(line string) (*session, error) {
	c, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		return nil, err
	}
	u := c.(*net.UnixConn)
	u.SetDeadline(time.Now().Add(30 * time.Second))
	s := &session{c: u}
	raw, err := u.SyscallConn()
	if err == nil {
		raw.Control(func(fd uintptr) { err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1) })
	}
	if err == nil {
		_, err = u.Write([]byte(line + "\n"))
	}
	b, oob := make([]byte, 1), make([]byte, 128)
	var n, oobn int
	if err == nil {
		n, oobn, _, _, err = u.ReadMsgUnix(b, oob)
	}
	if err == nil && (n != 1 || b[0] != 'C') {
		err = errors.New("no credentials byte")
	}
	if err == nil {
		err = s.creds(oob[:oobn])
	}
	if err == nil {
		err = json.NewDecoder(bufio.NewReader(u)).Decode(&s.r)
	}
	if err != nil {
		u.Close()
		return nil, err
	}
	return s, nil
}

func (s *session) creds(oob []byte) error {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil || len(msgs) != 1 {
		return fmt.Errorf("credentials: %v (%d messages)", err, len(msgs))
	}
	cr, err := syscall.ParseUnixCredentials(&msgs[0])
	if err != nil {
		return err
	}
	s.pid, s.uid = int(cr.Pid), int(cr.Uid)
	return nil
}

// close closes the session and reports whether its process ended.
func (s *session) close() bool {
	s.c.Close()
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end) && alive(s.pid); {
		time.Sleep(100 * time.Millisecond)
	}
	return !alive(s.pid)
}

func check(i int, s *session) {
	r := s.r
	say(s.uid != os.Getuid() && s.uid != 0, "session %d runs as uid %d, not the clerk's %d or root", i, s.uid, os.Getuid())
	say(r.PID == 1 && s.pid > 1, "session %d has its own pid namespace (pid %d there, %d on the host)", i, r.PID, s.pid)
	say(r.Undumpable == "", "session %d marks itself undumpable (%s)", i, r.Undumpable)
	say(r.Unix != "" && r.Inet != "" && r.Inet6 != "" && r.Netlink != "",
		"session %d: socket() refused (unix %q, inet %q, inet6 %q, netlink %q)", i, r.Unix, r.Inet, r.Inet6, r.Netlink)
	say(r.ClerkDir != "", "session %d cannot open the clerk's state directory (%s)", i, r.ClerkDir)
	say(r.ClerkSock != "", "session %d cannot reach the clerk's kernel socket (%s)", i, r.ClerkSock)
	say(r.Passwd != "", "session %d: the root is the empty tmpfs (/etc/passwd: %s)", i, r.Passwd)
	say(r.NoNewPrivs, "session %d has no new privileges", i)
}

func main() {
	refused := flag.Bool("refused", false, "expect the socket to refuse this user")
	flag.Parse()
	if *refused {
		c, err := net.DialTimeout("unix", sock, 10*time.Second)
		if c != nil {
			c.Close()
		}
		say(errors.Is(err, os.ErrPermission), "uid %d is refused the socket (%v)", os.Getuid(), err)
		fmt.Println("agentos-imapconn: DONE refused")
		return
	}
	_, err := os.Stat(clerkDir)
	say(err == nil, "the clerk's state directory is there for its own user (%v)", err)
	s1, err := open("none")
	if err != nil {
		say(false, "session 1: %v", err)
	} else {
		check(1, s1)
		say(alive(s1.pid), "session 1's process %d runs while the session is open", s1.pid)
		// The second session opens while the first is held, and tries the
		// first's memory by its host pid.
		s2, err := open("probe " + strconv.Itoa(s1.pid))
		if err != nil {
			say(false, "session 2: %v", err)
		} else {
			check(2, s2)
			say(s2.r.PeerMem != "", "session 2 cannot read session 1's memory (%s)", s2.r.PeerMem)
			say(s2.pid != s1.pid, "each session is a fresh process (%d, %d)", s1.pid, s2.pid)
			say(s2.close(), "session 2's process %d ends when the session closes", s2.pid)
		}
		say(s1.close(), "session 1's process %d ends when the session closes", s1.pid)
	}
	if failed {
		fmt.Println("agentos-imapconn: DONE failed")
		return
	}
	fmt.Println("agentos-imapconn: DONE")
}
