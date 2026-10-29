// Command bootprobe is the CI boot probe for the IMAP connection process's
// launch (image/ci_boot.sh, #3015), run as the mail clerk's user against the
// image's agentos-imapconn.socket, whose instances run bootconn under the
// shipped sandbox. It opens two sessions one after the other and checks
// that each is a fresh process under a user other than the clerk's, with
// no network, none of the clerk's files and no new privileges, and that a
// session's process is gone once the clerk closes it. With -refused, run as
// any other user, it checks that the socket admits no one but the clerk.
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
	"time"
)

// These match the image's units (agentos-imapconn.socket, the mail clerk's
// -dir and kernel socket).
const (
	sock     = "/run/agentos-imapconn/conn.sock"
	clerkDir = "/var/lib/agentos-mail"
)

// Report is bootconn's.
type Report struct {
	UID, PID                                          int
	Inet, Inet6, Netlink, ClerkDir, ClerkSock, Passwd string
	NoNewPrivs                                        bool
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

// session opens one session, reads its process's report, checks the process
// is running while the session is open, closes it, and waits for the
// process to end.
func session() (Report, bool, bool, error) {
	c, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		return Report{}, false, false, err
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var r Report
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&r); err != nil {
		c.Close()
		return r, false, false, err
	}
	during := alive(r.PID)
	c.Close()
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end) && alive(r.PID); {
		time.Sleep(100 * time.Millisecond)
	}
	return r, during, !alive(r.PID), nil
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
	var pids []int
	for i := 1; i <= 2; i++ {
		r, during, ended, err := session()
		if err != nil {
			say(false, "session %d: %v", i, err)
			continue
		}
		say(r.UID != os.Getuid() && r.UID != 0, "session %d runs as uid %d, not the clerk's %d or root", i, r.UID, os.Getuid())
		say(r.Inet != "" && r.Inet6 != "" && r.Netlink != "", "session %d: socket() refused (inet %q, inet6 %q, netlink %q)",
			i, r.Inet, r.Inet6, r.Netlink)
		say(r.ClerkDir != "", "session %d cannot open the clerk's state directory (%s)", i, r.ClerkDir)
		say(r.ClerkSock != "", "session %d cannot reach the clerk's kernel socket (%s)", i, r.ClerkSock)
		say(r.Passwd != "", "session %d: the root is the empty tmpfs (/etc/passwd: %s)", i, r.Passwd)
		say(r.NoNewPrivs, "session %d has no new privileges", i)
		say(during && ended, "session %d's process %d runs while the session is open and ends when it closes", i, r.PID)
		pids = append(pids, r.PID)
	}
	say(len(pids) == 2 && pids[0] != pids[1], "each session is a fresh process (%v)", pids)
	if failed {
		fmt.Println("agentos-imapconn: DONE failed")
		return
	}
	fmt.Println("agentos-imapconn: DONE")
}
