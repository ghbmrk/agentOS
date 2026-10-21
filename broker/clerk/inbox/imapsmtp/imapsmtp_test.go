package imapsmtp

// REQ: CRED-8

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// failedSelect is a raw IMAP server that logs in, refuses every SELECT
// and then floods unilateral "* n EXISTS" lines. A failed SELECT
// sets go-imap's selected mailbox back to nil on the caller's goroutine
// while the reader is still handling those lines, which is the window
// in which the reader's EXISTS handler used to dereference a nil
// mailbox while holding the client's state lock (SR3-mail-k18c).
func failedSelect(t testing.TB, flood int) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	exists := strings.Repeat("* 3 EXISTS\r\n* 2 RECENT\r\n", flood)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(30 * time.Second))
				w := bufio.NewWriter(c)
				say := func(s string) { w.WriteString(s); w.Flush() }
				say("* OK [CAPABILITY IMAP4rev1] ready\r\n")
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					f := strings.Fields(line)
					if len(f) < 2 {
						return
					}
					tag, cmd := f[0], strings.ToUpper(f[1])
					switch cmd {
					case "LOGIN":
						say(tag + " OK done\r\n")
					case "SELECT", "EXAMINE":
						say(exists + tag + " NO [NONEXISTENT] no such folder\r\n" + exists)
					case "LOGOUT":
						say("* BYE bye\r\n" + tag + " OK done\r\n")
						return
					default:
						say(tag + " BAD unknown\r\n")
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// TestFailedSelectThenExistsAnswers (CRED-8 / egress K18: a hostile
// server costs one call): unilateral EXISTS and RECENT lines around a
// refused SELECT must never leave the call waiting. Each call must fail
// (the folder was refused) well inside the store's timeout; a call that
// does not return means the reader died holding the client's state lock
// and the session's deferred Logout is blocked on it. The race is
// between two goroutines, so the test repeats the call.
func TestFailedSelectThenExistsAnswers(t *testing.T) {
	addr := failedSelect(t, 200)
	s := hostileStore(t, addr, 30*time.Second)
	for i := 0; i < 300; i++ {
		done := make(chan error, 1)
		go func() {
			_, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1})
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("call %d: a refused SELECT was answered as success", i)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("call %d hung after a refused SELECT and unilateral EXISTS: the client's state lock was left held", i)
		}
	}
}

// A flag that is not a system flag or a keyword atom is refused before
// any connection: go-imap writes flags unquoted, so a space or a line
// break would add a flag or a whole command (CRED-8).
func TestFlagsThatAreNotAtomsAreRefusedBeforeActing(t *testing.T) {
	s, err := New(Config{IMAP: "127.0.0.1:1", SMTP: "127.0.0.1:1", IMAPSec: Plain, SMTPSec: Plain, From: "o@example.test",
		Credential: func(context.Context) (Login, error) { t.Fatal("a refused flag reached the login"); return Login{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"", "a b", "agentOS/bulk \\Deleted", "x\r\nA1 UID EXPUNGE", "(x", "x)", "x{3}", "x%", "x*", `x"`, `x\`, "x]", "café", `\Recent`, `\Other`} {
		if err := s.SetFlags(context.Background(), Ref{Folder: "INBOX", Validity: 1, UID: 1}, []string{f}, nil); !errors.Is(err, ErrBadFlag) {
			t.Errorf("SetFlags add %q = %v, want ErrBadFlag", f, err)
		}
		if err := s.SetFlags(context.Background(), Ref{Folder: "INBOX", Validity: 1, UID: 1}, nil, []string{f}); !errors.Is(err, ErrBadFlag) {
			t.Errorf("SetFlags remove %q = %v, want ErrBadFlag", f, err)
		}
		if err := s.Append(context.Background(), "INBOX", []string{f}, time.Now(), []byte("x")); !errors.Is(err, ErrBadFlag) {
			t.Errorf("Append %q = %v, want ErrBadFlag", f, err)
		}
	}
	for _, f := range []string{`\Seen`, `\deleted`, `\Draft`, "agentOS/bulk", "AgentOS", "$Junk"} {
		if !flagsValid([]string{f}) {
			t.Errorf("%q refused, want accepted", f)
		}
	}
}
