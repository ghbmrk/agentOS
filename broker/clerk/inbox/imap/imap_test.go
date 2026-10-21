package imap

// REQ: CRED-8

import (
	"bufio"
	"context"
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
