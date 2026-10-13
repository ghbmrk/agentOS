package imapsmtp

// REQ: CRED-1, CRED-8

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// hostile is a raw IMAP server that logs in, selects any folder with
// UID validity 7 and answers a UID FETCH with fetch's bytes, after which
// it closes the connection when hangup is set, else holds it open. It
// stands in for a hostile or broken mail host (SR3-mail-k18).
func hostile(t testing.TB, fetch string, hangup bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go converse(c, fetch, hangup)
		}
	}()
	return l.Addr().String()
}

func converse(c net.Conn, fetch string, hangup bool) {
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
		switch {
		case cmd == "LOGIN":
			say(tag + " OK done\r\n")
		case cmd == "SELECT" || cmd == "EXAMINE":
			say("* 1 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n" + tag + " OK [READ-ONLY] done\r\n")
		case cmd == "UID" && len(f) > 2 && strings.ToUpper(f[2]) == "FETCH":
			say(fetch)
			if hangup {
				return
			}
		case cmd == "LOGOUT":
			say("* BYE bye\r\n" + tag + " OK done\r\n")
			return
		default:
			say(tag + " BAD unknown\r\n")
		}
	}
}

func hostileStore(t testing.TB, addr string, timeout time.Duration) *Store {
	t.Helper()
	s, err := New(Config{IMAP: addr, SMTP: addr, IMAPSec: Plain, SMTPSec: Plain, From: "owner@example.test",
		Timeout: timeout,
		Credential: func(context.Context) (Login, error) {
			return Login{User: "canary-user", Secret: "canary-secret"}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// bareFetch is the reproduced seed: responses.Fetch.Handle reads
// fields[1] after checking only len(fields) < 1 (go-imap v1.2.1
// responses/fetch.go:21-30), on the client's reader goroutine.
const bareFetch = "* 1 FETCH\r\n"

const childEnv = "AGENTOS_K18_CHILD"

// TestReaderPanicFailsTheCall (T1): a bare "* 1 FETCH" during a UID
// fetch panics in go-imap's reader goroutine, where neither imapsmtp nor
// mailsock can recover it. Run in a subprocess so that without the
// guard the panic is reported here instead of ending this test binary:
// with the guard the call returns an error and the process lives. The
// server holds the connection open, so the error comes from the guard,
// not from EOF, and well inside the store's own timeout.
func TestReaderPanicFailsTheCall(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReaderPanicChild$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "panic:") {
		t.Fatalf("the reader goroutine's panic ended the process: %v\n%s", err, tail(string(out), 1500))
	}
	if !strings.Contains(string(out), "k18: call failed:") {
		t.Fatalf("child did not report the failed call:\n%s", tail(string(out), 1500))
	}
}

func TestReaderPanicChild(t *testing.T) {
	if os.Getenv(childEnv) != "1" {
		t.Skip("run by TestReaderPanicFailsTheCall")
	}
	s := hostileStore(t, hostile(t, bareFetch, false), 30*time.Second)
	start := time.Now()
	_, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1})
	if err == nil {
		t.Fatal("a hostile FETCH reply was answered as success")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the call took %v: it waited out a timeout instead of failing on the guard", d)
	}
	t.Logf("k18: call failed: %v", err)
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// FuzzIMAPReplies (T2): whatever a server sends in answer to a UID
// FETCH, the call ends in an error and the process lives. The server
// closes after its bytes, so no stream can complete the command (it
// cannot know the tag), and the timeout bounds any that stall.
func FuzzIMAPReplies(f *testing.F) {
	for _, s := range []string{
		bareFetch,
		"* 1 FETCH (UID 1 BODY[]<0> {99999999}\r\nshort",              // oversized literal
		"* 1 FETCH (UID 1 BODY[] {10}\r\nabc",                         // truncated literal
		"* 1 FETCH (((((((((((((((((((((((((((((((((",                 // nested lists
		"* 1 FETCH (FLAGS (\\Seen) BODYSTRUCTURE (((((((\r\n",         // nested, unterminated
		"* 1 FETCH (UID 1 FLAGS (\x00))\r\n",                          // NUL
		"* 99999999999999999999 FETCH (UID 99999999999999999999)\r\n", // huge numbers
		"* 1 FETCH (UID 4294967296)\r\n",
		"* 3 EXISTS\r\n* 2 EXPUNGE\r\n* 1 FETCH\r\n* OK [ALERT] mid-command\r\n", // untagged mid-command
		"* 1 FETCH (BODYSTRUCTURE (\"text\"))\r\n",
		"* 1 FETCH (ENVELOPE (NIL))\r\n",
		"* 1 FETCH (BODY[] NIL BODY[] NIL)\r\n",
		"* FETCH\r\n",
		"* 1 FETCH UID\r\n",
		"* CAPABILITY\r\n* 1 EXISTS\r\n* 1 RECENT\r\n* 1 EXPUNGE\r\n",
		"* BYE\r\n",
		"+ more\r\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, stream string) {
		s := hostileStore(t, hostile(t, stream, true), 3*time.Second)
		if _, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1}); err == nil {
			t.Fatalf("stream %q was answered as success", stream)
		}
	})
}
