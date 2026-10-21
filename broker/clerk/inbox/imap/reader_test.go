package imap

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

	"github.com/emersion/go-imap/client"
)

// hostile is a raw IMAP server that logs in, selects any folder with
// UID validity 7 and answers a UID FETCH with fetch's bytes, after which
// it closes the connection when hangup is set, else holds it open. It
// stands in for a hostile or broken mail host (SR3-mail-k18). Each
// conversation's end ("eof" when the client closed the connection,
// "logout" or "hangup") is sent on the returned channel if there is room.
func hostile(t testing.TB, fetch string, hangup bool) (string, <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ended := make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				end := converse(c, fetch, hangup)
				select {
				case ended <- end:
				default:
				}
			}()
		}
	}()
	return l.Addr().String(), ended
}

func converse(c net.Conn, fetch string, hangup bool) string {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	w := bufio.NewWriter(c)
	say := func(s string) { w.WriteString(s); w.Flush() }
	say("* OK [CAPABILITY IMAP4rev1] ready\r\n")
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "eof"
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return "short"
		}
		tag, cmd := f[0], strings.ToUpper(f[1])
		switch {
		case cmd == "LOGIN":
			say(tag + " OK done\r\n")
		case cmd == "SELECT" || cmd == "EXAMINE":
			say("* 1 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n" + tag + " OK [READ-ONLY] done\r\n")
		case cmd == "UID" && len(f) > 2 && strings.ToUpper(f[2]) == "FETCH":
			say(strings.ReplaceAll(fetch, "$TAG", tag))
			if hangup {
				return "hangup"
			}
		case cmd == "LOGOUT":
			say("* BYE bye\r\n" + tag + " OK done\r\n")
			return "logout"
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
// not from EOF, and well inside the store's own timeout. The guard also
// closes the connection: the server reads EOF, not a LOGOUT sent on a
// connection the client would otherwise leave open.
func TestReaderPanicFailsTheCall(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReaderPanicChild$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the child hung after the hostile reply:\n%s", tail(string(out), 1500))
	}
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
	addr, ended := hostile(t, bareFetch, false)
	s := hostileStore(t, addr, 30*time.Second)
	start := time.Now()
	_, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1})
	if err == nil {
		t.Fatal("a hostile FETCH reply was answered as success")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the call took %v: it waited out a timeout instead of failing on the guard", d)
	}
	select {
	case end := <-ended:
		if end != "eof" {
			t.Fatalf("the server saw %q, want the client to close the connection (eof)", end)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the connection was left open after the guarded panic")
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
// FETCH, the process lives. The server closes after its bytes, so no
// stream can complete the command (it cannot know the tag) and the error
// check only guards against a reply taken for success; it is not a check
// that replies are parsed correctly. The deadline bounds any that stall.
// It runs Store.Fetch's own steps (selectAt, then fetch) on a go-imap
// client over net.Pipe rather than a dialed socket: LOOP-7 replays this
// target in a jail whose network namespace has no usable loopback.
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
	f.Add("* 1 FETCH (UID 1 BODY[] " + strings.Repeat("(", 5000)) // deeper than the list bound (SR3-mail-k18b)
	s := hostileStore(f, "127.0.0.1:1", 3*time.Second)
	f.Fuzz(func(t *testing.T, stream string) {
		cl, sv := net.Pipe()
		go converse(sv, stream, true)
		cl.SetDeadline(time.Now().Add(3 * time.Second))
		c, err := client.New(cl)
		if err != nil {
			cl.Close()
			t.Fatalf("greeting: %v", err)
		}
		c.ErrorLog = quiet{}
		defer c.Logout()
		defer cl.Close()
		if err := c.Login("canary-user", "canary-secret"); err != nil {
			t.Fatalf("login: %v", err)
		}
		if err := selectAt(c, "INBOX", true, 7); err != nil {
			t.Fatalf("select: %v", err)
		}
		if _, err := s.fetch(c, "INBOX", 7, []uint32{1}); err == nil {
			t.Fatalf("stream %q was answered as success", stream)
		}
	})
}
