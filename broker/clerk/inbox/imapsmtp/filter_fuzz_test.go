package imapsmtp

// REQ: A5, CLK-3

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// The filter's safety argument, end to end (A5): the server runs only
// commands whose first line the filter read at a line start and allowed.
// It holds if the filter and the server agree where each command starts:
//  1. A command line ends in CRLF and holds no other CR (crlf), so the two
//     split lines alike.
//  2. A literal's bytes go only after the server's "+" (a synchronizing
//     literal; a non-synchronizing one is never passed, since a server
//     reads one only when its parser reaches it). A tagged answer first
//     ends the session. A server sending "+" is reading the literal.
//  3. The "+" is the server's own: the framer skips a server literal only
//     where the grammar allows one, so attacker text inside server data
//     (a message body) is never a line start; status and "+" text is text.
//     A line it cannot frame refuses every later literal. It trusts the
//     server to format its own data: quoted strings escaped, literals
//     counted.
//  4. Server lines start only where the server starts them: no CR or LF
//     reaches the server outside an APPEND's message, so even a server
//     echoing the client's words raw cannot start a line of theirs. What a
//     server echoes inside data is a fetch's items, which are atoms (no
//     quote, backslash or literal), so it cannot unbalance a quoted string
//     before a literal. A tag holds no "*", "+" or "{" (tagOK).
// APPEND's message may hold CRLF; only the old core sends one, and no
// server echoes a message.
// FuzzTheFilter drives the filter with arbitrary connection bytes against
// a server built to break that agreement, and checks point 1's result.

// hostileServer is a server written to break the filter's agreement with
// it, as real ones may. It reads a synchronizing literal only after its
// "+", and sends none when the verb takes no arguments or the line fails to
// parse (Dovecot); it reads a non-synchronizing literal under the same rule
// (LITERAL+, also Dovecot); it echoes a mailbox it cannot find, literal
// bytes and all, raw; and a fetch returns body, a literal of any bytes.
type hostileServer struct {
	body []byte
	mu   sync.Mutex
	ran  []string // each command's first line, as the server read it
}

func (s *hostileServer) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	// A command's answer waits until the next command line arrives, as on
	// a slow link, so it lands while the filter waits on a later literal;
	// the answer to a literal ("+" or a refusal) goes at once.
	pending := ""
	say := func(x string) { io.WriteString(c, pending+x); pending = "" }
	later := func(x string) { pending += x }
	defer func() { say("") }()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		say("")
		f := strings.Fields(line)
		if len(f) < 2 {
			later("* BAD Error in IMAP command: " + strings.TrimRight(line, "\r\n") + "\r\n")
			continue
		}
		tag, verb := f[0], strings.ToUpper(f[1])
		if verb == "UID" && len(f) > 2 {
			verb += " " + strings.ToUpper(f[2])
		}
		s.mu.Lock()
		s.ran = append(s.ran, line)
		s.mu.Unlock()
		// args is what follows the verb, quotes dropped, literals inline:
		// the name a server echoes.
		_, args, _ := strings.Cut(strings.TrimRight(line, "\r\n"), verb+" ")
		args = strings.ReplaceAll(args, `"`, "")
		for {
			n, ok := literal([]byte(line))
			if !ok {
				break
			}
			if verb == "NOOP" || verb == "CAPABILITY" || strings.Contains(line, ")") && !strings.Contains(line, "(") {
				// The parser stops before the literal, which it never
				// reads: its bytes are the next command.
				say(tag + " BAD Error in IMAP command\r\n")
				verb = ""
				break
			}
			if !nonSync([]byte(line)) {
				say("+ OK\r\n")
			}
			b := make([]byte, min(n, 1<<16))
			if _, err := io.ReadFull(r, b); err != nil {
				return
			}
			line, err = r.ReadString('\n')
			if err != nil {
				return
			}
			args += string(b) + strings.TrimRight(line, "\r\n")
		}
		switch verb {
		case "":
		case "SELECT", "EXAMINE":
			if args == "INBOX" {
				later("* 9 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n" + tag + " OK done\r\n")
			} else {
				later(tag + " NO [NONEXISTENT] Mailbox doesn't exist: " + args + "\r\n")
			}
		case "UID FETCH":
			later("* 1 FETCH (UID 1 BODY[] {" + strconv.Itoa(len(s.body)) + "}\r\n" + string(s.body) + ")\r\n" + tag + " OK done\r\n")
		default:
			later(tag + " BAD Error in IMAP command " + args + "\r\n")
		}
	}
}

func unixPair(t testing.TB) (*net.UnixConn, *net.UnixConn) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "pair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	return conn(fds[0]), conn(fds[1])
}

// filterRun relays client through a read request's filter to a
// hostileServer and returns the command lines the server ran.
func filterRun(t testing.TB, client, body []byte) []string {
	up, srvEnd := net.Pipe()
	local, peer := unixPair(t)
	ctrl, ctrlPeer := unixPair(t)
	defer ctrlPeer.Close()
	defer peer.Close()
	x := &session{up: up, ctrl: ctrl, local: local, closed: make(chan struct{}), downDone: make(chan struct{})}
	x.left.Store(1 << 40)
	x.allow.Store(&allowance{})
	srv := &hostileServer{body: body}
	served := make(chan struct{})
	go func() { srv.serve(srvEnd); close(served) }()
	go x.down(nil)
	filtered := make(chan struct{})
	go func() { x.filter(); close(filtered) }()
	go io.Copy(io.Discard, peer)
	peer.Write(client)
	peer.CloseWrite()
	select {
	case <-filtered:
	case <-time.After(2 * time.Second):
	}
	// net.Pipe is unbuffered: whatever the filter sent, the server read.
	x.teardown()
	<-served
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.ran
}

// FuzzTheFilter (A5): whatever a compromised connection process sends
// during a read, the server runs only commands a read allows.
func FuzzTheFilter(f *testing.F) {
	for _, s := range []string{
		"h1 NOOP {18}\r\nh2 UID EXPUNGE 1:*\r\n",
		"h1 NOOP {14+}\r\nh2 DELETE Keep\r\n",
		"h1 SELECT ) {14+}\r\nh2 DELETE Keep\r\n",
		"h1 SELECT {12}\r\nx\r\n+ planted\r\nh2 NOOP {18}\r\nh3 UID EXPUNGE 1:*\r\n",
		"h1 SELECT \"a{44}\"\r\nh1b SELECT \"+zz\"\r\nh2 NOOP {18}\r\nh3 UID EXPUNGE 1:*\r\n",
		"h1 UID FETCH 1 (BODY.PEEK[])\r\nh2 UID SEARCH HEADER X {9}\r\nh3 CLOSE\r\n",
		"h1 UID SEARCH SEEN\rh2 UID EXPUNGE 1:*\r\n",
		"h1 SELECT {3}\r\nabc\r\nh2 STATUS INBOX (UIDNEXT)\r\n",
	} {
		f.Add([]byte(s), []byte("+ OK\r\nh2 OK\r\n"))
	}
	f.Fuzz(func(t *testing.T, client, body []byte) {
		for _, line := range filterRun(t, client, body) {
			if _, ok := (&allowance{}).command([]byte(line)); !ok {
				t.Fatalf("the server ran %q", line)
			}
		}
	})
}

// TestALiteralHoldsNoLineBreak (A5; L3's #3018 delta repro): a CR LF in a
// literal's bytes would reach a server that echoes a mailbox name raw and
// put "+ planted" at a line start, where it would answer a later literal
// the server refused. A literal outside an APPEND's message holds none.
func TestALiteralHoldsNoLineBreak(t *testing.T) {
	name := "x\r\n+ planted"
	inner := "h3 UID EXPUNGE 1:*"
	ran := filterRun(t, []byte("h1 SELECT {"+strconv.Itoa(len(name))+"}\r\n"+name+"\r\nh2 NOOP {"+strconv.Itoa(len(inner))+"}\r\n"+inner+"\r\n"), nil)
	for _, l := range ran {
		if strings.Contains(l, "EXPUNGE") {
			t.Fatalf("the server ran %q", l)
		}
	}
	// The relay stops at the CR: the server never got the planted words.
	if len(ran) != 1 {
		t.Fatalf("ran %q", ran)
	}
}

// TestNoNonSynchronizingLiteral (A5; Security's #3018 delta, confirmed on
// Dovecot 2.3): a server that offers LITERAL+ still reads a {n+} literal
// only when its parser reaches it, so the filter passes none, and go-imap
// is not told of LITERAL+ or LITERAL-.
func TestNoNonSynchronizingLiteral(t *testing.T) {
	for _, first := range []string{"h1 NOOP {14+}\r\n", "h1 SELECT ) {14+}\r\n", "h1 UID SEARCH ) {14+}\r\n", "h1 SELECT {14+}\r\n"} {
		for _, l := range filterRun(t, []byte(first+"h2 DELETE Keep\r\n"), nil) {
			if strings.Contains(l, "DELETE") || strings.Contains(l, "{14+}") {
				t.Errorf("%q: the server ran %q", first, l)
			}
		}
	}
	g := greeting(map[string]bool{"IMAP4rev1": true, "LITERAL+": true, "LITERAL-": true, "MOVE": true})
	if strings.Contains(g, "LITERAL") || !strings.Contains(g, "MOVE") {
		t.Fatalf("greeting %q", g)
	}
}

// TestTheReproductionsOnDovecot runs the #3018 reviews' attacks through the
// clerk against a real Dovecot, where one is installed: set DOVECOT_CONF
// to a configuration whose mail belongs to nobody (the PR's notes). Each
// would delete the folder Keep or expunge INBOX if it got through.
func TestTheReproductionsOnDovecot(t *testing.T) {
	conf := os.Getenv("DOVECOT_CONF")
	if conf == "" {
		t.Skip("no Dovecot (DOVECOT_CONF unset)")
	}
	run := func(stdin io.Reader, stdout io.Writer) {
		cmd := exec.Command("/usr/lib/dovecot/imap", "-c", conf)
		cmd.Env = []string{"USER=nobody", "HOME=" + os.TempDir()}
		cmd.Stdin, cmd.Stdout = stdin, stdout
		cmd.Run()
	}
	script := func(s string) string {
		var out bytes.Buffer
		run(strings.NewReader(s), &out)
		return out.String()
	}
	l := listenLoopback(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); run(c, c) }()
		}
	}()
	name := "x\r\n+ planted"
	prefix := "h1b NO [NONEXISTENT] Mailbox doesn't exist: "
	for _, attack := range []struct{ name, first, then string }{
		{"a refused literal", "h1 NOOP {14}\r\n", "h2 DELETE Keep\r\n"},
		{"a non-synchronizing literal on NOOP", "h1 NOOP {14+}\r\n", "h2 DELETE Keep\r\n"},
		{"a non-synchronizing literal after a parse error", "h1 SELECT ) {14+}\r\n", "h2 DELETE Keep\r\n"},
		{"a CR LF in a literal", "h1 SELECT {" + strconv.Itoa(len(name)) + "}\r\n" + name + "\r\n", "h2 NOOP {14}\r\nh3 DELETE Keep\r\n"},
		{"an echoed {n}", `h1 SELECT "a{` + strconv.Itoa(len(prefix)) + `}"` + "\r\n", "h1b SELECT \"+zz\"\r\nh2 NOOP {14}\r\nh3 DELETE Keep\r\n"},
	} {
		script("a CREATE Keep\r\nz LOGOUT\r\n")
		conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
			io.WriteString(w, attack.first)
			time.Sleep(50 * time.Millisecond)
			io.WriteString(w, attack.then)
			time.Sleep(200 * time.Millisecond)
			io.WriteString(w, "h4 NOOP\r\n")
			tagged(br, "h4")
			answer(ctrl, imapwire.Response{Validity: 7})
		})
		_, _, err := hostileClerk(t, l.Addr().String(), conn, 5*time.Second).UIDs(context.Background(), "INBOX")
		if !strings.Contains(script("c LIST \"\" *\r\nz LOGOUT\r\n"), "Keep") {
			t.Errorf("%s: a read deleted the folder Keep (err %v)", attack.name, err)
		}
		if err == nil {
			t.Errorf("%s: the session ended clean", attack.name)
		}
	}
}
