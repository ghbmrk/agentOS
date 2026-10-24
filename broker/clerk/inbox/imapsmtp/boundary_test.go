package imapsmtp

// REQ: KRN-2, CLK-1, CLK-3, A5, CRED-1

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	goutf7 "github.com/emersion/go-imap/utf7"

	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// recorder keeps every byte that crossed between the clerk and its
// connection process, both ways, and what each process was started with.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *recorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

// recvFD is the descriptor passed with the next message on c.
func recvFD(c *net.UnixConn) (int, error) {
	b, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := c.ReadMsgUnix(b, oob)
	if err != nil {
		return -1, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return -1, errors.New("no descriptor")
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return -1, errors.New("no descriptor")
	}
	return fds[0], nil
}

func fdConn(t testing.TB, fd int) net.Conn {
	f := os.NewFile(uintptr(fd), "fd")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		t.Error(err)
	}
	return c
}

// relay copies a to b and b to a, each way into rec, until both end.
func relay(a, b net.Conn, rec io.Writer) {
	var wg sync.WaitGroup
	for _, p := range [][2]net.Conn{{a, b}, {b, a}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(io.MultiWriter(p[1], rec), p[0])
			if u, ok := p[1].(*net.UnixConn); ok {
				u.CloseWrite()
			}
		}()
	}
	wg.Wait()
	a.Close()
	b.Close()
}

// spied is a Conn that stands between the clerk and each connection
// process start starts on its control end, and records every byte on the
// control connection and on the passed stream.
func spied(t testing.TB, rec *recorder, start func(ctrl *net.UnixConn)) func(context.Context) (*net.UnixConn, error) {
	return func(context.Context) (*net.UnixConn, error) {
		clerk, mid, err := imapconn.Socketpair()
		if err != nil {
			return nil, err
		}
		mid2, child, err := imapconn.Socketpair()
		if err != nil {
			return nil, err
		}
		start(child)
		go func() {
			fd, err := recvFD(mid)
			if err != nil {
				mid.Close()
				mid2.Close()
				return
			}
			stream := fdConn(t, fd)
			mine, theirs, err := imapconn.Socketpair()
			if err != nil {
				return
			}
			f, _ := theirs.File()
			mid2.WriteMsgUnix([]byte{0}, syscall.UnixRights(int(f.Fd())), nil)
			f.Close()
			theirs.Close()
			go relay(stream, mine, rec)
			relay(mid, mid2, rec)
		}()
		return clerk, nil
	}
}

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// imapconnBinary is the connection process's binary, built once.
func imapconnBinary(t testing.TB) string {
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "imapconn")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "imapconn")
		out, err := exec.Command("go", "build", "-o", binPath, "github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn/cmd/imapconn").CombinedOutput()
		if err != nil {
			binErr = errors.New(string(out))
		}
	})
	if binErr != nil {
		t.Fatalf("building imapconn: %v", binErr)
	}
	return binPath
}

// child starts the built connection process on ctrl, through childproc
// with an empty environment, as fd 3, and records its argv and
// environment into rec.
func child(t testing.TB, rec io.Writer) func(ctrl *net.UnixConn) {
	bin := imapconnBinary(t)
	return func(ctrl *net.UnixConn) {
		f, err := ctrl.File()
		ctrl.Close()
		if err != nil {
			t.Error(err)
			return
		}
		env := childproc.NewEnv()
		cmd := childproc.Command(context.Background(), env, childproc.Options{ExtraFiles: []*os.File{f}}, bin)
		io.WriteString(rec, bin+"\x00")
		if err := cmd.Start(); err != nil {
			t.Error(err)
		}
		f.Close()
		go cmd.Wait()
	}
}

// TestTheConnectionNeverSeesTheCredential (CLK-1, A5): a full read, mark,
// move and seen run against the test server, signed in with a canary
// password and then a canary XOAUTH2 token, through the built connection
// process. Neither canary, nor any encoding of a sign-in carrying it,
// crosses the control connection or the passed stream either way, or is
// in the process's argv or environment.
func TestTheConnectionNeverSeesTheCredential(t *testing.T) {
	for _, oauth := range []bool{false, true} {
		rec := &recorder{}
		srv := imaptest.Start(t)
		srv.AddFolder("Archive", `\Archive`)
		srv.Deliver("INBOX", "From: a@example.test\nMessage-ID: <one@example.test>\nSubject: one\n\nhello\n", `\Seen`)
		srv.Deliver("INBOX", "From: b@example.test\nMessage-ID: <two@example.test>\nSubject: two\n\nhello\n")
		login := Login{User: imaptest.User, Secret: imaptest.Password}
		if oauth {
			login = Login{User: imaptest.User, Secret: imaptest.Token, OAuth: true}
		}
		s, err := New(Config{Conn: spied(t, rec, child(t, rec)), IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: Plain, SMTPSec: Plain,
			From: imaptest.User, Timeout: 20 * time.Second, Credential: func(context.Context) (Login, error) { return login, nil }})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if _, err := s.Folders(ctx); err != nil {
			t.Fatal(err)
		}
		v, uids, err := s.UIDs(ctx, "INBOX")
		if err != nil || len(uids) != 2 {
			t.Fatalf("uids %v %v", uids, err)
		}
		if ms, err := s.Fetch(ctx, "INBOX", v, uids); err != nil || len(ms) != 2 {
			t.Fatalf("fetch %d %v", len(ms), err)
		}
		n := 0
		if err := s.Seen(ctx, "INBOX", func([]byte, time.Time) error { n++; return nil }); err != nil || n != 1 {
			t.Fatalf("seen %d %v", n, err)
		}
		if _, err := s.Marks(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFlags(ctx, Ref{Folder: "INBOX", Validity: v, UID: uids[1]}, []string{`\Flagged`}, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.Move(ctx, Ref{Folder: "INBOX", Validity: v, UID: uids[1]}, "Archive"); err != nil {
			t.Fatal(err)
		}
		if ms, err := s.Find(ctx, "Archive", "<two@example.test>", func(Message) bool { return true }); err != nil || len(ms) != 1 {
			t.Fatalf("find %d %v", len(ms), err)
		}
		time.Sleep(100 * time.Millisecond) // the last relays drain
		all := rec.String()
		if !strings.Contains(all, "PREAUTH") || !strings.Contains(all, "UID FETCH") {
			t.Fatalf("the recorder saw no session:\n%.400q", all)
		}
		for _, secret := range []string{imaptest.Password, imaptest.Token} {
			for _, enc := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)),
				base64.StdEncoding.EncodeToString([]byte("\x00" + imaptest.User + "\x00" + secret)),
				base64.StdEncoding.EncodeToString(xoauth2{imaptest.User, secret}.ir())} {
				if strings.Contains(all, enc) {
					t.Fatalf("oauth %v: the connection process saw %q", oauth, enc)
				}
			}
		}
		if srv.Logins()[len(srv.Logins())-1] == "" {
			t.Fatal("no sign-in")
		}
	}
}

// logServer is a raw IMAP server that signs in anything, selects any folder
// at validity 7 with UIDs 1 and 2, answers each command OK, reads {n} and
// {n+} literals by count (answering "+" to a synchronizing one), and logs
// each whole command it received, literals included. A UID FETCH with
// flood set floods the reply instead.
type logServer struct {
	addr string
	mu   sync.Mutex
	cmds []string
}

func newLogServer(t testing.TB) *logServer {
	l := listenLoopback(t)
	s := &logServer{addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *logServer) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	w := bufio.NewWriter(c)
	say := func(x string) { w.WriteString(x); w.Flush() }
	say("* OK [CAPABILITY IMAP4rev1 MOVE LITERAL+] ready\r\n")
	r := bufio.NewReader(c)
	for {
		var cmd strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd.WriteString(line)
			n, ok := literal([]byte(line))
			if !ok {
				break
			}
			if !strings.HasSuffix(strings.TrimRight(line, "\r\n"), "+}") {
				say("+ go on\r\n")
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(r, b); err != nil {
				return
			}
			cmd.Write(b)
		}
		line := cmd.String()
		s.mu.Lock()
		s.cmds = append(s.cmds, line)
		s.mu.Unlock()
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		tag, verb := f[0], strings.ToUpper(f[1])
		switch verb {
		case "SELECT", "EXAMINE":
			say("* 2 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n* OK [UIDNEXT 3] n\r\n" + tag + " OK done\r\n")
		case "LOGOUT":
			say("* BYE\r\n" + tag + " OK done\r\n")
			return
		default:
			say(tag + " OK done\r\n")
		}
	}
}

// saw says whether the server received a command holding each of parts.
func (s *logServer) saw(parts ...string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(strings.ToUpper(c), strings.ToUpper(p))
		}
		if ok {
			return true
		}
	}
	return false
}

// hostileConn is a Conn whose connection process is a test double speaking
// raw IMAP: for each request it runs act over the passed stream and the
// control connection, after reading the PREAUTH greeting.
func hostileConn(t testing.TB, act func(n int, q imapwire.Request, stream *bufio.Reader, w net.Conn, ctrl *net.UnixConn)) func(context.Context) (*net.UnixConn, error) {
	return func(context.Context) (*net.UnixConn, error) {
		clerk, theirs, err := imapconn.Socketpair()
		if err != nil {
			return nil, err
		}
		go func() {
			defer theirs.Close()
			fd, err := recvFD(theirs)
			if err != nil {
				return
			}
			stream := fdConn(t, fd)
			defer stream.Close()
			br := bufio.NewReader(stream)
			if g, _ := br.ReadString('\n'); !strings.HasPrefix(g, "* PREAUTH") {
				t.Errorf("greeting %q", g)
				return
			}
			for n := 0; ; n++ {
				var q imapwire.Request
				if imapwire.Read(theirs, 64<<20, &q) != nil {
					return
				}
				act(n, q, br, stream, theirs)
			}
		}()
		return clerk, nil
	}
}

// tagged reads stream to the tagged answer to tag.
func tagged(br *bufio.Reader, tag string) error {
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(l, tag+" ") {
			return nil
		}
	}
}

// answer writes r as the double's answer.
func answer(ctrl *net.UnixConn, r imapwire.Response) { imapwire.Write(ctrl, r) }

func hostileClerk(t testing.TB, addr string, conn func(context.Context) (*net.UnixConn, error), timeout time.Duration) *Store {
	s, err := New(Config{Conn: conn, IMAP: addr, SMTP: addr, IMAPSec: Plain, SMTPSec: Plain, From: "o@example.test", Timeout: timeout,
		Credential: func(context.Context) (Login, error) { return Login{User: "canary-user", Secret: "canary-secret"}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestTheFilterRefusesUndeclaredCommands (A5, CLK-3): a compromised
// connection process that sends a command its request does not need ends
// the session with ErrConnRefused, and the server never receives it: it
// cannot expunge, close, delete, append, mark mail read in a read, set a
// flag in a read, set a flag the request did not ask for, or move a UID it
// was not asked to.
func TestTheFilterRefusesUndeclaredCommands(t *testing.T) {
	type call func(s *Store) error
	readCall := func(s *Store) error { _, _, err := s.UIDs(context.Background(), "INBOX"); return err }
	flagCall := func(s *Store) error {
		return s.SetFlags(context.Background(), Ref{Folder: "INBOX", Validity: 7, UID: 1}, []string{`\Flagged`}, nil)
	}
	moveCall := func(s *Store) error {
		return s.Move(context.Background(), Ref{Folder: "INBOX", Validity: 7, UID: 5}, "Trash")
	}
	for _, c := range []struct {
		name, cmd string
		call      call
	}{
		{"EXPUNGE", "EXPUNGE", readCall},
		{"CLOSE", "CLOSE", readCall},
		{"DELETE", "DELETE INBOX", readCall},
		{"APPEND", "APPEND INBOX {3+}\r\nabc", readCall},
		{"RENAME", "RENAME INBOX Old", readCall},
		{"COPY", "UID COPY 1 Trash", readCall},
		{"IDLE", "IDLE", readCall},
		{"STARTTLS", "STARTTLS", readCall},
		{"LOGIN", "LOGIN a b", readCall},
		{"plain FETCH", "FETCH 1 (BODY[])", readCall},
		{"non-PEEK BODY[] in a read", "UID FETCH 1 (UID BODY[])", readCall},
		{"non-PEEK BODY[TEXT] in a read", "UID FETCH 1 (body[text])", readCall},
		{"RFC822 in a read", "UID FETCH 1 (UID RFC822)", readCall},
		{"RFC822.TEXT in a read", "UID FETCH 1 RFC822.TEXT", readCall},
		{"BINARY[] in a read", "UID FETCH 1 (BINARY[1])", readCall},
		{"UID STORE in a read", `UID STORE 1 +FLAGS.SILENT (\Seen)`, readCall},
		{"UID MOVE in a read", "UID MOVE 1 Trash", readCall},
		{"another flag on the asked UID", `UID STORE 1 +FLAGS.SILENT (\Deleted)`, flagCall},
		{"the asked flag on another UID", `UID STORE 2 +FLAGS.SILENT (\Flagged)`, flagCall},
		{"the asked flag as a set", `UID STORE 1:2 +FLAGS.SILENT (\Flagged)`, flagCall},
		{"UID MOVE in a flag", "UID MOVE 1 Trash", flagCall},
		{"a UID MOVE of a UID not asked for", `UID MOVE 6 "Trash"`, moveCall},
		{"a UID MOVE of a range", `UID MOVE 5:6 "Trash"`, moveCall},
		{"the asked UID moved elsewhere", `UID MOVE 5 "Archive"`, moveCall},
		{"the asked UID moved, unquoted", "UID MOVE 5 Trash", moveCall},
		{"a second SELECT in a move", "SELECT Private", moveCall},
		{"a second SELECT of the same folder", "SELECT INBOX", moveCall},
		{"an EXAMINE in a flag", "EXAMINE Private", flagCall},
		{"UID STORE in a move", `UID STORE 5 +FLAGS.SILENT (\Deleted)`, moveCall},
		{"EXPUNGE in a move", "EXPUNGE", moveCall},
		{"an untagged command", "* NOOP", readCall},
	} {
		srv := newLogServer(t)
		conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
			selectFirst(q, br, w)
			io.WriteString(w, "h1 "+c.cmd+"\r\n")
			// A filter that passed it lets the server answer.
			tagged(br, "h1")
			answer(ctrl, imapwire.Response{Validity: 7})
		})
		err := c.call(hostileClerk(t, srv.addr, conn, 5*time.Second))
		if !errors.Is(err, ErrConnRefused) {
			t.Errorf("%s: err %v, want ErrConnRefused", c.name, err)
		}
		verb := strings.Fields(strings.TrimPrefix(c.cmd, "UID "))[0]
		if srv.saw("h1 ", verb) {
			t.Errorf("%s: the server received it", c.name)
		}
	}
	// The same double, sending only what each request needs, passes.
	for name, c := range map[string]struct {
		cmd  string
		call call
	}{
		"a peek fetch":     {"UID FETCH 1:2 (UID FLAGS BODY.PEEK[]<0.262144>)", readCall},
		"a header fetch":   {"UID FETCH 1 (UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (From Message-Id)]<0.8193>)", readCall},
		"the asked store":  {`UID STORE 1 +FLAGS.SILENT (\Flagged)`, flagCall},
		"the asked move":   {`UID MOVE 5 "Trash"`, moveCall},
		"a search":         {"UID SEARCH SEEN", readCall},
		"a status":         {"STATUS INBOX (UIDNEXT)", moveCall},
		"RFC822.SIZE":      {"UID FETCH 1 (RFC822.SIZE)", readCall},
		"RFC822.HEADER":    {"UID FETCH 1 (RFC822.HEADER)", readCall},
		"a capability ask": {"CAPABILITY", readCall},
	} {
		srv := newLogServer(t)
		conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
			selectFirst(q, br, w)
			io.WriteString(w, "h1 "+c.cmd+"\r\n")
			tagged(br, "h1")
			answer(ctrl, imapwire.Response{Validity: 7})
		})
		if err := c.call(hostileClerk(t, srv.addr, conn, 5*time.Second)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !srv.saw("h1 ") {
			t.Errorf("%s: the server did not receive it", name)
		}
	}
}

// selectFirst makes a write request's one SELECT, of its own folder, as
// go-imap would.
func selectFirst(q imapwire.Request, br *bufio.Reader, w net.Conn) {
	if q.Op == imapwire.OpSetFlags || q.Op == imapwire.OpMove {
		io.WriteString(w, "h0 SELECT "+selectArg(q.Folder)+"\r\n")
		tagged(br, "h0")
	}
}

// TestWritesStayInTheirFolder (A5, CLK-3; Security's #3018 repro): a
// store or a move acts only after the one SELECT of the request's folder.
// A connection that selects another folder first, or stores or moves
// before selecting, is refused, and the server never sees the write.
func TestWritesStayInTheirFolder(t *testing.T) {
	for _, c := range []struct{ name, script string }{
		{"a move in another folder", "h1 SELECT Private\r\n"},
		{"a move in another folder, quoted", "h1 SELECT \"Private\"\r\n"},
		{"a move after an EXAMINE", "h1 EXAMINE INBOX\r\n"},
		{"a move before any SELECT", ""},
	} {
		srv := newRFCServer(t)
		conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
			if c.script != "" {
				io.WriteString(w, c.script)
				if tagged(br, "h1") != nil {
					return
				}
			}
			io.WriteString(w, "h2 UID MOVE 5 \"Trash\"\r\n")
			tagged(br, "h2")
			answer(ctrl, imapwire.Response{})
		})
		err := hostileClerk(t, srv.addr, conn, 5*time.Second).Move(context.Background(), Ref{Folder: "INBOX", Validity: 7, UID: 5}, "Trash")
		if !errors.Is(err, ErrConnRefused) || strings.Contains(srv.log(), "MOVE") {
			t.Errorf("%s: err %v, server log %s", c.name, err, srv.log())
		}
	}
	srv := newRFCServer(t)
	conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		io.WriteString(w, "h1 SELECT Private\r\n")
		tagged(br, "h1")
		io.WriteString(w, `h2 UID STORE 1 +FLAGS.SILENT (\Flagged)`+"\r\n")
		tagged(br, "h2")
		answer(ctrl, imapwire.Response{})
	})
	err := hostileClerk(t, srv.addr, conn, 5*time.Second).SetFlags(context.Background(), Ref{Folder: "INBOX", Validity: 7, UID: 1}, []string{`\Flagged`}, nil)
	if !errors.Is(err, ErrConnRefused) || strings.Contains(srv.log(), "STORE") {
		t.Errorf("a store in another folder: err %v, server log %s", err, srv.log())
	}
	srv = newRFCServer(t)
	conn = hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		io.WriteString(w, `h2 UID STORE 1 +FLAGS.SILENT (\Flagged)`+"\r\n")
		tagged(br, "h2")
		answer(ctrl, imapwire.Response{})
	})
	err = hostileClerk(t, srv.addr, conn, 5*time.Second).SetFlags(context.Background(), Ref{Folder: "INBOX", Validity: 7, UID: 1}, []string{`\Flagged`}, nil)
	if !errors.Is(err, ErrConnRefused) || strings.Contains(srv.log(), "STORE") {
		t.Errorf("a store before any SELECT: err %v, server log %s", err, srv.log())
	}
	// A folder go-imap writes in modified UTF-7 and quoted is matched as
	// written, so the honest write passes.
	srv = newRFCServer(t)
	conn = hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		io.WriteString(w, `h1 SELECT "Entw&APw-rfe"`+"\r\n")
		tagged(br, "h1")
		io.WriteString(w, `h2 UID MOVE 5 "&ZeVnLIqe-"`+"\r\n")
		tagged(br, "h2")
		answer(ctrl, imapwire.Response{})
	})
	if err := hostileClerk(t, srv.addr, conn, 5*time.Second).Move(context.Background(), Ref{Folder: "Entwürfe", Validity: 7, UID: 5}, "日本語"); err != nil {
		t.Errorf("an honest move between non-ASCII folders: %v (%s)", err, srv.log())
	}
}

// TestALiteralWaitsForTheServer (A5; Security's and L3's #3018 repro): a
// synchronizing literal's bytes go only after the server's "+". A server
// that refuses the literal with a tagged answer reads what follows as a new
// command (RFC 3501 7.5), so a literal sent at once could smuggle one; the
// session ends instead. A non-synchronizing literal passes only where the
// server must read it (LITERAL+), and a bare CR inside a line is refused.
func TestALiteralWaitsForTheServer(t *testing.T) {
	inner := "h2 UID EXPUNGE 1:*\r\n"
	srv := newRFCServer(t)
	conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		io.WriteString(w, "h1 NOOP {"+strconv.Itoa(len(inner))+"}\r\n"+inner)
		tagged(br, "h2")
		answer(ctrl, imapwire.Response{Validity: 7})
	})
	_, _, err := hostileClerk(t, srv.addr, conn, 5*time.Second).UIDs(context.Background(), "INBOX")
	if err == nil || strings.Contains(srv.log(), "EXPUNGE") {
		t.Fatalf("a refused literal: err %v, server log %s", err, srv.log())
	}
	// Without LITERAL+ a non-synchronizing literal is refused outright.
	srv = newRFCServer(t)
	conn = hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		io.WriteString(w, "h1 NOOP {"+strconv.Itoa(len(inner))+"+}\r\n"+inner)
		tagged(br, "h2")
		answer(ctrl, imapwire.Response{Validity: 7})
	})
	_, _, err = hostileClerk(t, srv.addr, conn, 5*time.Second).UIDs(context.Background(), "INBOX")
	if !errors.Is(err, ErrConnRefused) || strings.Contains(srv.log(), "EXPUNGE") || strings.Contains(srv.log(), "h1 NOOP") {
		t.Fatalf("a non-synchronizing literal without LITERAL+: err %v, server log %s", err, srv.log())
	}
	// A bare CR inside a command line.
	srv = newRFCServer(t)
	conn = hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		io.WriteString(w, "h1 UID SEARCH SEEN\rh2 UID EXPUNGE 1:*\r\n")
		tagged(br, "h2")
		answer(ctrl, imapwire.Response{Validity: 7})
	})
	_, _, err = hostileClerk(t, srv.addr, conn, 5*time.Second).UIDs(context.Background(), "INBOX")
	if !errors.Is(err, ErrConnRefused) || strings.Contains(srv.log(), "EXPUNGE") {
		t.Fatalf("a bare CR: err %v, server log %s", err, srv.log())
	}
}

// rfcServer follows RFC 3501 7.5: it rejects every synchronizing literal
// with a tagged BAD instead of "+", and then reads the next bytes as a new
// command. It offers no LITERAL+. It logs each command with the folder
// selected when it ran.
type rfcServer struct {
	addr string
	mu   sync.Mutex
	cmds []string
}

func newRFCServer(t *testing.T) *rfcServer {
	l := listenLoopback(t)
	s := &rfcServer{addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *rfcServer) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	say := func(x string) { io.WriteString(c, x) }
	say("* OK [CAPABILITY IMAP4rev1 MOVE] ready\r\n")
	r := bufio.NewReader(c)
	sel := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		tag, verb := f[0], strings.ToUpper(f[1])
		if _, ok := literal([]byte(line)); ok && !nonSync([]byte(line)) {
			say(tag + " BAD literal refused\r\n")
			continue
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, "["+sel+"] "+strings.TrimRight(line, "\r\n"))
		s.mu.Unlock()
		switch verb {
		case "SELECT", "EXAMINE":
			sel = f[2]
			say("* 9 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n* OK [UIDNEXT 30] n\r\n" + tag + " OK done\r\n")
		default:
			say(tag + " OK done\r\n")
		}
	}
}

func (s *rfcServer) log() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.cmds, " | ")
}

// The clerk's modified UTF-7 is go-imap's, byte for byte, so a write's
// folder is matched exactly as go-imap writes it.
func TestMailboxNamesEncodeAsGoIMAPDoes(t *testing.T) {
	for _, n := range []string{"INBOX", "inbox", "Trash", "A&B", "&", "Entwürfe", "日本語", "a 日 b", "😀 smile", "~peter/mail/台北/日本語",
		"\x01ctl", "[Gmail]/All Mail", `quote"back\`, "a\x7f", ""} {
		want, _ := goutf7.Encoding.NewEncoder().String(n)
		if got := utf7(n); got != want {
			t.Errorf("%q: %q, go-imap %q", n, got, want)
		}
	}
	if selectArg("INBOX") != "INBOX" || selectArg("Trash") != `"Trash"` || mailboxArg("INBOX") != `"INBOX"` {
		t.Fatal("quoting differs from go-imap's")
	}
}

// TestTheFilterCountsLiterals (A5): bytes inside a {n} or {n+} literal
// are data, even when they spell a command, and the command after the
// literal is still filtered. A literal counted one byte short or long
// desynchronises the filter, which then refuses the honest command: a
// command line ends in CRLF, never a bare LF.
func TestTheFilterCountsLiterals(t *testing.T) {
	for _, sync := range []string{"+", ""} {
		const inner = "h3 EXPUNGE\r\n" // 12 bytes
		srv := newLogServer(t)
		conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
			first := "h1 UID SEARCH HEADER Message-Id {" + strconv.Itoa(len(inner)) + sync + "}\r\n"
			if sync == "" {
				io.WriteString(w, first)
				br.ReadString('\n') // "+ go on"
				io.WriteString(w, inner+"\r\n")
			} else {
				io.WriteString(w, first+inner+"\r\n")
			}
			if tagged(br, "h1") != nil {
				return
			}
			io.WriteString(w, "h2 EXPUNGE\r\n")
			tagged(br, "h2")
			answer(ctrl, imapwire.Response{Validity: 7})
		})
		_, _, err := hostileClerk(t, srv.addr, conn, 5*time.Second).UIDs(context.Background(), "INBOX")
		if !errors.Is(err, ErrConnRefused) {
			t.Fatalf("sync %q: err %v, want ErrConnRefused for h2", sync, err)
		}
		if !srv.saw("h1 UID SEARCH", inner) {
			t.Fatalf("sync %q: the command with a literal never reached the server", sync)
		}
		if srv.saw("h2 EXPUNGE") {
			t.Fatalf("sync %q: the command after the literal passed", sync)
		}
	}
}

// TestALyingConnectionIsBounded (KRN-2): the clerk trusts nothing the
// connection process answers. An oversize frame, a message in another
// folder or validity, a UID not asked for or twice, more messages than
// asked, a body past MaxFetch, a header past headMax, a long header for a
// mail not in the batch, a folder with an unknown role, unsorted marks, or
// an unknown error code each fail closed with a bounded error; a process
// that never answers fails at the timeout.
func TestALyingConnectionIsBounded(t *testing.T) {
	msg := func(folder string, validity, uid uint32, raw int) imapwire.Message {
		return imapwire.Message{Ref: imapwire.Ref{Folder: folder, Validity: validity, UID: uid}, Raw: bytes.Repeat([]byte("x"), raw)}
	}
	fetch := func(s *Store) error { _, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1, 2}); return err }
	findSince := func(s *Store) error {
		_, err := s.FindSince(context.Background(), "INBOX", 7, 5, "<a@x>", func(Message) bool { return true })
		return err
	}
	seen := func(s *Store) error {
		return s.Seen(context.Background(), "INBOX", func([]byte, time.Time) error { return nil })
	}
	type answerFn func(ctrl *net.UnixConn, q imapwire.Request)
	frame := func(r imapwire.Response) answerFn {
		return func(ctrl *net.UnixConn, _ imapwire.Request) { answer(ctrl, r) }
	}
	for _, c := range []struct {
		name string
		call func(*Store) error
		act  answerFn
		want error
	}{
		{"an oversize frame", fetch, func(ctrl *net.UnixConn, _ imapwire.Request) {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], 1<<31)
			ctrl.Write(n[:])
		}, errLied},
		{"not JSON", fetch, func(ctrl *net.UnixConn, _ imapwire.Request) { ctrl.Write([]byte{0, 0, 0, 2, '{', '{'}) }, errLied},
		{"another folder", fetch, frame(imapwire.Response{Messages: []imapwire.Message{msg("Archive", 7, 1, 1)}}), errLied},
		{"another validity", fetch, frame(imapwire.Response{Messages: []imapwire.Message{msg("INBOX", 8, 1, 1)}}), errLied},
		{"a UID not asked for", fetch, frame(imapwire.Response{Messages: []imapwire.Message{msg("INBOX", 7, 3, 1)}}), errLied},
		{"a UID twice", fetch, frame(imapwire.Response{Messages: []imapwire.Message{msg("INBOX", 7, 1, 1), msg("INBOX", 7, 1, 1)}}), errLied},
		{"more than asked", fetch, frame(imapwire.Response{Messages: []imapwire.Message{msg("INBOX", 7, 1, 1), msg("INBOX", 7, 2, 1), msg("INBOX", 7, 3, 1)}}), errLied},
		{"a body past MaxFetch", fetch, frame(imapwire.Response{Messages: []imapwire.Message{msg("INBOX", 7, 1, 256<<10+1)}}), errLied},
		{"a flag that is no atom", fetch, frame(imapwire.Response{Messages: []imapwire.Message{{Ref: imapwire.Ref{Folder: "INBOX", Validity: 7, UID: 1}, Flags: []string{"a b"}}}}), errLied},
		{"a find before from", findSince, frame(imapwire.Response{Validity: 7, Messages: []imapwire.Message{msg("INBOX", 7, 4, 1)}}), errLied},
		{"a find at another validity", findSince, frame(imapwire.Response{Validity: 8}), errLied},
		{"a header past headMax", seen, func(ctrl *net.UnixConn, q imapwire.Request) {
			if q.Op == imapwire.OpSeenSearch {
				answer(ctrl, imapwire.Response{UIDs: []uint32{1}})
				return
			}
			answer(ctrl, imapwire.Response{Heads: []imapwire.Head{{UID: 1, Header: bytes.Repeat([]byte("x"), headMax+1)}}})
		}, errLied},
		{"a header not in the batch", seen, func(ctrl *net.UnixConn, q imapwire.Request) {
			if q.Op == imapwire.OpSeenSearch {
				answer(ctrl, imapwire.Response{UIDs: []uint32{1}})
				return
			}
			answer(ctrl, imapwire.Response{Heads: []imapwire.Head{{UID: 2, Header: []byte("From: a")}}})
		}, errLied},
		{"a long header not in the batch", seen, func(ctrl *net.UnixConn, q imapwire.Request) {
			if q.Op == imapwire.OpSeenSearch {
				answer(ctrl, imapwire.Response{UIDs: []uint32{1}})
				return
			}
			answer(ctrl, imapwire.Response{Err: "longheader", Long: &imapwire.LongHeaderError{UID: 9}})
		}, errLied},
		{"an unknown role", func(s *Store) error { _, err := s.Folders(context.Background()); return err },
			frame(imapwire.Response{Folders: []imapwire.Folder{{Name: "INBOX", Role: "owner"}}}), errLied},
		{"unsorted marks", func(s *Store) error { _, err := s.Marks(context.Background()); return err },
			frame(imapwire.Response{Marks: []imapwire.Mark{{Folder: "b"}, {Folder: "a"}}}), errLied},
		{"an unknown code", fetch, frame(imapwire.Response{Err: "success"}), imapwire.ErrFailed},
		{"no answer", fetch, func(*net.UnixConn, imapwire.Request) {}, ErrTimeout},
	} {
		srv := newLogServer(t)
		conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) { c.act(ctrl, q) })
		start := time.Now()
		err := c.call(hostileClerk(t, srv.addr, conn, time.Second))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.want)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: took %v, past the timeout", c.name, d)
		}
	}
}

// TestTheBudgetIsTheClerks (KRN-2): the reply budget is counted and
// renewed on this side only. A server that floods a fetch's reply fails
// the call with ErrReplyTooLarge, however eagerly the connection process
// reads, and however many commands it sends to look busy: only the
// clerk's next typed request renews it.
func TestTheBudgetIsTheClerks(t *testing.T) {
	addr, wrote := flood(t, "* 1 FETCH (UID 1 BODY[] {4000000000}\r\n", strings.Repeat("x", 64<<10))
	conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		io.WriteString(w, "h1 UID FETCH 1 (UID BODY.PEEK[])\r\n")
		buf := make([]byte, 64<<10)
		for i := 0; ; i++ {
			if _, err := io.ReadFull(br, buf); err != nil {
				break
			}
			io.WriteString(w, "n"+strconv.Itoa(i)+" NOOP\r\n")
		}
		answer(ctrl, imapwire.Response{})
	})
	s := hostileClerk(t, addr, conn, 8*time.Second)
	s.replyBase = 1 << 20
	s.cfg.MaxFetch = 4 << 10
	start := time.Now()
	_, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1})
	if !errors.Is(err, ErrReplyTooLarge) {
		t.Fatalf("err %v, want ErrReplyTooLarge", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v: the flood ran to the timeout", d)
	}
	if n := <-wrote; n > s.replyBudget(1)+32<<20 {
		t.Fatalf("the server wrote %d bytes before the clerk hung up; budget %d", n, s.replyBudget(1))
	}
}

// New refuses a Config with no connection process: there is no
// in-process fallback that would put the parser back in the clerk.
func TestNewNeedsTheConnectionProcess(t *testing.T) {
	_, err := New(Config{IMAP: "127.0.0.1:1", SMTP: "127.0.0.1:1", IMAPSec: Plain, SMTPSec: Plain, From: "o@example.test",
		Credential: func(context.Context) (Login, error) { return Login{}, nil }})
	if err == nil {
		t.Fatal("New took a Config without Conn")
	}
}

// FuzzPreauth (CLK-1): whatever a server sends before sign-in, the clerk's
// pre-auth reader never panics, never reads a line past preauthLine bytes
// or more than preauthLines lines, and refuses a literal.
func FuzzPreauth(f *testing.F) {
	for _, s := range []string{
		"* OK [CAPABILITY IMAP4rev1] ready\r\nA2 OK in\r\n* CAPABILITY IMAP4rev1 LITERAL+\r\nA3 OK\r\n",
		"* OK ready\r\n* CAPABILITY IMAP4rev1 AUTH=XOAUTH2 SASL-IR\r\nA1 OK done\r\n+ eyJ9\r\nA2 NO [AUTHENTICATIONFAILED] no\r\n",
		"* OK [CAPABILITY IMAP4rev1 LOGINDISABLED AUTH=PLAIN] ready\r\n+ \r\n+ \r\nA2 OK\r\n",
		"* PREAUTH hi\r\n",
		"* BYE go\r\n",
		"* OK {5}\r\nhello\r\n",
		"* OK [CAPABILITY IMAP4rev1] {2}\r\nA2 OK in\r\nA3 OK\r\n",
		"* OK ready\r\n* CAPABILITY {3+}\r\nabc\r\nA1 OK\r\n",
		"* OK [CAPABILITY\r\n",
		"A2 OK\r\n",
		"* OK [CAPABILITY IMAP4rev1] ready\r\nA2 NO [UNAVAILABLE] later\r\n",
		"* OK [CAPABILITY IMAP4rev1] ready\r\n+\r\n+\r\n+\r\n",
		"* OK " + strings.Repeat("x", preauthLine+10) + "\r\n",
		strings.Repeat("* OK\r\n", preauthLines+5),
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, in string, oauth bool) {
		s := &Store{cfg: Config{Credential: func(context.Context) (Login, error) {
			return Login{User: "canary-user", Secret: "canary-secret", OAuth: oauth}, nil
		}}}
		cr := &countReader{r: strings.NewReader(in)}
		br := bufio.NewReaderSize(cr, preauthLine)
		_, err := s.signIn(context.Background(), io.Discard, br)
		if cr.n > int64(preauthLines+1)*preauthLine {
			t.Fatalf("read %d bytes before sign-in", cr.n)
		}
		first, _, _ := strings.Cut(in, "\n")
		if _, lit := literal([]byte(first + "\n")); lit && strings.Contains(in, "\n") && len(first) < preauthLine && err == nil {
			t.Fatalf("a greeting with a literal signed in: %q", in)
		}
	})
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// An honest answer passes the checks: flags as servers send them, system
// flags such as \Recent included.
func TestAnHonestConnectionPasses(t *testing.T) {
	srv := newLogServer(t)
	conn := hostileConn(t, func(n int, q imapwire.Request, br *bufio.Reader, w net.Conn, ctrl *net.UnixConn) {
		answer(ctrl, imapwire.Response{Messages: []imapwire.Message{{Ref: imapwire.Ref{Folder: "INBOX", Validity: 7, UID: 2},
			Flags: []string{`\Seen`, `\Recent`, "$Forwarded", "agentOS/news"}, Raw: []byte("x")}}})
	})
	ms, err := hostileClerk(t, srv.addr, conn, time.Second).Fetch(context.Background(), "INBOX", 7, []uint32{1, 2})
	if err != nil || len(ms) != 1 {
		t.Fatalf("%v %v", ms, err)
	}
}
