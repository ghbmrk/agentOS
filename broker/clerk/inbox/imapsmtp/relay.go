package imapsmtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// ErrConnRefused ends a session whose connection process sent a command its
// typed request does not need (A5, CLK-3): the command never reached the
// server, and the session ends. A compromised parser cannot change mailbox
// state the request did not ask for, or mark mail read.
var ErrConnRefused = errors.New("imapsmtp: the connection process sent a command outside its request")

var codeLong, codeUnanswered = imapwire.Code(imapwire.ErrLongHeader), imapwire.Code(imapwire.ErrUnanswered)

// session is one signed-in IMAP session: the upstream connection this side
// dialled and signed in on, the control connection to its connection
// process, and this side's end of the socketpair that process runs go-imap
// over. Two goroutines relay the socketpair: server bytes down under the
// reply budget, connection bytes up through the command filter.
type session struct {
	s     *Store
	up    net.Conn
	ctrl  *net.UnixConn
	local *net.UnixConn
	step  *time.Timer

	caps map[string]bool // the server's, signed in (signIn)

	left                          atomic.Int64 // the reply budget left, renewed only by do
	allow                         atomic.Pointer[allowance]
	wait                          atomic.Pointer[waiter]
	over, late, refused, rejected atomic.Bool
	closeOnce                     sync.Once
	closed, downDone              chan struct{}
}

// waiter is the filter waiting for the server's answer to a synchronizing
// literal in the command tagged tag: true for its "+", false for the
// command's tagged answer, which refuses the literal.
type waiter struct {
	tag string
	ch  chan bool
}

// errLiteralRejected ends a session whose server refused a synchronizing
// literal: its bytes never went, and the session cannot continue in step.
var errLiteralRejected = errors.New("imapsmtp: the mail server refused a command's literal")

// teardown closes everything the session holds, once.
func (x *session) teardown() {
	x.closeOnce.Do(func() {
		close(x.closed)
		x.up.Close()
		x.ctrl.Close()
		x.local.Close()
	})
}

// session runs f on a signed-in session served by a fresh connection
// process. It dials, signs in (preauth.go), passes the process its end of
// a socketpair that starts with a synthetic PREAUTH greeting, and relays.
// The connection is closed however the session ends; after a clean end it
// says LOGOUT itself.
func (s *Store) session(ctx context.Context, f func(x *session) error) (err error) {
	var late, over atomic.Bool
	defer func() { err = ended(err, over.Load(), late.Load(), ctx) }()
	dctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	ctrl, err := s.cfg.Conn(dctx)
	if err != nil {
		return errors.New("imapsmtp: could not start the connection process")
	}
	defer ctrl.Close()
	conn, err := s.dial(dctx, s.cfg.IMAP, s.cfg.IMAPSec)
	if err != nil {
		// The caller's deadline, passed before or during the dial, not the
		// dial's own timeout, ended it.
		late.Store(ctx.Err() == context.DeadlineExceeded)
		return err
	}
	// A timer closes the connection: at the dial's deadline for the
	// greeting, handshake and sign-in, then once a request has run for the
	// timeout, as do restarts it. Every cut-off goes through it and so marks
	// the session late.
	dl, _ := dctx.Deadline()
	raw := conn
	step := time.AfterFunc(time.Until(dl), func() { late.Store(true); raw.Close(); ctrl.Close() })
	defer step.Stop()
	switch s.cfg.IMAPSec {
	case TLS:
		conn = tls.Client(conn, s.tlsConfig(s.cfg.IMAP))
	case Plain:
	default:
		conn.Close()
		return errors.New("imapsmtp: IMAP uses implicit TLS, or plain to loopback only")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() {
		if ctx.Err() == context.DeadlineExceeded {
			late.Store(true)
		}
		conn.Close()
		ctrl.Close()
	})
	defer stop()
	br := bufio.NewReaderSize(conn, preauthLine)
	caps, err := s.signIn(dctx, conn, br)
	if err != nil {
		return err
	}
	local, err := handOff(ctrl, caps)
	if err != nil {
		return errors.New("imapsmtp: could not hand the session to the connection process")
	}
	x := &session{s: s, up: conn, ctrl: ctrl, local: local, step: step, caps: caps,
		closed: make(chan struct{}), downDone: make(chan struct{})}
	defer x.teardown()
	// Until the first request, the base budget covers what the sign-in left
	// unread and go-imap's start-up CAPABILITY.
	x.left.Store(s.replyBase)
	// What the reader holds past the tagged OK is the server's, and goes
	// down first, under the first request's budget.
	pending, _ := br.Peek(br.Buffered())
	go x.down(append([]byte(nil), pending...))
	go x.filter()
	err = f(x)
	over.Store(x.over.Load())
	if x.refused.Load() {
		return ErrConnRefused
	}
	if x.rejected.Load() {
		return errLiteralRejected
	}
	if err == nil && !x.over.Load() && !late.Load() {
		// The process is idle after its last answer: stop the relay and
		// end the session on this side.
		x.local.Close()
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		io.WriteString(conn, "Z LOGOUT\r\n")
	}
	return err
}

// handOff writes the synthetic PREAUTH greeting into one end of a fresh
// socketpair and passes the other end to the connection process with the
// first byte on ctrl (SCM_RIGHTS). go-imap enters the authenticated state
// on PREAUTH. The process never sees the sign-in.
func handOff(ctrl *net.UnixConn, caps map[string]bool) (*net.UnixConn, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fds[1])
	f := os.NewFile(uintptr(fds[0]), "imap-stream")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	local := c.(*net.UnixConn)
	if _, err := io.WriteString(local, greeting(caps)); err != nil {
		local.Close()
		return nil, err
	}
	if _, _, err := ctrl.WriteMsgUnix([]byte{0}, syscall.UnixRights(fds[1]), nil); err != nil {
		local.Close()
		return nil, err
	}
	return local, nil
}

// greeting is the synthetic PREAUTH greeting, carrying the server's
// signed-in capabilities that are atoms, so go-imap decides what it may
// send (non-synchronizing literals) from the list the filter reads.
func greeting(caps map[string]bool) string {
	var l []string
	for c := range caps {
		if tagOK(strings.ReplaceAll(c, "+", "")) && !strings.ContainsAny(c, "]") {
			l = append(l, c)
		}
	}
	if len(l) == 0 {
		return "* PREAUTH ready\r\n"
	}
	slices.Sort(l)
	return "* PREAUTH [CAPABILITY " + strings.Join(l, " ") + "] ready\r\n"
}

// read is the allowance of a request that only reads.
var read = allowance{}

// do sends one typed request and reads its answer. It sets the request's
// allowance and, unless budget is 0, renews the reply budget to budget and
// restarts the timeout: only this side renews either, never the
// connection. The answer is bounded by twice the budget: it carries what
// the server sent, re-encoded. A code the connection answers becomes its
// error; the codes that were the server's own answer stand.
func (x *session) do(req imapwire.Request, budget int64, a allowance) (imapwire.Response, error) {
	var r imapwire.Response
	x.allow.Store(&a)
	if budget > 0 {
		x.left.Store(budget)
		x.step.Reset(x.s.cfg.Timeout)
	}
	if err := imapwire.Write(x.ctrl, req); err != nil {
		return r, err
	}
	if err := imapwire.Read(x.ctrl, 2*max(x.left.Load(), budget)+64<<10, &r); err != nil {
		if errors.Is(err, imapwire.ErrFrame) {
			return imapwire.Response{}, errLied
		}
		return imapwire.Response{}, err
	}
	err := imapwire.Err(r.Err)
	switch {
	case errors.Is(err, ErrNoUIDNext), errors.Is(err, ErrPartialStatus), errors.Is(err, ErrUnanswered):
		err = stand{err}
	}
	return r, err
}

// down relays server bytes to the connection under the reply budget. Once
// the budget is spent, a byte more from the server ends the session as
// over, unless do renewed the budget meanwhile.
func (x *session) down(pending []byte) {
	defer close(x.downDone)
	defer x.local.CloseWrite()
	var fr frames
	buf := make([]byte, 32<<10)
	for {
		var n int
		var err error
		if len(pending) > 0 {
			n = copy(buf, pending)
			pending = pending[n:]
		} else {
			left := x.left.Load()
			if left <= 0 {
				n, err = x.up.Read(buf[:1])
				if n > 0 && x.left.Load() <= 0 {
					x.over.Store(true)
					x.teardown()
					return
				}
			} else {
				n, err = x.up.Read(buf[:min(int64(len(buf)), left)])
			}
		}
		x.left.Add(-int64(n))
		fr.feed(buf[:n], x.answered)
		if n > 0 {
			if _, werr := x.local.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// answered hands a waiting filter the server's answer to its literal: a
// continuation ("+") or the command's tagged answer.
func (x *session) answered(head []byte) {
	w := x.wait.Load()
	if w == nil {
		return
	}
	switch {
	case bytes.HasPrefix(head, []byte("+")):
		if x.wait.CompareAndSwap(w, nil) {
			w.ch <- true
		}
	case bytes.HasPrefix(head, []byte(w.tag+" ")):
		if x.wait.CompareAndSwap(w, nil) {
			w.ch <- false
		}
	}
}

// frames finds the server's response lines in the relayed bytes, skipping
// {n} literals by count, and hands each line's start (up to frameHead
// bytes) to its caller. It reads no more than that: it frames, it does not
// parse.
type frames struct {
	head []byte
	tail []byte // the line's last bytes, for a literal's {n}
	lit  int64  // literal bytes still to skip
}

const frameHead = 128

func (f *frames) feed(p []byte, line func(head []byte)) {
	for len(p) > 0 {
		if f.lit > 0 {
			k := min(int64(len(p)), f.lit)
			f.lit -= k
			p = p[k:]
			continue
		}
		c := p[0]
		p = p[1:]
		if len(f.head) < frameHead {
			f.head = append(f.head, c)
		}
		if f.tail = append(f.tail, c); len(f.tail) > 32 {
			f.tail = f.tail[1:]
		}
		if c == '\n' {
			line(f.head)
			if i := bytes.LastIndexByte(f.tail, '{'); i >= 0 {
				if n, ok := literal(f.tail[i:]); ok {
					f.lit = n
				}
			}
			f.head, f.tail = f.head[:0], f.tail[:0]
		}
	}
}

// Bounds on the command filter: a command's line between literals, which
// the filter holds whole before passing it on.
const filterLine = 64 << 10

// filter relays the connection's commands to the server, each only if its
// allowance permits it (A5). It reads each command's tag and verb and skips
// {n} and {n+} literals by count, so no literal's bytes are read as a
// command. Each line ends in CRLF and holds no other CR (RFC 3501 2.2), so
// a miscounted literal shows. A synchronizing literal waits for the
// server's "+"; a non-synchronizing one passes only where the server must
// read it. A refused command is never sent; it ends the session.
func (x *session) filter() {
	br := bufio.NewReaderSize(x.local, filterLine)
	refuse := func() { x.refused.Store(true); x.teardown() }
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			// A line past the bound is refused; at EOF the connection
			// finished, and the session's end closes the upstream.
			if errors.Is(err, bufio.ErrBufferFull) {
				refuse()
			}
			return
		}
		a := x.allow.Load()
		verb, ok := a.command(line)
		if !ok || !crlf(line) {
			refuse()
			return
		}
		tag, _, _ := bytes.Cut(line, []byte(" "))
		for {
			n, more := literal(line)
			var w *waiter
			if more && !x.literalOK(line, n) {
				refuse()
				return
			}
			if more && !nonSync(line) {
				// A synchronizing literal goes only after the server's "+":
				// a server may refuse it with a tagged answer and read what
				// follows as a new command (RFC 3501 7.5).
				w = &waiter{tag: string(tag), ch: make(chan bool, 1)}
				x.wait.Store(w)
			}
			if _, err := x.up.Write(line); err != nil {
				return
			}
			if !more {
				break
			}
			if w != nil {
				select {
				case ok := <-w.ch:
					if !ok {
						x.rejected.Store(true)
						x.teardown()
						return
					}
				case <-x.closed:
					return
				case <-x.downDone:
					return
				}
			}
			if _, err := io.CopyN(x.up, br, n); err != nil {
				return
			}
			if line, err = br.ReadSlice('\n'); err != nil {
				if errors.Is(err, bufio.ErrBufferFull) {
					refuse()
				}
				return
			}
			if !crlf(line) || !a.continuation(verb, line) {
				refuse()
				return
			}
		}
	}
}

// crlf says whether line ends in CRLF and holds no other CR.
func crlf(line []byte) bool {
	return bytes.HasSuffix(line, []byte("\r\n")) && bytes.IndexByte(line[:len(line)-2], '\r') < 0
}

// nonSync says whether line's literal is non-synchronizing, {n+}.
func nonSync(line []byte) bool {
	return bytes.HasSuffix(bytes.TrimRight(line, "\r\n"), []byte("+}"))
}

// literalOK says whether the server takes line's literal of n bytes as
// the client sends it: a synchronizing one always (it waits for "+"); a
// non-synchronizing one only where the server must read it whatever it
// then answers, under LITERAL+, or LITERAL- up to 4096 bytes (RFC 7888).
func (x *session) literalOK(line []byte, n int64) bool {
	return !nonSync(line) || x.caps["LITERAL+"] || x.caps["LITERAL-"] && n <= 4096
}

// literal is the length of the literal line announces at its end, {n} or
// {n+} before its CRLF.
func literal(line []byte) (int64, bool) {
	l := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
	if !bytes.HasSuffix(l, []byte("}")) {
		return 0, false
	}
	i := bytes.LastIndexByte(l, '{')
	if i < 0 {
		return 0, false
	}
	d := strings.TrimSuffix(string(l[i+1:len(l)-1]), "+")
	n, err := strconv.ParseInt(d, 10, 64)
	if err != nil || n < 0 || d == "" || d[0] == '+' {
		return 0, false
	}
	return n, true
}

// allowance is what one typed request may send: the commands every read
// needs, plus one UID STORE of the request's flags or one UID MOVE to the
// request's target, each on the request's UID only and after the one
// SELECT of the request's folder that a write may make (no EXAMINE, no
// second SELECT), and, for the old core, CREATE or APPEND.
// EXPUNGE, CLOSE, DELETE, RENAME, COPY, LOGIN, AUTHENTICATE, STARTTLS,
// IDLE and anything unnamed are never allowed. A nil allowance, before the
// first request, allows only the CAPABILITY go-imap sends as it starts.
type allowance struct {
	store, move    uint32
	add, remove    []string
	create, append bool
	// folder, set for a write, is the one SELECT the write may make, as
	// go-imap writes it; to is its UID MOVE's target. selected is the
	// filter's own note that the SELECT went.
	folder, to string
	selected   bool
}

// write says whether a is a store or a move.
func (a *allowance) write() bool { return a != nil && (a.store != 0 || a.move != 0) }

// reads are the commands every request may send.
var reads = map[string]bool{"SELECT": true, "EXAMINE": true, "STATUS": true, "LIST": true, "UID FETCH": true,
	"UID SEARCH": true, "CAPABILITY": true, "NOOP": true, "LOGOUT": true}

// command is the verb of a command's first line, "UID <verb>" for a UID
// command, if a permits it.
func (a *allowance) command(line []byte) (string, bool) {
	l := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	f := strings.SplitN(l, " ", 4)
	if len(f) < 2 || !tagOK(f[0]) {
		return "", false
	}
	verb, rest := strings.ToUpper(f[1]), strings.Join(f[2:], " ")
	if verb == "UID" && len(f) > 2 {
		verb, rest = "UID "+strings.ToUpper(f[2]), strings.Join(f[3:], " ")
	}
	switch {
	case a == nil:
		return verb, verb == "CAPABILITY" && len(f) == 2
	case a.write() && (verb == "SELECT" || verb == "EXAMINE"):
		ok := verb == "SELECT" && !a.selected && rest == a.folder
		a.selected = a.selected || ok
		return verb, ok
	case reads[verb]:
		return verb, verb != "UID FETCH" || peekOnly(rest)
	case verb == "UID STORE" && a.store != 0:
		return verb, a.selected && a.storeOK(rest)
	case verb == "UID MOVE" && a.move != 0:
		return verb, a.selected && rest == strconv.FormatUint(uint64(a.move), 10)+" "+a.to
	case verb == "CREATE" && a.create, verb == "APPEND" && a.append:
		return verb, true
	}
	return verb, false
}

// continuation says whether a line after a literal, within a command of
// verb, may pass: a fetch's items stay peek-only, and a write's SELECT,
// UID STORE or UID MOVE carries no literal at all.
func (a *allowance) continuation(verb string, line []byte) bool {
	switch {
	case verb == "UID FETCH":
		return peekOnly(string(line))
	case verb == "UID STORE", verb == "UID MOVE", a.write() && verb == "SELECT":
		return false
	}
	return true
}

// tagOK says whether t is an IMAP tag: ATOM-CHARs but "+".
func tagOK(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte(`(){%*"\]+`, c) >= 0 {
			return false
		}
	}
	return true
}

// peekOnly says whether a fetch's items mark nothing read: no BODY[ or
// BINARY[ section without .PEEK, no RFC822 or RFC822.TEXT (RFC 3501
// 6.4.5, RFC 3516). VRB-2 reads \Seen.
func peekOnly(items string) bool {
	u := strings.ToUpper(items)
	if strings.Contains(u, "BODY[") || strings.Contains(u, "BINARY[") {
		return false
	}
	for _, t := range strings.FieldsFunc(u, func(r rune) bool { return r == ' ' || r == '(' || r == ')' }) {
		if t == "RFC822" || t == "RFC822.TEXT" {
			return false
		}
	}
	return true
}

// storeOK says whether rest is the UID STORE of the request: its UID, then
// +FLAGS.SILENT with its add flags or -FLAGS.SILENT with its remove flags,
// as go-imap writes them.
func (a *allowance) storeOK(rest string) bool {
	uid := strconv.FormatUint(uint64(a.store), 10)
	for _, x := range []struct {
		op    string
		flags []string
	}{{"+FLAGS.SILENT", a.add}, {"-FLAGS.SILENT", a.remove}} {
		if len(x.flags) > 0 && strings.EqualFold(rest, uid+" "+x.op+" ("+strings.Join(x.flags, " ")+")") {
			return true
		}
	}
	return false
}
