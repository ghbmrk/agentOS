// Package readerwire is the frame between the mail clerk and the reader
// process on the main side (MAIL-reader-sock-a, #3421). D-154 rule 4 keeps
// the reader out of every keeper process, so the mail clerk's quarantined
// read (PLN-2) sends each mail's bounded text over this frame, and the reader
// returns the model's reply. inbox.Read stays the one judge of that reply.
//
// One connection carries one call. The call is one JSON line,
// {"v":1,"op":"read","prompt":"<base64>"}, and the answer one JSON line,
// {"reply":"..."} or {"err":"<word>"}. Each end checks the other's uid
// (SO_PEERCRED), as kernel/proc's wire does. The package links only the
// standard library and sockets, so the main-side reader links no keeper code.
package readerwire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// Ask is one quarantined read; it converts to inbox.Ask.
type Ask func(ctx context.Context, prompt string) (string, error)

const (
	// MaxPrompt bounds a call's prompt, in raw bytes.
	MaxPrompt = 24 << 10
	// MaxReply bounds a reply, in bytes after decoding: a class word fits
	// many times over, and a longer reply is refused, never cut.
	MaxReply = 64
	// maxCall bounds a call on the wire, its newline included: the prompt is
	// base64, so its size is fixed whatever its bytes hold.
	maxCall = 4*((MaxPrompt+2)/3) + 64
	// maxAnswer bounds an answer on the wire, its newline included.
	maxAnswer = 256

	// DefaultTimeout is the whole call's deadline when Dial is given 0.
	DefaultTimeout = 60 * time.Second
	// pause is how long calls fail at once after the reader itself failed.
	pause = 60 * time.Second
	// serveTimeout is the serving end's deadline for one connection.
	serveTimeout = 60 * time.Second
	// maxConns is how many calls the serving end runs at once.
	maxConns = 8

	version = 1
	opRead  = "read"
)

// The closed error words, and the errors the mail clerk's end returns.
var (
	ErrUnavailable = errors.New("readerwire: unavailable")
	// ErrRefused is the answer when no route admits the call. A model
	// function returns it (or wraps it) to answer refused.
	ErrRefused  = errors.New("readerwire: refused")
	ErrTooLarge = errors.New("readerwire: too-large")
	// ErrPaused is every call's answer, with nothing dialled, for a while
	// after the reader itself failed.
	ErrPaused = errors.New("readerwire: the reader failed; paused")
	// ErrMalformed is an answer the frame does not admit: that mail fails,
	// and the reader is not paused.
	ErrMalformed = errors.New("readerwire: malformed answer")
)

var words = map[string]error{"unavailable": ErrUnavailable, "refused": ErrRefused, "too-large": ErrTooLarge}

type call struct {
	V      int    `json:"v"`
	Op     string `json:"op"`
	Prompt []byte `json:"prompt"` // standard base64
}

type answer struct {
	Reply *string `json:"reply,omitempty"`
	Err   *string `json:"err,omitempty"`
}

// canonical decodes line into v only if v encodes back to exactly line: so
// another case of a key, a duplicate or unknown key, other spacing or another
// escaping of the same value is refused, not read.
func canonical(line []byte, v any) bool {
	if json.Unmarshal(line, v) != nil {
		return false
	}
	b, err := json.Marshal(v)
	return err == nil && bytes.Equal(b, line)
}

// errLong is a line past its bound.
var errLong = errors.New("readerwire: line too long")

// readLine reads one line of at most max bytes, its newline included, from
// br, which must be bounded to max+1 bytes. Any byte after the newline is
// trailing data, and refused.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	switch {
	case err == nil && len(line) > max:
		return nil, errLong
	case errors.Is(err, io.EOF) && len(line) > max:
		return nil, errLong
	case err != nil:
		return nil, err
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errLong
		}
		return nil, err
	}
	return line[:len(line)-1], nil
}

// Dial is the mail clerk's end: each call dials sock, refuses with nothing
// sent unless the listener's uid is uid, and runs under one deadline of
// timeout (DefaultTimeout when 0). Every failure is an error, so the mail
// stays unclassified. After a failure of the reader itself (a dial error, a
// wrong uid, a deadline, a lost answer, unavailable or refused) the next
// calls fail at once, with nothing dialled, for a minute, so a down reader
// costs a read at most one timeout.
func Dial(sock string, uid int, timeout time.Duration) Ask {
	return newDialer(sock, uid, timeout, time.Now).ask
}

type dialer struct {
	sock    string
	uid     int
	timeout time.Duration
	now     func() time.Time

	mu    sync.Mutex
	until time.Time
}

func newDialer(sock string, uid int, timeout time.Duration, now func() time.Time) *dialer {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &dialer{sock: sock, uid: uid, timeout: timeout, now: now}
}

func (d *dialer) ask(ctx context.Context, prompt string) (string, error) {
	if len(prompt) > MaxPrompt {
		return "", ErrTooLarge
	}
	d.mu.Lock()
	paused := d.now().Before(d.until)
	d.mu.Unlock()
	if paused {
		return "", ErrPaused
	}
	reply, down, err := d.call(ctx, prompt)
	// A caller that gave up is not the reader's failure.
	if down && ctx.Err() == nil {
		d.mu.Lock()
		d.until = d.now().Add(pause)
		d.mu.Unlock()
	}
	return reply, err
}

// call makes one call. down is true when the reader itself failed.
func (d *dialer) call(ctx context.Context, prompt string) (reply string, down bool, err error) {
	b, err := json.Marshal(call{V: version, Op: opRead, Prompt: []byte(prompt)})
	if err != nil || len(b)+1 > maxCall {
		return "", false, ErrTooLarge
	}
	// The connection's deadline is the reader's own timeout; the caller's
	// context ends the call through AfterFunc, which runs only once that
	// context is done, so ask never reads the caller's deadline as the
	// reader's failure.
	own := time.Now().Add(d.timeout)
	ctx, cancel := context.WithDeadline(ctx, own)
	defer cancel()
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "unix", d.sock)
	if err != nil {
		return "", true, ErrUnavailable
	}
	defer conn.Close()
	if u, ok := sockets.PeerUID(conn); !ok || u != d.uid {
		return "", true, ErrUnavailable
	}
	conn.SetDeadline(own)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return "", true, ErrUnavailable
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}
	line, err := readLine(bufio.NewReader(io.LimitReader(conn, maxAnswer+1)), maxAnswer)
	switch {
	case errors.Is(err, errLong):
		return "", false, ErrMalformed
	case err != nil:
		return "", true, ErrUnavailable
	}
	var a answer
	switch {
	case !canonical(line, &a) || (a.Reply == nil) == (a.Err == nil):
		return "", false, ErrMalformed
	case a.Err != nil:
		e, ok := words[*a.Err]
		if !ok {
			return "", false, ErrMalformed
		}
		return "", e != ErrTooLarge, e
	case len(*a.Reply) > MaxReply:
		return "", false, ErrMalformed
	}
	return *a.Reply, false, nil
}

// Listen opens the reader's socket, admitting only the mail clerk's uid;
// every other peer is closed unread.
func Listen(path string, mailUID int) (net.Listener, error) {
	return sockets.ListenPeers(path, mailUID)
}

// Serve is the reader's end: it answers each call on ln with model's reply,
// at most eight at once (the rest wait in the listen backlog), until ln
// closes. A model error is answered unavailable (refused when it is
// ErrRefused) and a reply over MaxReply too-large: never with the model's
// text.
func Serve(ln net.Listener, model Ask) error {
	return serve(ln, model, serveTimeout)
}

func serve(ln net.Listener, model Ask, timeout time.Duration) error {
	slots := make(chan struct{}, maxConns)
	wait := 5 * time.Millisecond
	for {
		slots <- struct{}{}
		conn, err := ln.Accept()
		if err != nil {
			<-slots
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(wait)
			wait = min(2*wait, time.Second)
			continue
		}
		wait = 5 * time.Millisecond
		go func() {
			defer func() { <-slots }()
			serveConn(conn, model, timeout)
		}()
	}
}

func serveConn(conn net.Conn, model Ask, timeout time.Duration) {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dl, _ := ctx.Deadline()
	conn.SetDeadline(dl)
	line, err := readLine(bufio.NewReader(io.LimitReader(conn, maxCall+1)), maxCall)
	if errors.Is(err, errLong) {
		write(conn, answer{Err: word("too-large")})
		return
	}
	var c call
	if err != nil || !canonical(line, &c) || c.V != version || c.Op != opRead {
		return
	}
	if len(c.Prompt) > MaxPrompt {
		write(conn, answer{Err: word("too-large")})
		return
	}
	reply, err := model(ctx, string(c.Prompt))
	switch {
	case errors.Is(err, ErrRefused):
		write(conn, answer{Err: word("refused")})
	case err != nil:
		write(conn, answer{Err: word("unavailable")})
	case len(reply) > MaxReply:
		// The mail can steer the reply's length, so it fails that mail
		// only: a reader failure would pause every other mail's read.
		write(conn, answer{Err: word("too-large")})
	default:
		write(conn, answer{Reply: &reply})
	}
}

func word(w string) *string { return &w }

// write sends a; an answer that escaping grows past maxAnswer is sent as
// too-large instead, which fails that mail only.
func write(conn net.Conn, a answer) {
	b, err := json.Marshal(a)
	if err != nil || len(b)+1 > maxAnswer {
		b, _ = json.Marshal(answer{Err: word("too-large")})
	}
	conn.Write(append(b, '\n'))
}
