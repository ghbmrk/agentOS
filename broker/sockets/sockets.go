// Package sockets is the broker's only way in: Unix sockets, one per peer.
//
// A socket's peer identity is fixed when the socket is created (the owner
// channel, or one agent machine whose VM gets only that socket). It is never
// read from a request, so a guest cannot claim to be someone else; OP-8's
// spend attribution and ARC-6's closed guest interface build on this. Each
// socket serves a closed set of ops; anything else is refused.
//
// Wire format: one JSON request per line, {"op": "...", "args": ...}, and one
// JSON response per line, {"ok": true, "result": ...} or {"ok": false,
// "error": "..."}. Requests are capped at MaxRequest bytes. Errors are fixed
// codes: a handler's error reaches the peer only if it is a Code.
//
// These are control sockets. Model access and MCP (ARC-6 a, b) will be
// separate per-machine HTTP listeners under the same identity rule.
package sockets

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxRequest is the largest request line accepted, in bytes.
const MaxRequest = 64 << 10

// Peer identifies who is on the other end of a socket.
type Peer struct {
	Kind string `json:"kind"` // "owner", "guest", ...
	ID   string `json:"id,omitempty"`
}

// Handler serves one op. Peer is the socket's fixed identity.
type Handler func(ctx context.Context, p Peer, args json.RawMessage) (any, error)

// Endpoint is one socket: a file name in the server's directory, the peer
// it belongs to, and the ops that peer may call.
type Endpoint struct {
	Name string
	Peer Peer
	Ops  map[string]Handler
	// MaxConns caps open connections on this socket (0: no cap), so one
	// peer cannot exhaust the broker's file descriptors.
	MaxConns int
	// IdleTimeout closes a connection that sends nothing for this long
	// (0: never).
	IdleTimeout time.Duration
	// PeerUID, if set, is the only uid allowed to connect (SO_PEERCRED).
	PeerUID *int
	// PeerGID, with PeerUID, is the group the socket file is given, mode
	// 0660, so the peer's process can connect while it runs as its own
	// user; the directory is then 0711. Without it the socket is 0600.
	PeerGID *int
	// HangupOps are ops whose context ends when the peer hangs up while
	// the op runs: long polls, whose answer would be lost on a closed
	// connection. Other ops run to the end whoever hangs up.
	HangupOps map[string]bool
	// Refused, if set, is told each frame or connection this socket
	// refuses before any op runs (a protocol refusal: malformed, unknown
	// op, too large, too many, peer, internal), with the socket's peer,
	// so the broker can journal it (LOOP-7). It runs on the serving
	// goroutine and must not block; an op's own answer is not told.
	Refused func(Peer, Code)
}

// refused tells ep.Refused of a protocol refusal in resp, if any.
func (ep Endpoint) refused(resp Response) Response {
	switch c := Code(resp.Error); c {
	case ErrMalformed, ErrUnknownOp, ErrTooLarge, ErrTooMany, ErrPeer, ErrInternal:
		if ep.Refused != nil {
			ep.Refused(ep.Peer, c)
		}
	}
	return resp
}

// listened is a test hook, called after each socket is listened on and
// before its mode is set.
var listened = func(dir string) {}

// Code is an error whose text is a fixed code, safe to send to a peer.
type Code string

func (c Code) Error() string { return string(c) }

// RefusalNote is the adapter, and the reason's prefix, of the journal
// note the daemon writes for a frame a guest socket refused (LOOP-7).
const RefusalNote = "socket-refusal"

// Token is c as one word ("unknown-op"), for a journal field that takes
// tokens only.
func (c Code) Token() string { return strings.ReplaceAll(string(c), " ", "-") }

// Fixed error codes.
const (
	ErrMalformed Code = "malformed request"
	ErrUnknownOp Code = "unknown op"
	ErrTooLarge  Code = "request too large"
	ErrTooMany   Code = "too many connections"
	ErrPeer      Code = "peer not allowed"
	ErrFailed    Code = "request failed"
	ErrInternal  Code = "internal error"
)

// Response is one reply line.
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type request struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Server listens on a set of endpoints inside Dir. Dir must be a real
// directory owned by the broker's uid; it is created 0700 if missing, and a
// lock file in it keeps a second broker out. Sockets are 0600.
type Server struct {
	Dir string

	wg sync.WaitGroup
}

// Start listens on every endpoint and serves until ctx is done. It fails
// without listening on any socket if one endpoint is invalid.
func (s *Server) Start(ctx context.Context, eps ...Endpoint) error {
	seen := map[string]bool{}
	for _, ep := range eps {
		if ep.Name == "" || ep.Name != filepath.Base(ep.Name) || strings.HasPrefix(ep.Name, ".") {
			return fmt.Errorf("sockets: bad endpoint name %q", ep.Name)
		}
		if seen[ep.Name] {
			return fmt.Errorf("sockets: duplicate endpoint %q", ep.Name)
		}
		seen[ep.Name] = true
	}
	// The directory stays 0700 while sockets are created, since Listen
	// makes each one 0777&^umask until it is chmodded; a restart narrows
	// a widened one first.
	if err := secureDir(s.Dir); err != nil {
		return err
	}
	unlock, err := lockDir(s.Dir)
	if err != nil {
		return err
	}
	var lns []net.Listener
	fail := func(err error) error {
		closeAll(lns)
		unlock()
		return err
	}
	for _, ep := range eps {
		path := filepath.Join(s.Dir, ep.Name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return fail(err)
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(true)
		lns = append(lns, ln)
		listened(s.Dir)
		mode := os.FileMode(0o600)
		if ep.PeerUID != nil && ep.PeerGID != nil {
			if err := os.Chown(path, -1, *ep.PeerGID); err != nil {
				return fail(err)
			}
			mode = 0o660
		}
		if err := os.Chmod(path, mode); err != nil {
			return fail(err)
		}
	}
	// A group socket is for another local user, so the directory becomes
	// traversable (not listable) once every socket has its mode; the
	// SO_PEERCRED check in accept still turns away every uid but PeerUID.
	for _, ep := range eps {
		if ep.PeerUID != nil && ep.PeerGID != nil {
			if err := os.Chmod(s.Dir, 0o711); err != nil {
				return fail(err)
			}
			break
		}
	}
	for i, ln := range lns {
		s.wg.Add(1)
		go s.accept(ctx, ln, eps[i])
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		closeAll(lns)
		unlock()
	}()
	return nil
}

// Wait returns once every listener and connection has finished.
func (s *Server) Wait() { s.wg.Wait() }

// secureDir creates dir 0700, or checks that an existing one is a real
// directory (not a symlink) owned by this process's uid, and resets it to
// 0700.
func secureDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("sockets: %s is not a directory", dir)
	}
	if uid, ok := fileUID(fi); !ok || uid != os.Getuid() {
		return fmt.Errorf("sockets: %s is not owned by uid %d", dir, os.Getuid())
	}
	return os.Chmod(dir, 0o700)
}

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		ln.Close()
	}
}

// accept serves ln until it is closed. Other accept errors (EMFILE, ENFILE,
// ECONNABORTED) are retried with backoff, so a flood on one socket cannot
// stop the broker listening on any socket for good.
func (s *Server) accept(ctx context.Context, ln net.Listener, ep Endpoint) {
	defer s.wg.Done()
	var open sync.WaitGroup
	defer open.Wait()
	var mu sync.Mutex
	n := 0
	backoff := time.Duration(0)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		if ep.PeerUID != nil {
			if uid, ok := peerUID(c); !ok || uid != *ep.PeerUID {
				ep.refused(Response{Error: string(ErrPeer)})
				refuse(c, ErrPeer)
				continue
			}
		}
		mu.Lock()
		if ep.MaxConns > 0 && n >= ep.MaxConns {
			mu.Unlock()
			ep.refused(Response{Error: string(ErrTooMany)})
			refuse(c, ErrTooMany)
			continue
		}
		n++
		mu.Unlock()
		open.Add(1)
		go func() {
			defer open.Done()
			s.serve(ctx, c, ep)
			mu.Lock()
			n--
			mu.Unlock()
		}()
	}
}

func refuse(c net.Conn, code Code) {
	c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	json.NewEncoder(c).Encode(Response{Error: string(code)})
	c.Close()
}

func (s *Server) serve(ctx context.Context, c net.Conn, ep Endpoint) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	r := bufio.NewReaderSize(c, 4096)
	enc := json.NewEncoder(c)
	for {
		if ep.IdleTimeout > 0 {
			c.SetReadDeadline(time.Now().Add(ep.IdleTimeout))
		}
		line, err := readLine(r)
		if errors.Is(err, errTooLarge) {
			enc.Encode(ep.refused(Response{Error: string(ErrTooLarge)}))
			return
		}
		if err != nil {
			return
		}
		if ep.HangupOps[opOf(line)] {
			if !s.serveWatched(ctx, c, r, enc, ep, line) {
				return
			}
			continue
		}
		if err := enc.Encode(ep.refused(handle(ctx, ep, line))); err != nil {
			return
		}
	}
}

// serveWatched serves one HangupOps request, ending its context if the
// peer hangs up first: a read on the connection that returns while the
// op runs is end of file (or a next request, which is kept). It reports
// whether the connection stays open.
func (s *Server) serveWatched(ctx context.Context, c net.Conn, r *bufio.Reader, enc *json.Encoder, ep Endpoint, line []byte) bool {
	hctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.SetReadDeadline(time.Time{})
	peeked := make(chan error, 1)
	go func() { _, err := r.Peek(1); peeked <- err }()
	done := make(chan Response, 1)
	go func() { done <- ep.refused(handle(hctx, ep, line)) }()
	var resp Response
	var peekErr error
	select {
	case resp = <-done:
		if err := enc.Encode(resp); err != nil {
			c.Close() // ends the pending read
			<-peeked
			return false
		}
		if ep.IdleTimeout > 0 {
			c.SetReadDeadline(time.Now().Add(ep.IdleTimeout))
		}
		peekErr = <-peeked
	case peekErr = <-peeked:
		if peekErr != nil {
			cancel()
		}
		resp = <-done
		if err := enc.Encode(resp); err != nil {
			return false
		}
	}
	return peekErr == nil
}

// opOf is a request's op, "" if it has none.
func opOf(line []byte) string {
	var req struct {
		Op string `json:"op"`
	}
	if json.Unmarshal(line, &req) != nil {
		return ""
	}
	return req.Op
}

var errTooLarge = errors.New("too large")

func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		frag, err := r.ReadSlice('\n')
		out = append(out, frag...)
		if len(out) > MaxRequest {
			return nil, errTooLarge
		}
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func handle(ctx context.Context, ep Endpoint, line []byte) (resp Response) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return Response{Error: string(ErrMalformed)}
	}
	h, ok := ep.Ops[req.Op]
	if !ok {
		return Response{Error: string(ErrUnknownOp)}
	}
	defer func() {
		if p := recover(); p != nil {
			resp = Response{Error: string(ErrInternal)}
		}
	}()
	out, err := h(ctx, ep.Peer, req.Args)
	if err != nil {
		var code Code
		if errors.As(err, &code) {
			return Response{Error: string(code)}
		}
		return Response{Error: string(ErrFailed)}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return Response{Error: string(ErrInternal)}
	}
	return Response{OK: true, Result: b}
}
