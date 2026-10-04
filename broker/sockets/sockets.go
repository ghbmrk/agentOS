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
// "error": "..."}. Requests are capped at MaxRequest bytes.
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
}

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

// Server listens on a set of endpoints inside Dir, which it creates with
// mode 0700; sockets are 0600.
type Server struct {
	Dir string

	wg sync.WaitGroup
}

// Start listens on every endpoint and serves until ctx is done. It fails
// without listening on any socket if one endpoint is invalid.
func (s *Server) Start(ctx context.Context, eps ...Endpoint) error {
	for _, ep := range eps {
		if ep.Name == "" || ep.Name != filepath.Base(ep.Name) || strings.HasPrefix(ep.Name, ".") {
			return fmt.Errorf("sockets: bad endpoint name %q", ep.Name)
		}
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	var lns []net.Listener
	for _, ep := range eps {
		path := filepath.Join(s.Dir, ep.Name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			closeAll(lns)
			return err
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			closeAll(lns)
			return err
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(true)
		if err := os.Chmod(path, 0o600); err != nil {
			ln.Close()
			closeAll(lns)
			return err
		}
		lns = append(lns, ln)
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
	}()
	return nil
}

// Wait returns once every listener and connection has finished.
func (s *Server) Wait() { s.wg.Wait() }

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		ln.Close()
	}
}

func (s *Server) accept(ctx context.Context, ln net.Listener, ep Endpoint) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.serve(ctx, c, ep)
	}
}

func (s *Server) serve(ctx context.Context, c net.Conn, ep Endpoint) {
	defer s.wg.Done()
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	r := bufio.NewReaderSize(c, 4096)
	enc := json.NewEncoder(c)
	for {
		line, err := readLine(r)
		if errors.Is(err, errTooLarge) {
			enc.Encode(Response{Error: "request too large"})
			return
		}
		if err != nil {
			return
		}
		if err := enc.Encode(handle(ctx, ep, line)); err != nil {
			return
		}
	}
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
		return Response{Error: "malformed request"}
	}
	h, ok := ep.Ops[req.Op]
	if !ok {
		return Response{Error: "unknown op"}
	}
	defer func() {
		if p := recover(); p != nil {
			resp = Response{Error: "internal error"}
		}
	}()
	out, err := h(ctx, ep.Peer, req.Args)
	if err != nil {
		return Response{Error: err.Error()}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return Response{Error: "internal error"}
	}
	return Response{OK: true, Result: b}
}
