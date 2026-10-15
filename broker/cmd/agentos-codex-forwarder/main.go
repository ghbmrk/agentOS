// Command agentos-codex-forwarder runs inside a Codex provider worker (S8-W1, #1014; A14,
// CRED-5). It listens on the worker's loopback and relays each connection, unparsed, to the
// per-worker route socket the host mounts at /run/agentos (broker/egress.NewWorkerRoute), where
// the vault process swaps the placeholder login for the owner's at declared endpoints only. It
// holds no credential and no destination of its own: whatever it relays, the socket's route
// decides. The tool boundary is the CLI's own sandbox (guest/codex C3): tool subprocesses run in
// bwrap with network access off, and CliSandboxTest asserts they reach neither this port nor
// /run/agentos/route.sock; agentos-toolsh is the fallback (C18).
//
// Usage: agentos-codex-forwarder [-listen 127.0.0.1:18432] [-socket /run/agentos/route.sock] [-- argv...]
// With argv, the command starts once the port is bound, AGENTOS_FORWARDER_ADDR names it, and the
// forwarder exits with the command's status.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListen = "127.0.0.1:18432"
	defaultSocket = "/run/agentos/route.sock"
)

// Bounds on the relay (egress K28): at most maxConns relays at once, the size of the route
// socket's own per-worker limit; a connection past it is accepted and closed at once. A relay
// with no traffic either way for idleTimeout is closed. Variables for tests.
var (
	maxConns    = 8
	idleTimeout = 10 * time.Minute
)

func main() { os.Exit(run(os.Args[1:])) }

// checkListen accepts only a literal loopback IPv4 address and a port.
func checkListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not a literal 127.x.x.x", addr)
	}
	return nil
}

func run(args []string) int {
	fs := flag.NewFlagSet("agentos-codex-forwarder", flag.ContinueOnError)
	listen := fs.String("listen", defaultListen, "loopback address to serve")
	socket := fs.String("socket", defaultSocket, "per-worker route socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := checkListen(*listen); err != nil {
		log.Print(err)
		return 2
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Print(err)
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay(ctx, ln, *socket)
	argv := fs.Args()
	if len(argv) == 0 {
		<-ctx.Done()
		return 0
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "AGENTOS_FORWARDER_ADDR="+ln.Addr().String())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	default:
		log.Print(err)
		return 127
	}
}

// relay serves ln until ctx ends, dialing socket for each connection. No socket, no connection:
// the client's side is closed. Past maxConns open relays a connection is closed at once.
func relay(ctx context.Context, ln net.Listener, socket string) {
	go func() { <-ctx.Done(); ln.Close() }()
	slots := make(chan struct{}, maxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				pipe(c, socket)
			}()
		default:
			c.Close()
		}
	}
}

// activeConn records the time of its last read.
type activeConn struct {
	net.Conn
	last *atomic.Int64
}

func (a activeConn) Read(b []byte) (int, error) {
	n, err := a.Conn.Read(b)
	if n > 0 {
		a.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func pipe(c net.Conn, socket string) {
	defer c.Close()
	u, err := net.Dial("unix", socket)
	if err != nil {
		return
	}
	defer u.Close()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(idleTimeout / 4)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				if now.Sub(time.Unix(0, last.Load())) >= idleTimeout {
					c.Close()
					u.Close()
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	half := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, activeConn{src, &last})
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	go half(u, c)
	go half(c, u)
	wg.Wait()
}
