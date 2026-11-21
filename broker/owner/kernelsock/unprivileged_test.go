package kernelsock

// REQ: KRN-5

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// heard is what a served kernel saw of one call: the request line, and
// whether the caller then closed its end.
type heard struct {
	line   string
	closed bool
}

// serveOnce serves one call on a fresh socket: it reads the request line,
// answers answer (none when answer is ""), and reports what it saw once the
// caller closed its end or a second passed.
func serveOnce(t *testing.T, answer string) (string, <-chan heard) {
	t.Helper()
	path := filepath.Join(runDir(t), "owner.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan heard, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		if answer != "" {
			c.Write([]byte(answer + "\n"))
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err = r.ReadByte()
		out <- heard{line, errors.Is(err, io.EOF)}
	}()
	return path, out
}

// The owner side's calls work with the owner side's uid this process's own,
// so no root is needed to test them: the call is sent as the kernel's wire
// has it, the caller closes its end, and the kernel's refusal, error or
// result comes back as such; an answer cut short or never given is lost,
// and a socket nobody (or another uid) holds is unreachable (#6023).
func TestTheOwnersCallsUnprivileged(t *testing.T) {
	ctx := context.Background()
	me := os.Geteuid()
	call := func(answer string, do func(Owner) error) (error, heard) {
		t.Helper()
		path, saw := serveOnce(t, answer)
		err := do(Owner{Socket: path, UID: me, As: me})
		select {
		case h := <-saw:
			return err, h
		case <-time.After(5 * time.Second):
			t.Fatal("the served kernel never finished")
		}
		return nil, heard{}
	}
	stop := func(o Owner) error { return o.Stop(ctx) }

	var r Refused
	err, h := call(`{"refusal":{"code":"stopped","detail":"stop is in force"}}`, stop)
	if !errors.As(err, &r) || r.Text != "stopped: stop is in force" {
		t.Fatalf("a refusal: %v", err)
	}
	if h.line != `{"op":"stop","args":{}}`+"\n" || !h.closed {
		t.Fatalf("the kernel heard %+v", h)
	}
	if err, _ := call(`{"error":"no such op"}`, stop); !errors.As(err, &r) || r.Text != "no such op" {
		t.Fatalf("an error: %v", err)
	}
	if err, _ := call(`{"result":`, stop); !errors.Is(err, ErrLost) {
		t.Fatalf("a cut answer: %v", err)
	}
	var stopped bool
	var stops uint64
	err, _ = call(`{"result":{"stopped":true,"stops":3}}`, func(o Owner) (err error) {
		stopped, stops, err = o.Stopped(ctx)
		return err
	})
	if err != nil || !stopped || stops != 3 {
		t.Fatalf("a result: %v %d %v", stopped, stops, err)
	}
	if err, _ := call(`{"result":"stopped"}`, func(o Owner) error { _, _, err := o.Stopped(ctx); return err }); !errors.Is(err, ErrLost) {
		t.Fatalf("an undecodable result: %v", err)
	}
	// No answer: the caller's deadline ends the wait, well before the
	// served kernel gives up.
	start := time.Now()
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err, _ := call("", func(o Owner) error { return o.Stop(short) }); !errors.Is(err, ErrLost) || time.Since(start) > 900*time.Millisecond {
		t.Fatalf("no answer: %v after %v", err, time.Since(start))
	}
	if err, h := call(`{"result":null}`, func(o Owner) error { o.UID = me + 1; return o.Stop(ctx) }); !errors.Is(err, ErrUnreachable) || h.line != "" {
		t.Fatalf("another uid's socket: %v, the kernel heard %+v", err, h)
	}
	if err := (Owner{Socket: filepath.Join(runDir(t), "none.sock"), UID: me, As: me}).Stop(ctx); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("no socket: %v", err)
	}
}
