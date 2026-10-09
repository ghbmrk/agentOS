// Package sockprobe is LOOP-7's in-guest socket probe (P3-4b-3). It runs
// inside an agent machine with guest authority only: it dials the sockets
// in the directory the machine sees, and nothing else. It checks that
// only the declared sockets are reachable, and that a fixed set of
// malformed and oversized frames is refused with the fixed codes and
// leaves the broker answering, as the same peer, after each one.
//
// The frames are fixed and off the shelf (D-067): no input is generated,
// mutated or searched for. That the refusals were journaled, and had no
// effect, is checked on the broker side against Result.Sent, since the
// guest cannot read the journal (broker/loop7).
package sockprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// Frame is one fixed probe frame and the code the broker must refuse it
// with.
type Frame struct {
	Name string
	Data []byte
	Want sockets.Code
}

// Frames is the fixed probe set, sent in order on a fresh connection
// each.
var Frames = []Frame{
	{"not JSON", []byte("not json\n"), sockets.ErrMalformed},
	{"wrong field type", []byte(`{"op":7}` + "\n"), sockets.ErrMalformed},
	{"unknown op", []byte(`{"op":"sockprobe-unknown"}` + "\n"), sockets.ErrUnknownOp},
	{"oversized frame", append(bytes.Repeat([]byte("a"), sockets.MaxRequest+1), '\n'), sockets.ErrTooLarge},
}

// Config is what the probe may know: the directory the machine sees, the
// socket names declared for it, and an op every declared socket answers.
type Config struct {
	Dir      string
	Declared []string
	Ping     string
	// Timeout bounds each exchange. Default 2 s.
	Timeout time.Duration
}

// Sent is one frame sent and the code that came back ("" for none).
type Sent struct {
	Socket string
	Frame  string
	Want   sockets.Code
	Got    sockets.Code
}

// Result is one probe run: every frame sent, in order, and each failure
// in plain words. No failures means the run passed.
type Result struct {
	Sent     []Sent
	Failures []string
}

// Run probes cfg.Dir once. It never returns an error: a probe that cannot
// run is a failure.
func Run(ctx context.Context, cfg Config) Result {
	var res Result
	fail := func(format string, a ...any) { res.Failures = append(res.Failures, fmt.Sprintf(format, a...)) }
	if cfg.Dir == "" || cfg.Ping == "" || len(cfg.Declared) == 0 {
		fail("probe config needs a directory, a declared socket and a ping op")
		return res
	}
	for _, n := range cfg.Declared {
		if n == "" || n != filepath.Base(n) || strings.HasPrefix(n, ".") {
			fail("declared socket name %q is not a plain name", n)
			return res
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	p := prober{cfg: cfg}
	// Only the declared sockets are reachable.
	ents, err := os.ReadDir(cfg.Dir)
	if err != nil {
		fail("cannot list %s: %v", cfg.Dir, err)
	}
	for _, e := range ents {
		if slices.Contains(cfg.Declared, e.Name()) {
			continue
		}
		if c, err := p.dial(ctx, e.Name()); err == nil {
			c.Close()
			fail("undeclared socket %s is reachable", e.Name())
		}
	}
	for _, name := range cfg.Declared {
		if ctx.Err() != nil {
			fail("probe stopped: %v", ctx.Err())
			return res
		}
		who, ok := p.ping(ctx, name)
		if !ok {
			fail("declared socket %s is not reachable", name)
			continue
		}
		for _, f := range Frames {
			got := p.send(ctx, name, f.Data)
			res.Sent = append(res.Sent, Sent{Socket: name, Frame: f.Name, Want: f.Want, Got: got})
			if got != f.Want {
				fail("%s on %s: got %q, want %q", f.Name, name, got, f.Want)
			}
			if again, ok := p.ping(ctx, name); !ok || !bytes.Equal(again, who) {
				fail("%s unresponsive after %s (or answered as another peer)", name, f.Name)
			}
		}
	}
	return res
}

type prober struct{ cfg Config }

func (p prober) dial(ctx context.Context, name string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	var d net.Dialer
	return d.DialContext(ctx, "unix", filepath.Join(p.cfg.Dir, name))
}

// exchange sends data on a fresh connection and reads one reply line.
func (p prober) exchange(ctx context.Context, name string, data []byte) (sockets.Response, bool) {
	c, err := p.dial(ctx, name)
	if err != nil {
		return sockets.Response{}, false
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(p.cfg.Timeout))
	// The broker may answer and close before reading all of an oversized
	// frame, so the write runs beside the read and its error is ignored.
	go c.Write(data)
	line, err := bufio.NewReaderSize(c, 4096).ReadBytes('\n')
	if err != nil {
		return sockets.Response{}, false
	}
	var r sockets.Response
	if json.Unmarshal(line, &r) != nil {
		return sockets.Response{}, false
	}
	return r, true
}

// send is the code a frame was refused with; "ok" if it was accepted, ""
// if nothing parseable came back.
func (p prober) send(ctx context.Context, name string, data []byte) sockets.Code {
	r, ok := p.exchange(ctx, name, data)
	switch {
	case !ok:
		return ""
	case r.OK:
		return "ok"
	}
	return sockets.Code(r.Error)
}

// ping is the ping op's result, the peer the broker sees.
func (p prober) ping(ctx context.Context, name string) (json.RawMessage, bool) {
	r, ok := p.exchange(ctx, name, []byte(`{"op":`+string(mustJSON(p.cfg.Ping))+"}\n"))
	return r.Result, ok && r.OK
}

func mustJSON(s string) []byte { b, _ := json.Marshal(s); return b }
