// Package conformance is the suite every device driver passes (DEVSLOT-drivers
// point 5). A driver's repository runs it at the pinned commit of this one:
// the declaration passes devslot.Check, a clean run against the driver's fake
// device writes only declared shapes, a canary key never leaves the driver,
// every parser survives bounded, mutated and random replies, and the driver's
// code imports no socket, file, process or unsafe package.
package conformance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
)

// Frame is one frame a fake device sends on a declared channel.
type Frame struct {
	Channel string
	Bytes   []byte
}

// Device is a driver's fake device, built from its own recorded traffic or
// notes. It knows the key the suite lends.
type Device interface {
	// Connect is what the device sends when an operation starts.
	Connect(op string) []Frame
	// Respond is what it sends after the driver writes frame on ch.
	Respond(ch string, frame []byte) []Frame
}

// Config is how the suite runs one driver.
type Config struct {
	// NewDevice builds a fresh fake device holding key.
	NewDevice func(key []byte) Device
	// Packages are the driver's import paths for the imports check; none
	// skips it (only this repository's own tests do that).
	Packages []string
	// Iterations is how many fuzzed runs each operation gets (default 300).
	Iterations int
	// Seed seeds the fuzzer, so a failure repeats.
	Seed uint64
}

// Problem is one way a driver fails the suite.
type Problem struct {
	Kind   string // declaration, clean-run, undeclared-write, canary, panic, imports
	Detail string
}

func (p Problem) String() string { return p.Kind + ": " + p.Detail }

// Canary is the key the suite lends: synthetic, and found in nothing.
var Canary = []byte("agentos-devslot-canary-key-00001")

// Run fails t with each problem Check finds.
func Run(t testing.TB, drv devslot.Driver, cfg Config) {
	t.Helper()
	for _, p := range Check(drv, cfg) {
		t.Error(p)
	}
}

// Check runs the suite on drv and returns its problems; none means it
// passes.
func Check(drv devslot.Driver, cfg Config) []Problem {
	var ps []Problem
	add := func(kind, format string, a ...any) { ps = append(ps, Problem{kind, fmt.Sprintf(format, a...)}) }
	d := drv.Declare()
	pin := pinFor(d.Link)
	if err := devslot.Check(d, pin); err != nil {
		add("declaration", "%v", err)
		return ps
	}
	if cfg.NewDevice == nil {
		add("clean-run", "no fake device")
		return ps
	}
	n := cfg.Iterations
	if n <= 0 {
		n = 300
	}
	r := rand.New(rand.NewPCG(cfg.Seed, 0x6465767))
	for _, op := range d.Operations {
		h := newHarness(drv, d, pin, op.Name, cfg.NewDevice(slices.Clone(Canary)), nil)
		_, err := h.slot.Do(context.Background(), op.Name)
		switch {
		case errors.Is(err, devslot.ErrUndeclared), errors.Is(err, devslot.ErrUnpinned),
			errors.Is(err, devslot.ErrTooLarge):
			add("undeclared-write", "%s: %v", op.Name, err)
		case errors.Is(err, devslot.ErrPanic):
			add("panic", "%s: clean run", op.Name)
		case err != nil:
			add("clean-run", "%s: %v", op.Name, err)
		}
		if where := h.leak(err); where != "" {
			add("canary", "%s: in %s", op.Name, where)
		}
		for i := range n {
			h := newHarness(drv, d, pin, op.Name, cfg.NewDevice(slices.Clone(Canary)), r)
			_, err := h.slot.Do(context.Background(), op.Name)
			if errors.Is(err, devslot.ErrPanic) {
				add("panic", "%s: fuzz run %d (seed %d)", op.Name, i, cfg.Seed)
				break
			}
			if where := h.leak(err); where != "" {
				add("canary", "%s: fuzz run %d, in %s", op.Name, i, where)
				break
			}
		}
	}
	for _, pkg := range cfg.Packages {
		for _, b := range bannedImports(pkg) {
			add("imports", "%s", b)
		}
	}
	return ps
}

func pinFor(l devslot.LinkKind) devslot.Pin {
	if l == devslot.TCP {
		return devslot.Pin{Host: netip.MustParseAddr("192.168.0.2"), Key: [32]byte{1}}
	}
	return devslot.Pin{Address: "02:00:00:00:00:01"}
}

// harness is one run: a fake transport between the slot and the device that
// records everything that could carry the key out.
type harness struct {
	slot    *devslot.Slot
	d       devslot.Declaration
	pin     devslot.Pin
	dev     Device
	fuzz    *rand.Rand
	queue   []Frame
	writes  [][]byte
	events  []devslot.Event
	logs    []string
	started bool
	op      string
}

func newHarness(drv devslot.Driver, d devslot.Declaration, pin devslot.Pin, op string, dev Device, fuzz *rand.Rand) *harness {
	h := &harness{d: d, pin: pin, dev: dev, fuzz: fuzz, op: op}
	lend := func(fn func(key []byte) error) error {
		k := slices.Clone(Canary)
		defer clear(k)
		return fn(k)
	}
	s, err := devslot.New(drv, devslot.Env{
		Pin: pin, Transport: h, Lend: lend,
		Emit: func(e devslot.Event) error { h.events = append(h.events, e); return nil },
		Log:  func(m string) { h.logs = append(h.logs, m) },
	})
	if err != nil {
		panic("conformance: checked declaration refused: " + err.Error())
	}
	h.slot = s
	return h
}

func (h *harness) push(fs []Frame) {
	for _, f := range fs {
		if h.fuzz != nil {
			f = h.mutate(f)
		}
		h.queue = append(h.queue, f)
	}
	if h.fuzz != nil && h.fuzz.IntN(4) == 0 {
		h.queue = append(h.queue, h.random())
	}
}

// mutate flips, truncates, extends or replaces a frame, within MaxRead.
func (h *harness) mutate(f Frame) Frame {
	b := slices.Clone(f.Bytes)
	switch h.fuzz.IntN(5) {
	case 0:
		if len(b) > 0 {
			b[h.fuzz.IntN(len(b))] ^= byte(1 << h.fuzz.IntN(8))
		}
	case 1:
		b = b[:h.fuzz.IntN(len(b)+1)]
	case 2:
		for range h.fuzz.IntN(16) + 1 {
			b = append(b, byte(h.fuzz.Uint32()))
		}
	case 3:
		return h.random()
	}
	if len(b) > h.d.MaxRead {
		b = b[:h.d.MaxRead]
	}
	return Frame{f.Channel, b}
}

func (h *harness) random() Frame {
	c := h.d.Channels[h.fuzz.IntN(len(h.d.Channels))]
	b := make([]byte, h.fuzz.IntN(min(h.d.MaxRead, 512)+1))
	for i := range b {
		b[i] = byte(h.fuzz.Uint32())
	}
	return Frame{c.Name, b}
}

func (h *harness) Write(_ context.Context, t devslot.Target, frame []byte) error {
	h.writes = append(h.writes, slices.Clone(frame))
	h.push(h.dev.Respond(t.Channel.Name, frame))
	return nil
}

// errNoFrame is a device with nothing more to say.
var errNoFrame = errors.New("conformance: no frame")

func (h *harness) Read(context.Context) (devslot.Target, []byte, error) {
	if !h.started {
		h.started = true
		h.push(h.dev.Connect(h.op))
	}
	if len(h.queue) == 0 {
		return devslot.Target{}, nil, errNoFrame
	}
	f := h.queue[0]
	h.queue = h.queue[1:]
	i := slices.IndexFunc(h.d.Channels, func(c devslot.Channel) bool { return c.Name == f.Channel })
	if i < 0 {
		return devslot.Target{}, nil, errNoFrame
	}
	return devslot.Target{Pin: h.pin, Channel: h.d.Channels[i]}, f.Bytes, nil
}

// leak names where the canary showed up, raw or encoded, if anywhere.
func (h *harness) leak(err error) string {
	forms := [][]byte{Canary, []byte(hex.EncodeToString(Canary)), []byte(strings.ToUpper(hex.EncodeToString(Canary))),
		[]byte(base64.StdEncoding.EncodeToString(Canary)), []byte(base64.RawURLEncoding.EncodeToString(Canary))}
	has := func(b []byte) bool {
		for _, f := range forms {
			if bytes.Contains(b, f) {
				return true
			}
		}
		return false
	}
	for _, w := range h.writes {
		if has(w) {
			return "a written frame"
		}
	}
	if err != nil && has([]byte(err.Error())) {
		return "an error"
	}
	for _, e := range h.events {
		if has(fmt.Appendf(nil, "%+v", e)) {
			return "an event"
		}
	}
	for _, l := range h.logs {
		if has([]byte(l)) {
			return "a log line"
		}
	}
	return ""
}

// banned is what driver code may not import: sockets, files, processes,
// unsafe memory, cgo, plugins and logs. Its one reach is the Link.
func banned(p string) bool {
	switch {
	case p == "net/netip":
		return false
	case p == "net", strings.HasPrefix(p, "net/"), p == "os", strings.HasPrefix(p, "os/"),
		p == "syscall", p == "unsafe", p == "plugin", p == "C", p == "runtime/cgo",
		p == "io/ioutil", p == "path/filepath", p == "log", strings.HasPrefix(p, "log/"):
		return true
	}
	return false
}

// slotSide is the public code a driver links on purpose; everything else
// it links is held to the ban.
var slotSide = map[string]bool{
	"github.com/ghbmrk/agentos/broker/clerk/devslot":             true,
	"github.com/ghbmrk/agentos/broker/clerk/devslot/conformance": true,
	"github.com/ghbmrk/agentos/broker/kernel/key":                true,
}

// bannedImports lists each banned import of pkg's own code and of every
// non-standard package it links, except the slot's own.
func bannedImports(pkg string) []string {
	out, err := exec.Command("go", "list", "-deps", "-f",
		"{{.ImportPath}}|{{.Standard}}|{{join .Imports \" \"}}", pkg).CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("go list %s: %v", pkg, err)}
	}
	var bad []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "|", 3)
		if len(f) != 3 || f[1] == "true" || slotSide[f[0]] {
			continue
		}
		for _, imp := range strings.Fields(f[2]) {
			if banned(imp) {
				bad = append(bad, f[0]+" imports "+imp)
			}
		}
	}
	return bad
}
