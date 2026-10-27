// Package conformance is the suite every device driver passes (DEVSLOT-drivers
// point 5). A driver's repository runs it at the pinned commit of this one:
// the declaration passes devslot.Check, a clean run against the driver's fake
// device writes only declared shapes, a canary key never leaves the driver,
// every parser survives bounded, mutated and random replies, and the driver's
// code imports only allowed standard packages (allowedStd).
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

// forms are the canary as raw bytes, hex, and base64 at each of its three
// alignments (the characters fixed by the key alone), standard and URL.
func forms() [][]byte {
	fs := [][]byte{Canary, []byte(hex.EncodeToString(Canary)), []byte(strings.ToUpper(hex.EncodeToString(Canary)))}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for a := range 3 {
			e := enc.EncodeToString(append(make([]byte, a), Canary...))
			if a > 0 {
				e = e[4:]
			}
			fs = append(fs, []byte(e[:len(e)-4]))
		}
	}
	return fs
}

// leak names where the canary showed up, raw or encoded, if anywhere. The
// written frames are also searched as one stream, with and without their
// shapes' prefixes, so a key split across frames is found.
func (h *harness) leak(err error) string {
	fs := forms()
	has := func(b []byte) bool {
		for _, f := range fs {
			if bytes.Contains(b, f) {
				return true
			}
		}
		return false
	}
	var tails [][]byte
	for _, w := range h.writes {
		cut := 0
		for _, sh := range h.d.Shapes {
			if bytes.HasPrefix(w, sh.Prefix) {
				cut = max(cut, len(sh.Prefix))
			}
		}
		tails = append(tails, w[cut:])
	}
	if has(bytes.Join(h.writes, nil)) || has(bytes.Join(tails, nil)) {
		return "a written frame"
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

// slotSide is the public code a driver links on purpose; everything else
// it links is held to allowedStd.
var slotSide = map[string]bool{
	"github.com/ghbmrk/agentos/broker/clerk/devslot":             true,
	"github.com/ghbmrk/agentos/broker/clerk/devslot/conformance": true,
	"github.com/ghbmrk/agentos/broker/kernel/key":                true,
}

// allowedStd is every standard package driver code may import: framing,
// encoding, hashing and crypto primitives, and the language's own helpers.
// Anything else (sockets, TLS and certificate pools, files, templates that
// read files, archives, processes, unsafe memory, cgo, plugins, logs, heap
// dumps) fails, so a driver's one reach is its Link.
var allowedStd = map[string]bool{}

func init() {
	for _, p := range strings.Fields(`bufio bytes cmp container/heap container/list container/ring context
		crypto crypto/aes crypto/cipher crypto/des crypto/ecdh crypto/ecdsa crypto/ed25519 crypto/elliptic
		crypto/hkdf crypto/hmac crypto/md5 crypto/mlkem crypto/pbkdf2 crypto/rand crypto/rsa crypto/sha1
		crypto/sha256 crypto/sha3 crypto/sha512 crypto/subtle
		encoding encoding/asn1 encoding/base32 encoding/base64 encoding/binary encoding/hex encoding/json encoding/pem
		errors fmt hash hash/adler32 hash/crc32 hash/crc64 hash/fnv hash/maphash io iter maps
		math math/big math/bits math/rand/v2 net/netip regexp slices sort strconv strings sync sync/atomic
		time unicode unicode/utf16 unicode/utf8`) {
		allowedStd[p] = true
	}
}

// bannedImports lists each standard import off allowedStd made by pkg's own
// code or any non-standard package it links, except the slot's own, and any
// such package with Go files the build skipped: a file under a build tag or
// for another target could import anything once built for the box.
func bannedImports(pkg string) []string {
	out, err := exec.Command("go", "list", "-deps", "-f",
		"{{.ImportPath}}|{{.Standard}}|{{join .Imports \" \"}}|{{join .IgnoredGoFiles \" \"}}{{join .CgoFiles \" \"}}", pkg).CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("go list %s: %v", pkg, err)}
	}
	type entry struct{ path, imports, ignored string }
	std := map[string]bool{}
	var own []entry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "|", 4)
		if len(f) != 4 {
			continue
		}
		if f[1] == "true" {
			std[f[0]] = true
		} else if !slotSide[f[0]] {
			own = append(own, entry{f[0], f[2], f[3]})
		}
	}
	var bad []string
	for _, e := range own {
		if strings.TrimSpace(e.ignored) != "" {
			bad = append(bad, e.path+" has files the build skipped or cgo files: "+e.ignored)
		}
		for _, imp := range strings.Fields(e.imports) {
			if (std[imp] || imp == "C" || !strings.Contains(strings.SplitN(imp, "/", 2)[0], ".")) && !allowedStd[imp] {
				bad = append(bad, e.path+" imports "+imp)
			}
		}
	}
	return bad
}
