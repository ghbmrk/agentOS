package proc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// tracking is a synced RPY_TRACKING reply to request seq: the box clock
// corr seconds slow (negative: fast), root delay 2 ms, root dispersion 1 ms.
// The floats are chrony 4.5's UTI_FloatHostToNetwork encodings.
func tracking(seq uint32, corr uint32) []byte {
	p := make([]byte, chronyLen)
	be := binary.BigEndian
	p[0], p[1] = 6, 2
	be.PutUint16(p[4:], chronyTracking)
	be.PutUint16(p[6:], chronyRpy)
	be.PutUint32(p[16:], seq)
	be.PutUint32(p[28:], 0xC0000201) // a reference id: 192.0.2.1
	be.PutUint16(p[52:], 2)          // stratum
	be.PutUint32(p[68:], corr)
	be.PutUint32(p[92:], 0xf283126f) // 0.002
	be.PutUint32(p[96:], 0xf083126f) // 0.001
	return p
}

const (
	corrZero    = 0x00000000 // 0 s
	corrTwoDays = 0x27574000 // -172800 s: the box clock two days fast
	corrTwoSlow = 0x26a8c000 // 172800 s: the box clock two days slow
)

// fakeChronyd answers each well-formed REQ_TRACKING at dir/chronyd.sock with
// reply(seq); a nil reply answers nothing.
func fakeChronyd(t *testing.T, dir string, reply func(seq uint32) []byte) string {
	t.Helper()
	sock := filepath.Join(dir, "chronyd.sock")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		q := make([]byte, 512)
		for {
			n, from, err := l.ReadFromUnix(q)
			if err != nil {
				return
			}
			be := binary.BigEndian
			if n != chronyLen || q[0] != 6 || q[1] != 1 || be.Uint16(q[4:]) != chronyTracking || from == nil {
				continue
			}
			if p := reply(be.Uint32(q[8:])); p != nil {
				l.WriteToUnix(p, from)
			}
		}
	}()
	return sock
}

// The protocol's float decodes as chrony's own decoder reads chrony's
// encodings (UTI_FloatHostToNetwork, UTI_FloatNetworkToHost, chrony 4.5).
//
// REQ: TIM-1
func TestTIM1AChronyFloat(t *testing.T) {
	for _, v := range []struct {
		x    uint32
		want float64
	}{
		{0x00000000, 0}, {0x04800000, 1}, {0x03000000, -1}, {0x02800000, 0.5},
		{0x27574000, -172800}, {0xea80f990, 0.0001230000052601099},
		{0xcb0f7b59, -3.5000000675466936e-09}, {0x24a8c020, 86400.25},
		{0xf283126f, 0.0020000000949949026}, {0xf083126f, 0.0010000000474974513}, {0x3cbebc20, 4e8},
		{0x80800000, math.Ldexp(1, -66)}, // the least negative exponent, -64
	} {
		if got := chronyFloat(v.x); got != v.want {
			t.Errorf("chronyFloat(%#08x) = %v, want %v", v.x, got, v.want)
		}
	}
}

// Only a well-formed answer to this request from a chronyd synced to a
// source vouches for a lower bound; anything else reads as no second source
// (TIM-1).
//
// REQ: TIM-1
func TestTIM1AChronyReplyGivesNoLowerBoundUnlessSynced(t *testing.T) {
	if c, b, ok := parseTracking(tracking(9, corrTwoDays), 9); !ok || c != -172800 || math.Abs(b-0.002) > 1e-6 {
		t.Fatalf("a synced reply read %v ± %v, %v", c, b, ok)
	}
	put16 := func(at int, v uint16) func([]byte) []byte {
		return func(p []byte) []byte { binary.BigEndian.PutUint16(p[at:], v); return p }
	}
	put32 := func(at int, v uint32) func([]byte) []byte {
		return func(p []byte) []byte { binary.BigEndian.PutUint32(p[at:], v); return p }
	}
	for name, bad := range map[string]func([]byte) []byte{
		"unsynced":                    put16(54, chronyUnsynced),
		"stratum 0":                   put16(52, 0),
		"local reference":             put32(28, chronyLocal),
		"version 5":                   func(p []byte) []byte { p[0] = 5; return p },
		"a request":                   func(p []byte) []byte { p[1] = 1; return p },
		"another command":             put16(4, 34),
		"another reply":               put16(6, 6),
		"a failure status":            put16(8, 1),
		"another sequence":            put32(16, 8),
		"short":                       func(p []byte) []byte { return p[:chronyLen-1] },
		"long":                        func(p []byte) []byte { return append(p, 0) },
		"a bound past days":           put32(96, 0x24a8c020), // 86400.25 s
		"a negative bound":            put32(96, 0x03000000), // -1 s
		"a correction past ten years": put32(68, 0x3cbebc20), // 4e8 s,
	} {
		if _, _, ok := parseTracking(bad(tracking(9, corrZero)), 9); ok {
			t.Errorf("%s: read as synced", name)
		}
	}
	// The limits themselves are in: a bound of none or of a day, and a
	// correction of ten years either way.
	for name, edge := range map[string]func([]byte) []byte{
		"no bound":         func(p []byte) []byte { return put32(96, 0)(put32(92, 0)(p)) },
		"a bound of a day": func(p []byte) []byte { return put32(96, 0x32015180)(put32(92, 0)(p)) }, // 86400 s
		"ten years slow":   put32(68, 0x4212cc03),                                                   // 315360000 s
		"ten years fast":   put32(68, 0x43ed33fd),                                                   // -315360000 s
	} {
		if _, _, ok := parseTracking(edge(tracking(9, corrZero)), 9); !ok {
			t.Errorf("%s: refused", name)
		}
	}

	dir := t.TempDir()
	s := NewChrony(filepath.Join(dir, "none.sock"), filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	before := time.Now().UnixMilli()
	if r := unstamped(s.Sample()); r.Earliest != 0 || r.Latest < before {
		t.Fatalf("no chronyd read %+v, want no lower bound and the box clock", r)
	}

	// A chronyd that never answers delays one decision by its wait, then
	// none for the retry interval.
	mute := NewChrony(fakeChronyd(t, dir, func(uint32) []byte { return nil }), filepath.Join(dir, "mute.sock"))
	defer closeChrony(mute)
	if r := unstamped(mute.Sample()); r.Earliest != 0 {
		t.Fatalf("a mute chronyd read %+v", r)
	}
	start := time.Now()
	if r := unstamped(mute.Sample()); r.Earliest != 0 || time.Since(start) >= chronyWait {
		t.Fatalf("a mute chronyd was asked again at once: %+v after %v", r, time.Since(start))
	}
}

// A synced chronyd's reading is the hull of its interval and the box clock:
// agreeing, it is the box clock within the bound; the box two days fast, it
// spans the two days, the guard's restricted mode (TIM-1).
//
// REQ: TIM-1
func TestTIM1AChronyReadsTheHullOfBothSources(t *testing.T) {
	dir := t.TempDir()
	var corr atomic.Uint32 // the fake's goroutine reads it
	corr.Store(corrZero)
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte { return tracking(seq, corr.Load()) }), filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	b0 := time.Now().UnixMilli()
	r := unstamped(s.Sample())
	b1 := time.Now().UnixMilli()
	if r.Earliest < b0-3 || r.Earliest > b1 || r.Latest < b0 || r.Latest > b1+3 {
		t.Fatalf("an agreeing chronyd read %+v around the box's [%d, %d]", r, b0, b1)
	}
	corr.Store(corrTwoDays)
	b0 = time.Now().UnixMilli()
	r = unstamped(s.Sample())
	b1 = time.Now().UnixMilli()
	if r.Earliest < b0-2*key.DayMS-3 || r.Earliest > b1-2*key.DayMS || r.Latest < b0 || r.Latest > b1 {
		t.Fatalf("a box two days fast read %+v around the box's [%d, %d]", r, b0, b1)
	}
}

// The reply socket is connected to chronyd's, so the host kernel refuses a
// datagram to it from any other socket: a forged report never reaches the
// kernel (TIM-1).
//
// REQ: TIM-1
func TestTIM1AOnlyChronydReachesTheReplySocket(t *testing.T) {
	dir := t.TempDir()
	reply := filepath.Join(dir, "reply.sock")
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte { return tracking(seq, corrZero) }), reply)
	defer closeChrony(s)
	if r := unstamped(s.Sample()); r.Earliest == 0 {
		t.Fatalf("chronyd's answer read %+v", r)
	}
	forger, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: reply, Net: "unixgram"})
	if err == nil {
		defer forger.Close()
		_, err = forger.Write(tracking(s.seq+1, corrTwoDays))
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("a forger sent to the reply socket: %v, want EPERM", err)
	}
}

// The issue's acceptance (#5391, KEY-8): the box clock two days fast at a
// kernel start, with chronyd synced and disagreeing, puts the kernel in
// restricted mode (the logged reading spans the two days) and ends no hold
// early (a grant's hold of a day, issued just before the start, is still
// running at the time the kernel logs). Without the second source, the same
// start ends it, which is what the kernel can do alone.
//
// REQ: TIM-1, KEY-8, KEY-4
func TestTIM1AStartAheadWithChronySyncedEndsNoHoldEarly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: pub, Sign: priv, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	// A grant issued now holds for GrantHold; the box clock is two days
	// fast at this start, and chronyd says so.
	truth := time.Now().UnixMilli() - 2*key.DayMS
	if _, err := l.Append(truth-1000, kernel.TStop, 1, struct{}{}); err != nil {
		t.Fatal(err)
	}
	from := truth + kernel.GrantHold
	dir := t.TempDir()
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte { return tracking(seq, corrTwoDays) }), filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	box := time.Now().UnixMilli()
	r := onLog(l, s.Sample)()
	if r.Earliest >= from {
		t.Fatalf("the start read %+v, past the hold's end %d: the box clock ended it early", r, from)
	}
	if r.Latest < box || r.Latest-r.Earliest < 2*key.DayMS-1000 {
		t.Fatalf("the reading %+v does not span the two days to the box's %d: not restricted", r, box)
	}

	// The box clock alone vouches for nothing, so a start reads it as before:
	// that is the hold ending early that the second source prevents.
	if r := onLog(l, NewChrony("", "").Sample)(); r.Earliest < from {
		t.Fatalf("without chronyd the start read %+v, before the hold's end %d: the contrast is gone", r, from)
	}
}

// The box clock two days slow, chronyd's interval lies wholly past it: the
// reading's Latest is the box clock plus the correction and the bound, so a
// wider bound reaches further (TIM-1).
//
// REQ: TIM-1
func TestTIM1AChronyAheadOfTheBoxReachesPastItByTheBound(t *testing.T) {
	dir := t.TempDir()
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte {
		p := tracking(seq, corrTwoSlow)
		binary.BigEndian.PutUint32(p[92:], 0)          // root delay none
		binary.BigEndian.PutUint32(p[96:], 0x04800000) // root dispersion 1 s
		return p
	}), filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	b0 := time.Now().UnixMilli()
	r := unstamped(s.Sample())
	b1 := time.Now().UnixMilli()
	reach := 2*key.DayMS + 1000 // the correction, then the bound's 1 s
	if r.Earliest < b0 || r.Earliest > b1 || r.Latest < b0+reach || r.Latest > b1+reach {
		t.Fatalf("a box two days slow read %+v around the box's [%d, %d], want Latest %d past it", r, b0, b1, reach)
	}
}

// With the box clock ahead, the reading's Earliest is the box clock less
// the correction and the bound, so a wider bound reaches further back
// (TIM-1). Revert mutant: chrony.go:55's corr-err as corr+err.
//
// REQ: TIM-1
func TestTIM1AChronyBehindTheBoxReachesBeforeItByTheBound(t *testing.T) {
	dir := t.TempDir()
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte {
		p := tracking(seq, corrTwoDays)
		binary.BigEndian.PutUint32(p[92:], 0)          // root delay none
		binary.BigEndian.PutUint32(p[96:], 0x04800000) // root dispersion 1 s
		return p
	}), filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	b0 := time.Now().UnixMilli()
	r := unstamped(s.Sample())
	b1 := time.Now().UnixMilli()
	reach := 2*key.DayMS + 1000 // the correction, then the bound's 1 s
	if r.Earliest < b0-reach || r.Earliest > b1-reach || r.Latest < b0 || r.Latest > b1 {
		t.Fatalf("a box two days fast read %+v around the box's [%d, %d], want Earliest %d before it", r, b0, b1, reach)
	}
}

// Each request carries a new sequence number from 1, so an answer to an
// earlier request, replayed, vouches for nothing (TIM-1).
//
// REQ: TIM-1
func TestTIM1AChronyRefusesAnAnswerToAnEarlierRequest(t *testing.T) {
	dir := t.TempDir()
	s := NewChrony(fakeChronyd(t, dir, func(uint32) []byte { return tracking(1, corrZero) }), filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	if r := unstamped(s.Sample()); r.Earliest == 0 {
		t.Fatalf("the answer to the first request read %+v", r)
	}
	if r := unstamped(s.Sample()); r.Earliest != 0 {
		t.Fatalf("the first answer replayed to the second request read %+v", r)
	}
}

// The reply socket replaces a stale file a crash left at its path and is
// open to chronyd's uid (0666); Close closes it and removes its file, and a
// later Read binds it again. A failed answer drops the socket the same way.
//
// REQ: TIM-1
func TestTIM1AChronyReplySocketLifecycle(t *testing.T) {
	dir := t.TempDir()
	var synced atomic.Bool
	synced.Store(true)
	reply := filepath.Join(dir, "reply.sock")
	if err := os.WriteFile(reply, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte {
		p := tracking(seq, corrZero)
		if !synced.Load() {
			binary.BigEndian.PutUint16(p[54:], chronyUnsynced)
		}
		return p
	}), reply)
	defer closeChrony(s)
	if r := unstamped(s.Sample()); r.Earliest == 0 {
		t.Fatalf("over a stale file the reply socket read %+v", r)
	}
	if fi, err := os.Stat(reply); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o666 {
		t.Fatalf("the reply socket is %v, %v: want a socket of mode 0666", fi, err)
	}
	closed := func(c *net.UnixConn, when string) {
		t.Helper()
		if s.c != nil {
			t.Fatalf("%s: the socket is still held", when)
		}
		if _, err := c.Write(make([]byte, chronyLen)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s: the old socket still writes: %v", when, err)
		}
		if _, err := os.Lstat(reply); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the reply socket's file is left: %v", when, err)
		}
	}
	c := s.c
	closeChrony(s)
	closed(c, "closed")

	// Closing leaves Read usable: it binds the socket again.
	done := make(chan kernel.Reading, 1)
	go func() { done <- unstamped(s.Sample()) }()
	select {
	case r := <-done:
		if r.Earliest == 0 {
			t.Fatalf("a Read after closing read %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a Read after closing never returned: closing kept the lock")
	}

	c = s.c
	synced.Store(false)
	if r := unstamped(s.Sample()); r.Earliest != 0 {
		t.Fatalf("an unsynced chronyd read %+v", r)
	}
	closed(c, "after a failed answer")
}

// A chronyd gone since its last answer refuses the next request at once:
// the decision waits for no reply (TIM-1).
//
// REQ: TIM-1
func TestTIM1AChronyGoneFailsWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "chronyd.sock")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		q := make([]byte, 512)
		if n, from, err := l.ReadFromUnix(q); err == nil && n == chronyLen {
			l.WriteToUnix(tracking(binary.BigEndian.Uint32(q[8:]), corrZero), from)
		}
	}()
	s := NewChrony(sock, filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	if r := unstamped(s.Sample()); r.Earliest == 0 {
		t.Fatalf("chronyd's answer read %+v", r)
	}
	l.Close()
	start := time.Now()
	if r := unstamped(s.Sample()); r.Earliest != 0 || time.Since(start) >= chronyWait {
		t.Fatalf("a gone chronyd read %+v after %v", r, time.Since(start))
	}
}

// closeChrony closes s's reply socket and removes its file.
func closeChrony(s *Chrony) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop()
}

// RunKernel reads chronyd at the sockets its config names (#5391, #5757 L3
// round 2): kernelSource reads a synced chronyd at cfg.Chrony, answered at
// cfg.ChronyReply, and the box clock alone without them; RunKernel hands
// OpenKernel that source as its Source, which carries each sample's Stamp.
// Killed by hand: kernelSource's arguments empty or swapped, and RunKernel's
// Source set to anything else or handed as its Clock.
//
// REQ: TIM-1
func TestTIM1ARunKernelReadsChronydAtItsConfiguredSocket(t *testing.T) {
	dir := t.TempDir()
	cfg := MainConfig{Chrony: fakeChronyd(t, dir, func(seq uint32) []byte { return tracking(seq, corrTwoDays) }), ChronyReply: filepath.Join(dir, "reply.sock")}
	box := time.Now().UnixMilli()
	if r := unstamped(kernelSource(cfg)()); r.Earliest == 0 || r.Earliest > box-2*key.DayMS+1000 || r.Latest < box {
		t.Fatalf("the configured chronyd read %+v: want two days behind the box's %d", r, box)
	}
	if r := unstamped(kernelSource(MainConfig{})()); r.Earliest != 0 || r.Latest < box {
		t.Fatalf("no chronyd read %+v: want the box clock alone", r)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "kernelmain.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var clocks []string
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "RunKernel" {
			ast.Inspect(fn, func(n ast.Node) bool {
				if kv, ok := n.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok && (k.Name == "Source" || k.Name == "Clock") {
						if c, ok := kv.Value.(*ast.CallExpr); ok && len(c.Args) == 1 {
							fun, ok1 := c.Fun.(*ast.Ident)
							if a, ok2 := c.Args[0].(*ast.Ident); ok1 && ok2 {
								clocks = append(clocks, k.Name+": "+fun.Name+"("+a.Name+")")
								return true
							}
						}
						clocks = append(clocks, "other")
					}
				}
				return true
			})
		}
	}
	if len(clocks) != 1 || clocks[0] != "Source: kernelSource(cfg)" {
		t.Fatalf("RunKernel hands OpenKernel the clocks %q: want Source: kernelSource(cfg) alone", clocks)
	}
}

// The Stamp is the reply's reference time as sent, zero for the box clock
// alone; over onLog a kernel started two days behind catches up
// only on a new reference time, not on a correction that changes while the
// sample stays the same (an unseen box step), and not on the zero Stamp
// (#5759).
//
// REQ: TIM-1, KEY-7, KEY-8
func TestTIM1AChronyRisesOnlyOnANewReferenceTime(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: pub, Sign: priv, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	var corr, ref atomic.Uint32
	corr.Store(corrTwoDays)
	ref.Store(0x65000000)
	dir := t.TempDir()
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte {
		p := tracking(seq, corr.Load())
		binary.BigEndian.PutUint32(p[60:], ref.Load()) // ref time's low seconds
		binary.BigEndian.PutUint32(p[64:], 123)        // and its nanoseconds
		return p
	}), filepath.Join(dir, "reply.sock"))
	defer closeChrony(s)
	r, st := s.Sample()
	if want := (Stamp{4: 0x65, 11: 123}); r.Earliest == 0 || st != want {
		t.Fatalf("a synced reply read %+v stamped %x, want %x", r, st, want)
	}

	box := time.Now().UnixMilli()
	w := onLog(l, s.Sample) // the box two days fast: Earliest two days back
	if r := w(); r.Earliest > box-2*key.DayMS+1000 {
		t.Fatalf("the start read %+v", r)
	}
	corr.Store(corrZero) // chronyd's correction follows, its sample does not
	if r := w(); r.Earliest > box-2*key.DayMS+60_000 {
		t.Fatalf("a changed correction on the same sample read %+v: Earliest rose", r)
	}
	if r, st := NewChrony("", "").Sample(); r.Earliest != 0 || st != (Stamp{}) {
		t.Fatalf("the box clock alone read %+v stamped %x", r, st)
	}
	ref.Add(64)
	if r := w(); r.Earliest < box-3 {
		t.Fatalf("a new sample read %+v: Earliest did not rise to the box's %d", r, box)
	}
}

// OpenKernel reads its Source, else its Clock on no sample, else none: a
// plain Clock never vouches for a fresh sample (#5759).
//
// REQ: TIM-1
func TestTIM1AKernelConfigSource(t *testing.T) {
	if (KernelConfig{}).source() != nil {
		t.Fatal("no clock gave a source")
	}
	plain := KernelConfig{Clock: func() kernel.Reading { return kernel.At(7) }}
	if src := plain.source(); src == nil {
		t.Fatal("a Clock gave no source")
	} else if r, st := src(); r != kernel.At(7) || st != (Stamp{}) {
		t.Fatalf("a Clock read %+v stamped %x: want its reading on no sample", r, st)
	}
	plain.Source = func() (kernel.Reading, Stamp) { return kernel.At(9), Stamp{11: 1} }
	if r, st := plain.source()(); r != kernel.At(9) || st != (Stamp{11: 1}) {
		t.Fatalf("with a Source set the source read %+v stamped %x: want the Source", r, st)
	}
	if onLog(nil, nil) != nil {
		t.Fatal("no source gave a clock")
	}
}
