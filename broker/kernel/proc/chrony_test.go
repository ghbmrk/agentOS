package proc

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
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

	dir := t.TempDir()
	s := NewChrony(filepath.Join(dir, "none.sock"), filepath.Join(dir, "reply.sock"))
	defer s.Close()
	before := time.Now().UnixMilli()
	if r := s.Read(); r.Earliest != 0 || r.Latest < before {
		t.Fatalf("no chronyd read %+v, want no lower bound and the box clock", r)
	}

	// A chronyd that never answers delays one decision by its wait, then
	// none for the retry interval.
	mute := NewChrony(fakeChronyd(t, dir, func(uint32) []byte { return nil }), filepath.Join(dir, "mute.sock"))
	defer mute.Close()
	if r := mute.Read(); r.Earliest != 0 {
		t.Fatalf("a mute chronyd read %+v", r)
	}
	start := time.Now()
	if r := mute.Read(); r.Earliest != 0 || time.Since(start) >= chronyWait {
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
	defer s.Close()
	b0 := time.Now().UnixMilli()
	r := s.Read()
	b1 := time.Now().UnixMilli()
	if r.Earliest < b0-3 || r.Earliest > b1 || r.Latest < b0 || r.Latest > b1+3 {
		t.Fatalf("an agreeing chronyd read %+v around the box's [%d, %d]", r, b0, b1)
	}
	corr.Store(corrTwoDays)
	b0 = time.Now().UnixMilli()
	r = s.Read()
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
	defer s.Close()
	if r := s.Read(); r.Earliest == 0 {
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
	b := newBBox(t, recipientWire(t, testRK))
	truth := func() int64 { return time.Now().UnixMilli() - 2*key.DayMS }
	b.cfg.Clock = func() kernel.Reading { return kernel.At(truth()) }
	b.restart()
	root := key.Issue(key.Ed25519Signer(ownerPriv), key.Root{Clerk: "mail", Verbs: []key.Verb{key.Send}, Serial: "r1"})
	ck, err := key.ClerkKey(root, key.Ed25519Signer(ownerPriv), holderPub, truth(), 1<<50)
	if err != nil {
		t.Fatal(err)
	}
	cos := []key.Cosign{key.Approve(key.Ed25519Signer(ownerPriv), kernel.BatchHash(root, ck)), key.Approve(key.Ed25519Signer(sparePriv), kernel.BatchHash(root, ck))}
	var from int64
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.h.With(func(k *kernel.Kernel) error {
		if err := k.Issue(b.now, cos, root, ck); err != nil {
			return err
		}
		var ok bool
		if from, ok = k.State().Granted(root.Tip()); !ok || from < truth()+kernel.GrantHold-1000 {
			t.Fatalf("the grant is live from %d, %v: want a day's hold from now", from, ok)
		}
		return nil
	}))

	// The box clock is two days fast at this start; chronyd says so.
	dir := t.TempDir()
	s := NewChrony(fakeChronyd(t, dir, func(seq uint32) []byte { return tracking(seq, corrTwoDays) }), filepath.Join(dir, "reply.sock"))
	defer s.Close()
	b.cfg.Clock = s.Read
	b.restart()
	box := time.Now().UnixMilli()
	stop := func() kernel.Entry {
		var e kernel.Entry
		must(b.h.With(func(k *kernel.Kernel) error {
			if err := k.Stop(b.now); err != nil {
				return err
			}
			es := k.Log().Entries()
			e = es[len(es)-1]
			return nil
		}))
		return e
	}
	e := stop()
	if e.At >= from {
		t.Fatalf("the kernel logged at %d, past the hold's end %d: the box clock ended it early", e.At, from)
	}
	if e.Late == nil || *e.Late < box || *e.Late-e.At < 2*key.DayMS-1000 {
		t.Fatalf("the reading [%d, %v] does not span the two days to the box's %d: not restricted", e.At, e.Late, box)
	}

	// The box clock alone vouches for nothing, so a start reads it as before:
	// that is the hold ending early that the second source prevents.
	b.cfg.Clock = func() kernel.Reading { return kernel.Reading{Latest: time.Now().UnixMilli()} }
	b.restart()
	if e := stop(); e.At < from {
		t.Fatalf("without chronyd the start logged at %d, before the hold's end %d: the contrast is gone", e.At, from)
	}
}
