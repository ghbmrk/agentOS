package channel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// REQ: NET-2, DEV-2

var allVerbs = []wire.Verb{wire.VerbOn, wire.VerbOff, wire.VerbLevel, wire.VerbLock, wire.VerbShut, wire.VerbClose, wire.VerbReturnToDock}

func cmd(id uint64, device string, v wire.Verb) wire.Command {
	c := wire.Command{ID: id, Device: device, Verb: v}
	if v == wire.VerbLevel {
		c.Level = 50
	}
	return c
}

// TestOnlyThreeKinds (NET-2 Channel, DEV-2): the channel acts only on a
// device command, a closed-list tightening or a read. A loosening or a
// rule change sent as a tightening is refused and logged and the policy
// is unchanged; an unlock, disarm, arm or open has no verb, so its frame,
// like any unknown type or overlong frame, ends the connection and is
// logged, and nothing reaches the radio. Catches channel widening.
// Revert mutants: a verb byte past VerbReturnToDock accepted by
// wire.Decode; Tighten applied without the engine's classification.
func TestOnlyThreeKinds(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()

	// The three kinds act.
	if c := cl.code(cmd(1, "lamp", wire.VerbOn)); c != wire.OK {
		t.Fatalf("everyday command: %v", c)
	}
	if c := cl.code(wire.Tighten{ID: 2, Kind: wire.RemoveDestination, Device: "tv", Host: "ads.example"}); c != wire.OK {
		t.Fatalf("closed-list tightening: %v", c)
	}
	if rep, ok := cl.do(wire.Read{ID: 3, What: wire.ReadState, Device: "lamp"}).(wire.ReadReply); !ok || string(rep.Body) != "state of lamp" {
		t.Fatalf("read: %+v", rep)
	}
	before := r.eng.Current()

	// A loosening or a rule change dressed as a tightening.
	for name, m := range map[string]wire.Tighten{
		"widen a rule's window":      {ID: 4, Kind: wire.NarrowRule, Device: "lock", Rule: "plumber", FromMS: 0, ToMS: 1 << 51},
		"move a rule to another day": {ID: 5, Kind: wire.NarrowRule, Device: "lock", Rule: "plumber", FromMS: 1 << 51, ToMS: 1 << 52},
		"remove an absent host":      {ID: 6, Kind: wire.RemoveDestination, Device: "tv", Host: "evil.example"},
		"rule moved to a device":     {ID: 7, Kind: wire.RevokeRule, Device: "lamp", Rule: "plumber"},
		"remove a pair never signed": {ID: 8, Kind: wire.RemovePair, A: "lamp", B: "tv"},
		"device not in the policy":   {ID: 9, Kind: wire.IsolateDevice, Device: "stranger"},
	} {
		if c := cl.code(m); c != wire.Refused {
			t.Errorf("%s: %v, want refused", name, c)
		}
	}
	if !reflect.DeepEqual(r.eng.Current(), before) {
		t.Fatal("a refused tightening changed the policy")
	}

	// Every type byte the core may not send, an unlock-shaped verb, a
	// waypoint-shaped tail and an overlong frame each end the connection.
	good, _ := wire.Encode(wire.ToEnforcer, cmd(10, "lock", wire.VerbLock))
	raws := map[string][]byte{
		"overlong command": frameBytes(wire.TCommand, make([]byte, 300)),
		"lying length":     {byte(wire.TCommand), 0xff, 0xff, 0xff, 0xff},
		"trailing bytes":   frameBytes(wire.TCommand, append(slices.Clone(good.Payload), 1, 2, 3, 4)),
		"second hello":     helloFrame(t, r),
	}
	for v := int(wire.VerbReturnToDock) + 1; v < 256; v += 37 {
		p := slices.Clone(good.Payload)
		p[8] = byte(v) // the verb: unlock, disarm, arm and open have no value
		raws[fmt.Sprintf("verb %d", v)] = frameBytes(wire.TCommand, p)
	}
	for ty := 0; ty < 256; ty++ {
		switch wire.Type(ty) {
		case wire.TCommand, wire.TTighten, wire.TRead, wire.TAnnounce, wire.THead, wire.TEntry, wire.TAnswer:
			continue
		}
		raws[fmt.Sprintf("type %d", ty)] = frameBytes(wire.Type(ty), good.Payload)
	}
	n := len(r.radio.calls())
	for name, raw := range raws {
		r.advance(time.Hour) // the hello and refusal buckets are not under test here
		cl := r.dial()
		if !cl.closed(raw) {
			t.Errorf("%s: connection not ended", name)
		}
	}
	if len(r.radio.calls()) != n {
		t.Errorf("a refused frame reached the radio: %v", r.radio.calls()[n:])
	}
	var logged int
	for _, e := range r.events() {
		if e.Kind == KindFrame && e.Code == wire.Refused {
			logged++
		}
	}
	if logged != len(raws) {
		t.Errorf("logged %d refused frames, want %d", logged, len(raws))
	}
	// Each is outside the format definition, so each trips the core
	// (NET-2 The channel, D-255). Revert mutant: malformed always false.
	if r.cut.trips() != len(raws) {
		t.Errorf("%d trips for %d malformed frames", r.cut.trips(), len(raws))
	}
}

func helloFrame(t *testing.T, r *rig) []byte {
	h, err := wire.SignHello(wire.RoleCore, r.core, exporter)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := wire.Encode(wire.ToEnforcer, h)
	return frameBytes(f.Type, f.Payload)
}

// TestSafetyListTable (NET-2 Safety devices): one row per class NET-2
// names, as the signed policy records it: exactly the allowed commands
// reach the radio, and every safety-list device still takes reads.
// Catches an unlock or a turn-on by the core. Revert mutant: Allowed
// returning everyday[v] for a safety-list device passes the heater's "on".
func TestSafetyListTable(t *testing.T) {
	want := map[string][]wire.Verb{
		"lamp":            {wire.VerbOn, wire.VerbOff, wire.VerbLevel, wire.VerbLock},
		"lock":            {wire.VerbLock},
		"valve":           {wire.VerbShut},
		"heater":          {wire.VerbOff},
		"oven":            {wire.VerbOff},
		"plug":            {wire.VerbOff},
		"relay":           {wire.VerbOff},
		"garage":          {wire.VerbClose},
		"drone":           {wire.VerbReturnToDock},
		"camera":          nil,
		"microphone":      nil,
		"alarm":           nil,
		"siren":           nil,
		"sensor":          nil,
		"untyped":         nil,
		"unnamed-valve":   nil,
		"primary-heating": nil,
		"feed-valve":      nil,
	}
	if len(want) != len(safetyDevices)+1 {
		t.Fatal("a safety class has no row")
	}
	r := newRig(t, nil)
	cl := r.dial()
	id := uint64(0)
	for device, allowed := range want {
		for _, v := range allVerbs {
			id++
			before := len(r.radio.calls())
			got := cl.code(cmd(id, device, v))
			ok := slices.Contains(allowed, v)
			if (got == wire.OK) != ok {
				t.Errorf("%s %s: %v, allowed %v", device, verbWords[v], got, ok)
			}
			if sent := len(r.radio.calls()) > before; sent != ok {
				t.Errorf("%s %s: reached the radio %v", device, verbWords[v], sent)
			}
		}
		id++
		if c := cl.code(wire.Read{ID: id, What: wire.ReadState, Device: device}); c != wire.OK {
			t.Errorf("%s: read refused: %v", device, c)
		}
		r.advance(10 * time.Minute) // keep under the command and refusal buckets
	}

	// The table is the policy's: naming is the owner's signed loosening,
	// and Nameable is the closed list a page offers.
	for _, s := range []string{"on", "open", "unlock", "disarm", "arm", "", "LOCK"} {
		if Nameable(s) {
			t.Errorf("%q is nameable", s)
		}
	}

	// A secure direction counts against the device's tightening limit.
	for i := range policy.TightenLimit + 1 {
		id++
		c := cl.code(cmd(id, "garage", wire.VerbClose))
		if i < policy.TightenLimit-1 && c != wire.OK { // one close above
			t.Fatalf("close %d: %v", i, c)
		}
		if i == policy.TightenLimit && c != wire.RateLimited {
			t.Fatalf("close over the limit: %v", c)
		}
	}
}

// TestDroneReturnOnly (NET-2 Drones): the channel's one drone command is
// return to dock. Every other verb is refused, a command carrying a
// waypoint-shaped tail ends the connection, and no wire type carries a
// route. Catches a waypoint on the channel.
func TestDroneReturnOnly(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	for i, v := range allVerbs {
		c := cl.code(cmd(uint64(i+1), "drone", v))
		if (c == wire.OK) != (v == wire.VerbReturnToDock) {
			t.Errorf("drone %s: %v", verbWords[v], c)
		}
	}
	if got := r.radio.calls(); !reflect.DeepEqual(got, []string{"drone return to dock"}) {
		t.Errorf("radio got %v", got)
	}
	ret, _ := wire.Encode(wire.ToEnforcer, cmd(9, "drone", wire.VerbReturnToDock))
	var wp []byte
	wp = binary.BigEndian.AppendUint64(wp, 0x4049_0000_0000_0000) // a latitude
	wp = binary.BigEndian.AppendUint64(wp, 0x4000_0000_0000_0000)
	if !cl.closed(frameBytes(wire.TCommand, append(slices.Clone(ret.Payload), wp...))) {
		t.Error("a waypoint after return to dock was not refused")
	}
	if len(r.radio.calls()) != 1 {
		t.Errorf("radio got %v", r.radio.calls())
	}
}

// TestBurstTrips (NET-2 The channel, D-255): a burst of any request kind
// past its rate is a core trip at the enforcer. While the trip is in force
// nothing acts, whatever the kind, however long the core waits and however
// often it reconnects, and it never trips again for asking; only the
// owner's steps on the page lift it (D-260). Catches a flood that only
// pauses. Revert mutant: count pausing instead of tripping.
func TestBurstTrips(t *testing.T) {
	floods := map[string]func(id uint64) wire.Msg{
		"commands":  func(id uint64) wire.Msg { return cmd(id, "lamp", wire.VerbOn) },
		"reads":     func(id uint64) wire.Msg { return wire.Read{ID: id, What: wire.ReadState, Device: "lamp"} },
		"summaries": func(id uint64) wire.Msg { return wire.Read{ID: id, What: wire.ReadTraffic, Device: "lamp"} },
		"announces": func(id uint64) wire.Msg { return wire.Announce{ID: id} },
		"heads":     func(id uint64) wire.Msg { return wire.Head{ID: id} },
	}
	for name, flood := range floods {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			cl := r.dial()
			var id uint64
			for r.cut.trips() == 0 {
				id++
				if id > 1000 {
					t.Fatal("never tripped")
				}
				cl.do(flood(id))
			}
			n := len(r.radio.calls())
			r.advance(24 * time.Hour)
			cl = r.dial()
			for _, m := range []wire.Msg{
				cmd(id+1, "lamp", wire.VerbOn),
				cmd(id+2, "heater", wire.VerbOff),
				wire.Tighten{ID: id + 3, Kind: wire.CutVendorCloud, Device: "tv"},
				wire.Read{ID: id + 4, What: wire.ReadExport},
				wire.Read{ID: id + 5, What: wire.ReadTraffic, Device: "lamp"},
				wire.Head{ID: id + 6},
			} {
				if c := cl.code(m); c != wire.Paused {
					t.Errorf("%T while tripped: %v", m, c)
				}
			}
			if len(r.radio.calls()) != n || !r.eng.Current().Device("tv").VendorCloud {
				t.Error("a request acted while tripped")
			}
			if r.cut.trips() != 1 {
				t.Errorf("%d trips, want 1: a paused request tripped again", r.cut.trips())
			}
			r.cut.set(Open) // the owner's passkey restore
			if c := cl.code(cmd(id+7, "lamp", wire.VerbOff)); c != wire.OK {
				t.Errorf("after the restore: %v", c)
			}
		})
	}

	// An honest core's pace never trips: one command every two seconds
	// for an hour.
	r := newRig(t, nil)
	cl := r.dial()
	for i := range 1800 {
		cl.do(cmd(uint64(i), "lamp", wire.VerbOn))
		r.advance(2 * time.Second)
	}
	if r.cut.trips() != 0 {
		t.Error("an honest pace tripped the core")
	}
}

// TestRefusalBurstWaits (NET-2 Channel): refusals have their own rate,
// which the kernel cannot check before sending, since it cannot know a
// request will be refused. Past it every request is refused RateLimited
// with no trip, that answer is not itself counted, and the rate refills by
// itself with no owner step, however hard the core keeps asking. Revert
// mutant: the bucket check removed (refusals unbounded).
func TestRefusalBurstWaits(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	var id uint64
	for {
		id++
		if id > 1000 {
			t.Fatal("refusals never limited")
		}
		if cl.code(cmd(id, "heater", wire.VerbOn)) == wire.RateLimited {
			break
		}
	}
	if int(id) != DefaultLimit(KindRefused).Burst+1 {
		t.Errorf("limited after %d refusals, want %d", id-1, DefaultLimit(KindRefused).Burst)
	}
	n := len(r.radio.calls())
	every := DefaultLimit(KindRefused).Every
	// The core keeps asking, an honest command every few seconds, for
	// under one refill: each waits.
	for range 10 {
		id++
		if c := cl.code(cmd(id, "lamp", wire.VerbOn)); c != wire.RateLimited {
			t.Fatalf("past the refusal rate: %v", c)
		}
		r.advance(every / 20)
	}
	if len(r.radio.calls()) != n || r.cut.trips() != 0 {
		t.Fatal("a request acted, or the core tripped, past the refusal rate")
	}
	r.advance(every)
	if c := cl.code(cmd(id+1, "lamp", wire.VerbOff)); c != wire.OK {
		t.Errorf("after the refusal rate refilled: %v", c)
	}
}

// TestPreAuthNeverPauses (NET-2 Channel, #3755): a hello that fails, from
// a key that is not the pinned core key, on another connection's exporter,
// after the core's key is revoked, or a frame before any hello, drops the
// connection and never pauses the channel, however many arrive; past the
// pre-auth bucket the drops stop being logged one by one. The real core
// connects straight after the flood, and only its own reconnects count
// toward a trip. Catches a stranger pausing the channel or tripping the core.
func TestPreAuthNeverPauses(t *testing.T) {
	r := newRig(t, nil)
	_, stranger, _ := ed25519.GenerateKey(nil)
	raw := func(m wire.Msg) []byte {
		f, err := wire.Encode(wire.ToEnforcer, m)
		if err != nil {
			t.Fatal(err)
		}
		return frameBytes(f.Type, f.Payload)
	}
	strangerHello, _ := wire.SignHello(wire.RoleCore, stranger, exporter)
	otherExporter, _ := wire.SignHello(wire.RoleCore, r.core, bytes.Repeat([]byte{1}, wire.ExporterLen))
	coreHello, _ := wire.SignHello(wire.RoleCore, r.core, exporter)
	floods := [][]byte{raw(strangerHello), raw(otherExporter), raw(cmd(1, "lamp", wire.VerbOn))}
	for i := range 300 {
		if !r.connect().closed(floods[i%len(floods)]) {
			t.Fatalf("%d: a failed hello was not dropped", i)
		}
	}
	r.mu.Lock()
	r.revoked = true
	r.mu.Unlock()
	for i := range 30 {
		if !r.connect().closed(raw(coreHello)) {
			t.Fatalf("%d: a revoked key's hello was not dropped", i)
		}
	}
	r.mu.Lock()
	r.revoked = false
	r.mu.Unlock()
	if r.cut.trips() != 0 {
		t.Fatal("failed hellos tripped the core")
	}
	var logged int
	for _, e := range r.events() {
		if e.Kind == KindHello || e.Kind == KindPreAuth {
			logged++
		}
	}
	if max := DefaultLimit(KindPreAuth).Burst + 1; logged > max {
		t.Errorf("%d log lines for a flood of failed hellos, want at most %d", logged, max)
	}

	cl := r.dial()
	if c := cl.code(cmd(2, "lamp", wire.VerbOn)); c != wire.OK {
		t.Fatalf("the core after a stranger's flood: %v", c)
	}

	// The core's own reconnects past the rate trip it.
	for i := 0; r.cut.trips() == 0; i++ {
		if i > DefaultLimit(KindHello).Burst {
			t.Fatal("the core's reconnect flood never tripped")
		}
		r.dial()
	}
}

// TestHeaterOffTexts (NET-2 Safety devices): a channel command that turns a
// heater off or shuts a valve texts the owner through the enforcer's own
// alerts; a lock, a garage door's close, an everyday device's off and a
// command the radio did not carry out do not. Catches a silent safety
// command.
func TestHeaterOffTexts(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	for i, m := range []wire.Command{
		cmd(1, "heater", wire.VerbOff),
		cmd(2, "valve", wire.VerbShut),
		cmd(3, "lock", wire.VerbLock),
		cmd(4, "garage", wire.VerbClose),
		cmd(5, "lamp", wire.VerbOff),
		cmd(6, "drone", wire.VerbReturnToDock),
	} {
		if c := cl.code(m); c != wire.OK {
			t.Fatalf("%d: %v", i, c)
		}
	}
	r.radio.mu.Lock()
	r.radio.fail = true
	r.radio.mu.Unlock()
	if c := cl.code(cmd(7, "oven", wire.VerbOff)); c != wire.Failed {
		t.Fatalf("failed radio: %v", c)
	}
	if want := []string{"heater off", "valve shut"}; !reflect.DeepEqual(r.alerts.off, want) {
		t.Errorf("texts %v, want %v", r.alerts.off, want)
	}
}

// TestHandshake (NET-2 Channel, KEY-7): only the pinned core key, on this
// connection's exporter, opens the channel; a revoked key is refused at
// the hello and ends a connection already open. The enforcer's own hello
// verifies under its key (the core's pin).
func TestHandshake(t *testing.T) {
	r := newRig(t, nil)
	_, other, _ := ed25519.GenerateKey(nil)
	for name, h := range map[string]func() wire.Hello{
		"another key": func() wire.Hello { h, _ := wire.SignHello(wire.RoleCore, other, exporter); return h },
		"another connection": func() wire.Hello {
			h, _ := wire.SignHello(wire.RoleCore, r.core, bytes.Repeat([]byte{1}, wire.ExporterLen))
			return h
		},
	} {
		cl := r.connect()
		f, _ := wire.Encode(wire.ToEnforcer, h())
		if !cl.closed(frameBytes(f.Type, f.Payload)) {
			t.Errorf("%s: hello accepted", name)
		}
	}
	cl := r.connect()
	cmdFrame, _ := wire.Encode(wire.ToEnforcer, cmd(1, "lamp", wire.VerbOn))
	if !cl.closed(frameBytes(cmdFrame.Type, cmdFrame.Payload)) {
		t.Error("a command before the hello was taken")
	}

	cl = r.dial()
	r.mu.Lock()
	r.revoked = true
	r.mu.Unlock()
	if !cl.closed(frameBytes(cmdFrame.Type, cmdFrame.Payload)) {
		t.Error("a revoked key's open connection kept going")
	}
	cl = r.connect()
	if !cl.closed(helloFrame(t, r)) {
		t.Error("a revoked key's hello was accepted")
	}
	if len(r.radio.calls()) != 0 {
		t.Errorf("radio got %v", r.radio.calls())
	}
}

// TestReads: the export is the engine's; a fingerprint is a hash, only for
// a safety-list device; a device the policy does not name is refused.
func TestReads(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	exp, _ := r.eng.Export()
	if rep, ok := cl.do(wire.Read{ID: 1, What: wire.ReadExport}).(wire.ReadReply); !ok || !bytes.Equal(rep.Body, exp) {
		t.Error("export differs from the engine's")
	}
	if rep, ok := cl.do(wire.Read{ID: 2, What: wire.ReadFingerprint, Device: "lock"}).(wire.ReadReply); !ok || len(rep.Body) != wire.HashLen {
		t.Errorf("fingerprint: %+v", rep)
	}
	for _, m := range []wire.Read{
		{ID: 3, What: wire.ReadFingerprint, Device: "lamp"},
		{ID: 4, What: wire.ReadState, Device: "stranger"},
		{ID: 5, What: wire.ReadTraffic, Device: "stranger"},
	} {
		if c := cl.code(m); c != wire.Refused {
			t.Errorf("%+v: %v", m, c)
		}
	}
	if rep, ok := cl.do(wire.Read{ID: 6, What: wire.ReadTraffic, Device: "tv"}).(wire.ReadReply); !ok || string(rep.Body) != "traffic of tv" {
		t.Errorf("traffic: %+v", rep)
	}
}

// TestTightenings: an off-list device's tightening applies at once; a
// safety-list device's comes back NeedsOwner, for a link the owner signs.
func TestTightenings(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	if c := cl.code(wire.Tighten{ID: 1, Kind: wire.CutVendorCloud, Device: "tv"}); c != wire.OK || r.eng.Current().Device("tv").VendorCloud {
		t.Errorf("off-list cut: %v", c)
	}
	if c := cl.code(wire.Tighten{ID: 2, Kind: wire.RemovePair, A: "tv", B: "speaker"}); c != wire.OK {
		t.Errorf("pair: %v", c)
	}
	for _, m := range []wire.Tighten{
		{ID: 3, Kind: wire.IsolateDevice, Device: "camera"},
		{ID: 4, Kind: wire.RevokeRule, Device: "lock", Rule: "plumber"},
	} {
		if c := cl.code(m); c != wire.NeedsOwner {
			t.Errorf("%+v: %v", m, c)
		}
	}
}

// TestChallengeAnswer: the core's answer reaches the device only for a
// challenge the enforcer sent, once.
func TestChallengeAnswer(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.Challenge(7, []byte{1}); err != ErrNoSession {
		t.Fatalf("challenge with no core: %v", err)
	}
	cl := r.dial()
	if c := cl.code(wire.Challenge{Answer: true, ID: 7, Data: []byte{2}}); c != wire.Refused {
		t.Errorf("unasked answer: %v", c)
	}
	go r.ch.Challenge(7, []byte{1})
	if m, ok := cl.recv().(wire.Challenge); !ok || m.ID != 7 || m.Answer {
		t.Fatalf("challenge frame: %+v", m)
	}
	if c := cl.code(wire.Challenge{Answer: true, ID: 7, Data: []byte{2}}); c != wire.OK {
		t.Errorf("answer: %v", c)
	}
	if c := cl.code(wire.Challenge{Answer: true, ID: 7, Data: []byte{2}}); c != wire.Refused {
		t.Errorf("second answer: %v", c)
	}
	if !reflect.DeepEqual(r.answers, []uint64{7}) {
		t.Errorf("answers %v", r.answers)
	}
}

// TestChallengeIDOutstanding (#3759 point 4): a challenge whose ID is
// already outstanding is refused before it is sent, so a late answer to
// the first can never be handed over as the answer to the second; the
// first's answer still reaches the device, and the ID is free again
// after it. Revert mutant: Challenge re-adding an outstanding ID.
func TestChallengeIDOutstanding(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	go r.ch.Challenge(7, []byte{1})
	if m, ok := cl.recv().(wire.Challenge); !ok || m.ID != 7 {
		t.Fatalf("challenge frame: %+v", m)
	}
	if err := r.ch.Challenge(7, []byte{2}); !errors.Is(err, ErrOutstanding) {
		t.Fatalf("a second challenge with an outstanding id: %v, want ErrOutstanding", err)
	}
	if c := cl.code(wire.Challenge{Answer: true, ID: 7, Data: []byte{3}}); c != wire.OK {
		t.Fatalf("answer: %v", c)
	}
	if c := cl.code(wire.Challenge{Answer: true, ID: 7, Data: []byte{3}}); c != wire.Refused {
		t.Errorf("the refused challenge's answer was taken: %v", c)
	}
	go r.ch.Challenge(7, []byte{4})
	if m, ok := cl.recv().(wire.Challenge); !ok || m.ID != 7 {
		t.Fatalf("a challenge after the answer: %+v", m)
	}
	if !reflect.DeepEqual(r.answers, []uint64{7}) {
		t.Errorf("answers %v", r.answers)
	}
}

// TestRatesIgnoreWallSteps (#4507, KRN-chan-4): the rates read the
// enforcer's own elapsed time, never its wall clock, so a wall clock
// stepped back an hour neither pauses their refill nor makes an honest
// kernel's next message, one interval later, a burst; nor does a step
// forward refill them. Revert mutant: the buckets reading Config.Now.
func TestRatesIgnoreWallSteps(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	l := wire.Rate(wire.RateAnnounce)
	id := uint64(0)
	announce := func() wire.Code { id++; return cl.code(wire.Announce{ID: id}) }
	for range l.Burst {
		if c := announce(); c != wire.OK {
			t.Fatalf("announce inside the burst: %v", c)
		}
	}
	r.mu.Lock()
	r.wallStep = -time.Hour
	r.mu.Unlock()
	r.advance(l.Every)
	if c := announce(); c != wire.OK || r.cut.trips() != 0 {
		t.Fatalf("one interval after a burst, with the wall clock stepped back: %v, %d trips", c, r.cut.trips())
	}
	r.mu.Lock()
	r.wallStep = 24 * time.Hour
	r.mu.Unlock()
	announce()
	if r.cut.trips() != 1 {
		t.Fatalf("a wall clock stepped forward refilled the rate: %d trips, want 1", r.cut.trips())
	}
	if e := r.events(); e[len(e)-1].At != r.now.Add(24*time.Hour) {
		t.Errorf("log line at %v, want the wall clock's time", e[len(e)-1].At)
	}
}

// TestSinksRequired (NET-2 Safety devices, Channel): a channel cannot be
// built without its log or its alerts, so no command acts unlogged and no
// heater off or valve shut goes untexted. Revert mutant: New accepting a
// nil Alerts or Log (the L3 probes on #3750).
func TestSinksRequired(t *testing.T) {
	for name, cut := range map[string]func(*Config){
		"no alerts": func(c *Config) { c.Alerts = nil },
		"no log":    func(c *Config) { c.Log = nil },
	} {
		r := newRig(t, nil)
		cfg := r.ch.cfg
		cut(&cfg)
		if _, err := New(cfg); err != ErrConfig {
			t.Errorf("%s: %v, want ErrConfig", name, err)
		}
	}
}

// TestAlertsMayUseChannel (NET-2 Texts and calls): the alerts sink runs
// after the channel lets go of its lock, so slice h can send its text back
// through the channel from inside SafetyOff without a deadlock.
// Revert mutant: calling Alerts under c.mu (Security finding on #3750).
func TestAlertsMayUseChannel(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	r.alerts.reenter = func() {
		r.ch.Alert(wire.Alert{Kind: wire.AlertText, Text: "The heater in the hall was turned off."})
	}
	cl.send(cmd(1, "heater", wire.VerbOff))
	if m, ok := cl.recv().(wire.Alert); !ok || m.Kind != wire.AlertText {
		t.Fatalf("alert frame: %+v", m)
	}
	if m, ok := cl.recv().(wire.Result); !ok || m.Code != wire.OK {
		t.Fatalf("result: %+v", m)
	}
}

// TestAnswerMayUseChannel (#3759 point 1): the answer callback runs after
// the channel lets go of its lock, so the radio host can send its next
// challenge from inside Answer without a deadlock. Revert mutant: calling
// Answer under c.mu.
func TestAnswerMayUseChannel(t *testing.T) {
	var r *rig
	errs := make(chan error, 1)
	r = newRig(t, func(c *Config) {
		c.Answer = func(id uint64, _ []byte) { errs <- r.ch.Challenge(id+1, []byte{9}) }
	})
	cl := r.dial()
	go r.ch.Challenge(7, []byte{1})
	if m, ok := cl.recv().(wire.Challenge); !ok || m.ID != 7 {
		t.Fatalf("challenge frame: %+v", m)
	}
	cl.send(wire.Challenge{Answer: true, ID: 7, Data: []byte{2}})
	if m, ok := cl.recv().(wire.Challenge); !ok || m.ID != 8 || m.Answer {
		t.Fatalf("the challenge sent from Answer: %+v", m)
	}
	if m, ok := cl.recv().(wire.Result); !ok || m.Code != wire.OK {
		t.Fatalf("result: %+v", m)
	}
	if err := <-errs; err != nil {
		t.Fatalf("Challenge from inside Answer: %v", err)
	}
}

// TestLogMayUseChannel (#3759 point 2, ENF-d-7): every log line the
// channel writes while it holds its lock is handed to Config.Log after it
// lets go, so a log sink may call the channel: on a request, a refused
// frame, a trip and a failed hello alike. Revert mutants: calling Log
// under c.mu in handle, refuse, trip, count or preAuth.
func TestLogMayUseChannel(t *testing.T) {
	r := newRig(t, nil)
	var calls atomic.Int32
	reenter := func() {
		// Takes the channel's lock and sends nothing: either no core is
		// connected or the id is outstanding.
		r.ch.Challenge(7, nil)
		calls.Add(1)
	}
	r.mu.Lock()
	r.logReenter = reenter
	r.mu.Unlock()
	bad := r.connect()
	bad.send(cmd(1, "lamp", wire.VerbOn)) // a frame before any hello: preAuth
	select {
	case <-bad.done:
	case <-time.After(5 * time.Second):
		t.Fatal("a failed hello's log line deadlocked the channel")
	}
	r.mu.Lock()
	r.logReenter = nil
	r.mu.Unlock()
	cl := r.dial()
	go r.ch.Challenge(7, []byte{1})
	if _, ok := cl.recv().(wire.Challenge); !ok {
		t.Fatal("no challenge frame")
	}
	r.mu.Lock()
	r.logReenter = reenter
	r.mu.Unlock()
	if c := cl.code(cmd(2, "lamp", wire.VerbOn)); c != wire.OK { // handle's line
		t.Fatalf("command: %v", c)
	}
	if c := cl.code(cmd(3, "nosuch", wire.VerbOn)); c != wire.Refused {
		t.Fatalf("unknown device: %v", c)
	}
	for i := range wire.Rate(wire.RateAnnounce).Burst + 1 { // count's trip line
		cl.code(wire.Announce{ID: uint64(10 + i)})
	}
	if r.cut.trips() != 1 {
		t.Fatalf("trips %d, want 1", r.cut.trips())
	}
	if !cl.closed(frameBytes(wire.TCommand, []byte{1})) { // trip's line
		t.Fatal("a malformed frame did not end the connection")
	}
	if calls.Load() < 5 {
		t.Fatalf("the log sink ran %d times", calls.Load())
	}
}

// TestLogNamesOnlySignedDevices (NET-2 Channel, #3758): the enforcer's log
// is the owner's record, so the core cannot write words into it. A name
// carrying any hostile-text entry (a line or paragraph separator, NEL or
// another C1 control, a bidi override or isolate) ends the connection and
// is not logged; a well-formed name the signed policy does not hold is
// logged only as "unknown " and its SHA-256, in every kind and in both of a
// pair's members; a device the policy names is logged by its ID, also when
// the tightening removes it. Catches a forged "resumed by the owner" line.
// Revert mutant: logName returning s for every name.
func TestLogNamesOnlySignedDevices(t *testing.T) {
	r := newRig(t, nil)
	n := len(r.events())
	for _, e := range hostiletext.Hidden {
		h := "a" + e.Text + "b"
		if len(h) > wire.MaxName {
			continue
		}
		place := strings.Repeat("x", len(h))
		good, err := wire.Encode(wire.ToEnforcer, cmd(1, place, wire.VerbOn))
		if err != nil {
			t.Fatal(err)
		}
		p := bytes.Replace(good.Payload, []byte(place), []byte(h), 1)
		r.advance(time.Hour) // the hello and refusal buckets are not under test here
		if cl := r.dial(); !cl.closed(frameBytes(wire.TCommand, p)) {
			t.Errorf("%s: connection not ended", e.Name)
		}
	}
	for _, e := range r.events()[n:] {
		if e.Device != "" || (e.Kind != KindHello && e.Kind != KindFrame) {
			t.Errorf("a hostile name was logged: %+v", e)
		}
	}
	r.cut.set(Open) // the owner's passkey restore after those trips

	forged := "resumed-by-the-owner"
	sum := sha256.Sum256([]byte(forged))
	unknown := "unknown " + hex.EncodeToString(sum[:])
	r.advance(time.Hour)
	cl := r.dial()
	n = len(r.events())
	cl.code(cmd(1, forged, wire.VerbOff))
	cl.code(wire.Read{ID: 2, What: wire.ReadState, Device: forged})
	cl.code(wire.Tighten{ID: 3, Kind: wire.IsolateDevice, Device: forged})
	cl.code(wire.Tighten{ID: 4, Kind: wire.RemovePair, A: forged, B: "tv"})
	cl.code(wire.Tighten{ID: 7, Kind: wire.RemovePair, A: "tv", B: forged})
	cl.code(cmd(5, "lamp", wire.VerbOn))
	if c := cl.code(wire.Tighten{ID: 6, Kind: wire.RemoveDevice, Device: "lamp"}); c != wire.OK || r.eng.Current().Device("lamp") != nil {
		t.Fatalf("remove lamp: %v", c)
	}
	want := map[uint64][2]string{1: {unknown, ""}, 2: {unknown, ""}, 3: {unknown, ""}, 4: {unknown, "tv"}, 5: {"lamp", ""}, 6: {"lamp", ""}, 7: {"tv", unknown}}
	got := map[uint64][2]string{}
	for _, e := range r.events()[n:] {
		if strings.Contains(e.Device+e.Other, forged) {
			t.Errorf("the core's name was logged: %+v", e)
		}
		if e.Kind != KindHello { // the hello's line may land after dial returns
			got[e.ID] = [2]string{e.Device, e.Other}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("logged devices %v, want %v", got, want)
	}
}

// TestLogPairUnambiguous (NET-2 Channel, #4066): signed IDs may hold a
// comma, so a pair logged as one joined string could name two pairs the
// same way. Each member has its own field, and two pairs that join the
// same way log differently. Revert mutant: Device = A + "," + B.
func TestLogPairUnambiguous(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	n := len(r.events())
	cl.code(wire.Tighten{ID: 1, Kind: wire.RemovePair, A: "a,b", B: "c"})
	cl.code(wire.Tighten{ID: 2, Kind: wire.RemovePair, A: "a", B: "b,c"})
	got := map[uint64][2]string{}
	for _, e := range r.events()[n:] {
		if e.Kind == KindTighten {
			got[e.ID] = [2]string{e.Device, e.Other}
		}
	}
	want := map[uint64][2]string{1: {"a,b", "c"}, 2: {"a", "b,c"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("logged pairs %v, want %v", got, want)
	}
}

// TestShortName (NET-2 Channel, #4066): the owner's line shows an unsigned
// name as "unknown" and 12 hex digits, which still tells repeated unknown
// names apart, and the event keeps the full hash for the detail view. A
// signed ID shows as itself, and no form shows the core's words.
func TestShortName(t *testing.T) {
	d := home()
	full := logName(d, "resumed-by-the-owner")
	short := Short(full)
	sum := sha256.Sum256([]byte("resumed-by-the-owner"))
	if want := "unknown " + hex.EncodeToString(sum[:6]); short != want {
		t.Errorf("Short(%q) = %q, want %q", full, short, want)
	}
	if other := Short(logName(d, "resumed-by-the-owner2")); other == short {
		t.Errorf("two unknown names show the same: %q", other)
	}
	for _, s := range []string{"lamp", "untyped", "", "a,b"} {
		if got := Short(logName(d, s)); got != s {
			t.Errorf("Short of signed %q = %q", s, got)
		}
	}
}

// countingPolicy counts the policy copies the channel takes.
type countingPolicy struct {
	Policy
	mu sync.Mutex
	n  int
}

func (p *countingPolicy) Current() policy.Document {
	p.mu.Lock()
	p.n++
	p.mu.Unlock()
	return p.Policy.Current()
}

func (p *countingPolicy) take() int { p.mu.Lock(); defer p.mu.Unlock(); n := p.n; p.n = 0; return n }

// TestOnePolicyCopyPerRequest (#4066): the channel takes at most one sorted
// deep copy of the policy per request, paused or not, and none for a
// request that names no device (an export read, an announce). Revert
// mutant: command or read calling Policy.Current() again.
func TestOnePolicyCopyPerRequest(t *testing.T) {
	var cp *countingPolicy
	r := newRig(t, func(c *Config) { cp = &countingPolicy{Policy: c.Policy}; c.Policy = cp })
	cl := r.dial()
	reqs := []wire.Msg{
		cmd(1, "lamp", wire.VerbOn),
		cmd(2, "heater", wire.VerbOff),
		wire.Read{ID: 3, What: wire.ReadState, Device: "lamp"},
		wire.Read{ID: 4, What: wire.ReadFingerprint, Device: "lock"},
		wire.Tighten{ID: 6, Kind: wire.IsolateDevice, Device: "tv"},
	}
	none := []wire.Msg{wire.Announce{ID: 9}, wire.Read{ID: 5, What: wire.ReadExport}}
	check := func(when string) {
		for _, m := range reqs {
			cp.take()
			cl.do(m)
			if n := cp.take(); n > 1 {
				t.Errorf("%s: %T took %d policy copies", when, m, n)
			}
		}
		for _, m := range none {
			cp.take()
			cl.do(m)
			if n := cp.take(); n != 0 {
				t.Errorf("%s: %+v took %d policy copies", when, m, n)
			}
		}
	}
	check("open")
	r.cut.set(Tripped)
	check("tripped")
}

// TestPausedLogsNames (NET-2 Channel, #4066): a request the tripped channel
// pauses is still logged by the names the signed policy holds, a pair's
// members each in its own field and an unsigned name only as its hash.
// Revert mutant: names set after gate, or blanked when paused.
func TestPausedLogsNames(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	r.cut.set(Tripped)
	n := len(r.events())
	cl.code(cmd(1, "lamp", wire.VerbOn))
	cl.code(wire.Read{ID: 2, What: wire.ReadState, Device: "heater"})
	cl.code(wire.Tighten{ID: 3, Kind: wire.RemovePair, A: "a,b", B: "c"})
	cl.code(cmd(4, "resumed-by-the-owner", wire.VerbOff))
	sum := sha256.Sum256([]byte("resumed-by-the-owner"))
	want := map[uint64][2]string{1: {"lamp", ""}, 2: {"heater", ""}, 3: {"a,b", "c"}, 4: {"unknown " + hex.EncodeToString(sum[:]), ""}}
	got := map[uint64][2]string{}
	for _, e := range r.events()[n:] {
		if e.Kind == KindCommand || e.Kind == KindRead || e.Kind == KindTighten {
			if e.Code != wire.Paused {
				t.Errorf("not refused as paused: %+v", e)
			}
			got[e.ID] = [2]string{e.Device, e.Other}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paused log names %v, want %v", got, want)
	}
}

// TestOwnerLine (NET-2 Channel, Texts and calls, #4185): the owner's line
// for a removed pair shows both members, an unsigned one as "unknown" and
// 12 hex digits, in either order; the detail view shows its full hash; a
// line without an ID, a name or a verdict word has no gap for one; and no
// line carries a time, which the renderer shows in the owner's zone
// (NET-4), so none can show UTC. Revert mutants: Line printing Device
// alone, a name without Short, or render writing e.At.
func TestOwnerLine(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	n := len(r.events())
	forged := "resumed-by-the-owner"
	cl.code(wire.Tighten{ID: 7, Kind: wire.RemovePair, A: "tv", B: forged})
	cl.code(wire.Tighten{ID: 8, Kind: wire.RemovePair, A: forged, B: "tv"})
	cl.code(cmd(9, "lamp", wire.VerbOn))
	sum := sha256.Sum256([]byte(forged))
	short, full := "unknown "+hex.EncodeToString(sum[:6]), "unknown "+hex.EncodeToString(sum[:])
	pair := ": refused, not a closed-list tightening of the policy in force"
	want := map[uint64][2]string{
		7: {"tighten #7 remove-pair tv / " + short + pair, "tighten #7 remove-pair tv / " + full + pair},
		8: {"tighten #8 remove-pair " + short + " / tv" + pair, "tighten #8 remove-pair " + full + " / tv" + pair},
		9: {"command #9 on lamp: done", "command #9 on lamp: done"},
	}
	got := map[uint64][2]string{}
	for _, e := range r.events()[n:] {
		if e.Kind != KindHello {
			got[e.ID] = [2]string{e.Line(), e.Detail()}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines\n%v\nwant\n%v", got, want)
	}
	if got, want := (Event{At: start, Kind: KindTrip, What: string(KindCommand), Reason: "burst of command past the rate: tripped the core"}).Line(), "trip command: burst of command past the rate: tripped the core"; got != want {
		t.Errorf("trip line %q, want %q", got, want)
	}
}

// TestReservedWord (NET-2 Channel, #4249): wire.Name refuses the word
// policy.Unknown reserves, in any case, so renaming one without the other
// fails here rather than letting the core send a name that reads as the
// marker. A lookalike such as "unknоwn" (Cyrillic о) passes both checks;
// only the owner can sign it, and it shows as itself, one token with no
// space, so it never takes the marker's two-part "unknown" and hex form.
func TestReservedWord(t *testing.T) {
	for _, s := range []string{policy.Unknown, strings.ToUpper(policy.Unknown), strings.ToUpper(policy.Unknown[:1]) + policy.Unknown[1:]} {
		if wire.Name(s) {
			t.Errorf("wire.Name(%q) = true, want the word policy.Unknown reserves refused", s)
		}
	}
	look := "unknоwn"
	if !wire.Name(look) {
		t.Fatalf("wire.Name(%q) = false", look)
	}
	if got := Short(look); got != look {
		t.Errorf("Short(%q) = %q, want it shown as itself", look, got)
	}
	if got := Short(logName(home(), look)); !strings.HasPrefix(got, unknownWord) || len(got) != len(unknownWord)+shortHex {
		t.Errorf("unsigned lookalike shows as %q, want the marker and its digits", got)
	}
}

// TestTripPausesUntilRestore (KRN-12 Response, D-260, D-262): after a core
// trip the channel answers every request Paused and logs it, never trips
// again for a paused request and never counts one as a refusal, while the
// core's hello, which carries the heartbeat, still connects. At the "core
// reflashed" step only traffic summaries act again; the passkey restore
// opens the rest. Revert mutants: Reflashed letting a command through; a
// Paused answer counted as a refusal, which holds the reopened summaries.
func TestTripPausesUntilRestore(t *testing.T) {
	r := newRig(t, nil)
	r.cut.set(Tripped)
	requests := func(id uint64) map[string]wire.Msg {
		return map[string]wire.Msg{
			"command":     cmd(id, "lamp", wire.VerbOn),
			"tighten":     wire.Tighten{ID: id + 1, Kind: wire.CutVendorCloud, Device: "tv"},
			"state":       wire.Read{ID: id + 2, What: wire.ReadState, Device: "lock"},
			"export":      wire.Read{ID: id + 3, What: wire.ReadExport},
			"fingerprint": wire.Read{ID: id + 4, What: wire.ReadFingerprint, Device: "lock"},
			"summary":     wire.Read{ID: id + 5, What: wire.ReadTraffic, Device: "lamp"},
			"counts":      wire.Read{ID: id + 9, What: wire.ReadCounts},
			"announce":    wire.Announce{ID: id + 6},
			"head":        wire.Head{ID: id + 7},
			"entry":       wire.Entry{ID: id + 8, Body: []byte{1}},
		}
	}
	var id uint64
	check := func(stage string, rounds int, want map[string]wire.Code) {
		t.Helper()
		// Each stage's requests go at an honest pace (a proposal link is
		// the slowest rate) for two hours: more Paused answers than the
		// refusal bucket holds.
		for range rounds {
			cl := r.dial()
			n := len(r.events())
			id += 20
			for name, m := range requests(id) {
				w, ok := want[name]
				if !ok {
					w = wire.Paused
				}
				if c := cl.code(m); c != w {
					t.Fatalf("%s: %s answered %v, want %v", stage, name, c, w)
				}
			}
			for _, e := range r.events()[n:] {
				if e.Code == wire.Paused && e.Reason == "" {
					t.Errorf("%s: a paused request logged no reason: %+v", stage, e)
				}
			}
			r.advance(DefaultLimit(KindAnnounce).Every)
		}
	}
	// A kernel learns of the trip only from Paused answers: a quick run of
	// them, past the refusal bucket, inside the command rate.
	cl := r.dial()
	for i := range 2 * DefaultLimit(KindRefused).Burst {
		if c := cl.code(cmd(uint64(1000+i), "lamp", wire.VerbOn)); c != wire.Paused {
			t.Fatalf("tripped: %v", c)
		}
	}
	check("tripped", 12, nil)
	cl = r.dial() // check's connections replaced this one
	if len(r.radio.calls()) != 0 || !r.eng.Current().Device("tv").VendorCloud {
		t.Fatal("a request acted while tripped")
	}
	r.cut.set(Reflashed)
	// Straight after the step, a kernel's run of Paused answers past the
	// refusal bucket leaves the reopened summaries answering.
	for i := range 2 * DefaultLimit(KindRefused).Burst {
		if c := cl.code(cmd(uint64(2000+i), "lamp", wire.VerbOn)); c != wire.Paused {
			t.Fatalf("reflashed: %v", c)
		}
	}
	if c := cl.code(wire.Read{ID: 2100, What: wire.ReadTraffic, Device: "lamp"}); c != wire.OK {
		t.Fatalf("reflashed: a summary after a run of Paused answers: %v", c)
	}
	check("reflashed", 12, map[string]wire.Code{"summary": wire.OK, "counts": wire.OK})
	r.cut.set(Open)
	check("restored", 1, map[string]wire.Code{"command": wire.OK, "tighten": wire.OK, "state": wire.OK, "export": wire.OK,
		"fingerprint": wire.OK, "summary": wire.OK, "counts": wire.OK, "announce": wire.OK, "head": wire.OK, "entry": wire.OK})
	if r.cut.trips() != 0 {
		t.Errorf("%d trips: a paused request tripped the core", r.cut.trips())
	}
}

// TestTruncatedFrameOnlyEnds: a stream that ends mid-frame is a lost
// connection, not a message outside the format, so it ends the
// connection and trips nothing (an honest core's link can drop
// mid-write). Revert mutant: malformed counting wire.ErrShort.
func TestTruncatedFrameOnlyEnds(t *testing.T) {
	r := newRig(t, nil)
	good, _ := wire.Encode(wire.ToEnforcer, cmd(1, "lamp", wire.VerbOn))
	raw := frameBytes(good.Type, good.Payload)
	cl := r.dial()
	cl.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cl.conn.Write(raw[:len(raw)-1]); err != nil {
		t.Fatal(err)
	}
	cl.conn.Close()
	<-cl.done
	if r.cut.trips() != 0 {
		t.Fatal("a truncated frame tripped the core")
	}
}

// TestCountRead (NET-2 Byte caps, #4174): the count read names no device
// and returns the enforcer's counts in the shared format's one encoding,
// which the kernel decodes; with no counts source it is refused, and a
// source that fails answers Failed, never a partial count. An honest
// kernel reading once each wire.SummaryInterval for a day, and once at
// exactly twice it after a gap, is never limited or tripped. Revert
// mutant: ReadCounts left out of summaryRead (TestTripPausesUntilRestore).
func TestCountRead(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	rep, ok := cl.do(wire.Read{ID: 1, What: wire.ReadCounts}).(wire.ReadReply)
	if !ok {
		t.Fatalf("count read: %+v", rep)
	}
	cs, err := wire.DecodeCounts(rep.Body)
	if err != nil || cs.Day != 1 || len(cs.Groups) != 1 || cs.Groups[0].Count != 3 || cs.Groups[0].Cap() != 9 {
		t.Fatalf("counts %+v, %v", cs, err)
	}
	for i := range 24 * 60 {
		r.advance(wire.SummaryInterval)
		if c := cl.code(wire.Read{ID: uint64(10 + i), What: wire.ReadCounts}); c != wire.OK {
			t.Fatalf("read %d at the summary interval: %v", i, c)
		}
	}
	r.advance(2 * wire.SummaryInterval)
	if c := cl.code(wire.Read{ID: 5000, What: wire.ReadCounts}); c != wire.OK || r.cut.trips() != 0 {
		t.Fatalf("read at twice the interval: %v, %d trips", c, r.cut.trips())
	}

	none := newRig(t, func(c *Config) { c.Counts = nil })
	if c := none.dial().code(wire.Read{ID: 1, What: wire.ReadCounts}); c != wire.Refused {
		t.Errorf("no counts source: %v", c)
	}
	broken := newRig(t, func(c *Config) {
		c.Counts = func() (wire.Counts, error) { return wire.Counts{}, errors.New("nft down") }
	})
	if c := broken.dial().code(wire.Read{ID: 1, What: wire.ReadCounts}); c != wire.Failed {
		t.Errorf("failing source: %v", c)
	}
	bad := newRig(t, func(c *Config) {
		c.Counts = func() (wire.Counts, error) {
			return wire.Counts{Groups: []wire.CountGroup{{Count: 1}}}, nil // an empty group: outside the format
		}
	})
	if c := bad.dial().code(wire.Read{ID: 1, What: wire.ReadCounts}); c != wire.Failed {
		t.Errorf("source outside the format: %v", c)
	}
}

// TestPausedBurstTripsNothingMore (Security release on #4377): a paused
// core that keeps asking past its rate trips nothing more, while tripped
// or after the reflash step, so its retries never undo the owner's step;
// a summary burst past the rate at the Reflashed stage, where summaries
// act, still trips. Revert mutant: counting a paused request with count.
func TestPausedBurstTripsNothingMore(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	for _, st := range []Stage{Tripped, Reflashed} {
		r.cut.set(st)
		for i := range DefaultLimit(KindCommand).Burst + 5 {
			if c := cl.code(cmd(uint64(i+1), "lamp", wire.VerbOn)); c != wire.Paused {
				t.Fatalf("stage %d: %v", st, c)
			}
		}
		for range DefaultLimit(KindHello).Burst + 5 {
			cl = r.dial() // each hello replaces the connection before it
		}
		if r.cut.trips() != 0 || r.cut.Stage() != st {
			t.Fatalf("stage %d: %d trips, stage now %d", st, r.cut.trips(), r.cut.Stage())
		}
		r.advance(time.Hour)
	}
	for i := 0; r.cut.trips() == 0; i++ {
		if i > DefaultLimit(KindRead).Burst+1 {
			t.Fatal("a summary burst at the Reflashed stage never tripped")
		}
		cl.do(wire.Read{ID: uint64(100 + i), What: wire.ReadCounts})
	}
}

// TestPausedRequestsTakeTheirRate: a paused request and a cut core's
// reconnect each take their rate's token (ENF-d-4), so a burst sent while
// paused leaves no tokens to spend on the restore. Revert mutants: the
// takes in gate and in the hello.
func TestPausedRequestsTakeTheirRate(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	r.cut.set(Tripped)
	for i := range DefaultLimit(KindCommand).Burst {
		cl.code(cmd(uint64(i+1), "lamp", wire.VerbOn))
	}
	r.cut.set(Open)
	cl.code(cmd(1000, "lamp", wire.VerbOn))
	if r.cut.trips() != 1 {
		t.Fatalf("a command after a paused burst: %d trips, want 1", r.cut.trips())
	}

	r = newRig(t, nil)
	r.cut.set(Tripped)
	for range DefaultLimit(KindHello).Burst {
		r.dial()
	}
	r.cut.set(Open)
	r.dial()
	if r.cut.trips() != 1 {
		t.Fatalf("a hello after a cut core's reconnects: %d trips, want 1", r.cut.trips())
	}
}
