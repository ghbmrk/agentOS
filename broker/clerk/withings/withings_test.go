package withings

// REQ: DEV-3, DEV-4, DEV-8, DEV-12, CLK-1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

type fixedRand struct{}

func (fixedRand) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0xa5
	}
	return len(b), nil
}

type rig struct {
	scale *fakeScale
	sess  *Session
	logs  []string
}

func newRig(f *fakeScale, kl string) *rig {
	r := &rig{scale: f}
	r.sess = &Session{Link: f, Prover: NewKeyProver([]byte(kl)), Rand: fixedRand{},
		Log: func(s string) { r.logs = append(r.logs, s) }}
	return r
}

func (r *rig) read(t *testing.T) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return r.sess.Read(ctx)
}

// twoWeighIns is one weigh-in split over two groups with one time (body
// composition, then heart rate), an unknown measure code, a value with no
// META before it, a value after a bad META, and a second weigh-in by another
// user slot.
func twoWeighIns(f *fakeScale) {
	f.records = [][]tlv{
		{data(9999, 1, -2)}, // no META yet: dropped
		{meta(1700000000, 1, 7, 0, 0), data(8215, 1, -2), data(221, 6, -1)},
		{meta(1700000000, 1, 7, 0, 0), data(64, 11, 0), data(5, 177, 0)},
		{{tMeasureMeta, []byte{1, 2}}, data(7777, 1, -2)}, // bad META: both dropped
		{meta(1700003600, 1, 8, 0, 0), data(6050, 1, -2)},
	}
}

// A synthetic scale's weigh-ins come back as typed readings, merged by time,
// user and measure, each unverified (DEV-3, DEV-8), and the reader wrote
// only read frames, in the source's order.
func TestSyntheticScaleReadingsParse(t *testing.T) {
	f := newScale()
	twoWeighIns(f)
	r := newRig(f, klCanary)
	res, err := r.read(t)
	if err != nil {
		t.Fatal(err)
	}
	want := []Reading{
		{1700000000, 7, "fat_ratio_pct", 221, -1, true},
		{1700000000, 7, "heart_rate_bpm", 64, 0, true},
		{1700000000, 7, "weight_kg", 8215, -2, true},
		{1700003600, 8, "weight_kg", 6050, -2, true},
	}
	if fmt.Sprint(res.Readings) != fmt.Sprint(want) {
		t.Fatalf("readings %+v, want %+v", res.Readings, want)
	}
	if res.Dropped != 4 || res.Battery != 87 || res.Reason != 2 || res.Firmware != 1311 {
		t.Fatalf("result %+v", res)
	}
	if v := res.Readings[2].Float(); v < 82.149 || v > 82.151 {
		t.Fatalf("weight %v", v)
	}
	ws := f.frames()
	order := []uint16{cmdProbe, cmdChallenge, cmdBattery, cmdConnectReason, cmdStoredMeasure, cmdStoredMeasure, cmdSyncOK, cmdDisconnect}
	if len(ws) != len(order) {
		t.Fatalf("%d frames written, want %d", len(ws), len(order))
	}
	for i, w := range ws {
		m, _ := decode(w)
		if m.cmd != order[i] || !allowed(w) {
			t.Fatalf("frame %d is command %d (allowed %v), want %d", i, m.cmd, allowed(w), order[i])
		}
	}
	if !bytes.Equal(ws[4], statusFrame) || !bytes.Equal(ws[5], allFrame) {
		t.Fatal("STORED_MEASURE sent with an action other than status and all")
	}
}

// An empty store is not read for records.
func TestEmptyStoreReadsNoRecords(t *testing.T) {
	f := newScale()
	res, err := newRig(f, klCanary).read(t)
	if err != nil || len(res.Readings) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, w := range f.frames() {
		if bytes.Equal(w, allFrame) {
			t.Fatal("records requested from an empty store")
		}
	}
}

// Every frame off the allowlist is refused before the link is written, and
// the refusal is logged by command number only (DEV-4, DEV-12): every
// command with an empty payload, every STORED_MEASURE action and rc but
// status and all, the source's never-send commands with plausible payloads,
// and every one-bit change to an allowed frame.
func TestEveryShapeOffTheAllowlistIsRefused(t *testing.T) {
	empty := map[uint16]bool{cmdBattery: true, cmdConnectReason: true, cmdSyncOK: true,
		cmdSyncOK | deviceRequest: true, cmdDisconnect: true}
	for c := 0; c <= 0xffff; c++ {
		if got := allowed(message{cmd: uint16(c)}.encode()); got != empty[uint16(c)] {
			t.Fatalf("empty command %d: allowed %v", c, got)
		}
	}
	for a := 0; a < 256; a++ {
		for rc := 0; rc < 256; rc++ {
			fr := message{cmdStoredMeasure, []tlv{{tMeasureAction, []byte{byte(a), byte(rc)}}}}.encode()
			if allowed(fr) != (rc == 0 && (a == 0 || a == 1)) {
				t.Fatalf("STORED_MEASURE action %d rc %d: allowed %v", a, rc, allowed(fr))
			}
		}
	}
	never := map[string][]byte{
		"association keys 308": message{308, []tlv{{308, str([]byte(klCanary))}}}.encode(),
		"setup ok 275":         message{cmd: 275}.encode(),
		"scale session 269":    message{269, []tlv{{269, []byte{1, 2, 3}}}}.encode(),
		"signal ack 328":       message{328, []tlv{{325, u32(1)}, {323, make([]byte, 8)}}}.encode(),
		"user units 274":       message{274, []tlv{{274, u16(1)}}}.encode(),
		"time set 1281":        message{1281, []tlv{{1281, make([]byte, 16)}}}.encode(),
		"delete all":           message{cmdStoredMeasure, []tlv{{tMeasureAction, []byte{2, 0}}}}.encode(),
		"status plus a tlv":    append(append([]byte(nil), statusFrame...), 0, 1, 0, 0),
		"error not unsupported": message{cmdError | deviceRequest, []tlv{{tCmdError,
			append(u16(308), u32(0)...)}}}.encode(),
		"challenge long mac": message{cmdChallenge, []tlv{{tChallengeResponse, str(make([]byte, 20))},
			{tChallenge, append(str(make([]byte, 33)), str(make([]byte, 16))...)}}}.encode(),
		"challenge short answer": message{cmdChallenge, []tlv{{tChallengeResponse, str(make([]byte, 19))},
			{tChallenge, append(str([]byte("m")), str(make([]byte, 16))...)}}}.encode(),
		"challenge extra tlv": message{cmdChallenge, []tlv{{tChallengeResponse, str(make([]byte, 20))},
			{tChallenge, append(str([]byte("m")), str(make([]byte, 16))...)}, {308, nil}}}.encode(),
	}
	for name, fr := range never {
		f := newScale()
		r := newRig(f, klCanary)
		if err := r.sess.send(context.Background(), fr); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: send gave %v", name, err)
		}
		if len(f.frames()) != 0 {
			t.Fatalf("%s reached the link", name)
		}
		want := fmt.Sprintf("refused frame, command %d, %d bytes, not sent", int(fr[1])<<8|int(fr[2]), len(fr))
		if len(r.logs) != 1 || r.logs[0] != want {
			t.Fatalf("%s logged %q", name, r.logs)
		}
	}
	allowedSet := map[string]bool{}
	for _, fr := range fixedFrames {
		allowedSet[string(fr)] = true
	}
	for _, fr := range fixedFrames {
		for i := range fr {
			for bit := 0; bit < 8; bit++ {
				m := append([]byte(nil), fr...)
				m[i] ^= 1 << bit
				if allowed(m) && !allowedSet[string(m)] {
					t.Fatalf("frame %x with byte %d bit %d flipped is allowed", fr, i, bit)
				}
			}
		}
	}
}

// Requests from the scale get only the unsupported error, naming the
// request, and SYNC_OK only its echo; none is acted on. A scale that floods
// requests ends the session, and a malformed frame ends it without a reply.
func TestScaleRequestsGetOnlyAllowedReplies(t *testing.T) {
	f := newScale()
	twoWeighIns(f)
	f.after = [][]byte{
		message{308 | deviceRequest, []tlv{{308, str([]byte("x"))}}}.encode(),
		message{cmd: 275 | deviceRequest}.encode(),
		message{1281 | deviceRequest, []tlv{{1281, make([]byte, 16)}}}.encode(),
		message{cmd: cmdSyncOK | deviceRequest}.encode(),
	}
	res, err := newRig(f, klCanary).read(t)
	if err != nil || len(res.Readings) != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	var answers []string
	for _, w := range f.frames() {
		if !allowed(w) {
			t.Fatalf("frame %x written off the allowlist", w)
		}
		m, _ := decode(w)
		if m.fromDevice() {
			answers = append(answers, fmt.Sprintf("%d:%x", m.cmd, m.find(tCmdError)))
		}
	}
	want := []string{
		fmt.Sprintf("%d:%x", cmdError|deviceRequest, append(u16(308), u32(0xfffffffd)...)),
		fmt.Sprintf("%d:%x", cmdError|deviceRequest, append(u16(275), u32(0xfffffffd)...)),
		fmt.Sprintf("%d:%x", cmdError|deviceRequest, append(u16(1281), u32(0xfffffffd)...)),
		fmt.Sprintf("%d:", cmdSyncOK|deviceRequest),
	}
	if fmt.Sprint(answers) != fmt.Sprint(want) {
		t.Fatalf("answers %v, want %v", answers, want)
	}

	flood := newScale()
	for range maxDeviceReqs + 1 {
		flood.after = append(flood.after, message{cmd: 274 | deviceRequest}.encode())
	}
	if _, err := newRig(flood, klCanary).read(t); !errors.Is(err, ErrFlood) {
		t.Fatalf("flood: %v", err)
	}

	bad := newScale()
	bad.after = [][]byte{{0x01, 0x41, 0x00, 0x00, 0x03, 0x01, 0x34, 0x00}} // TLV cut short
	if _, err := newRig(bad, klCanary).read(t); !errors.Is(err, ErrScale) {
		t.Fatalf("malformed: %v", err)
	}
	ws := bad.frames()
	if last, _ := decode(ws[len(ws)-1]); len(ws) != 3 || last.cmd != cmdDisconnect {
		t.Fatalf("after a malformed frame the reader wrote %d frames", len(ws))
	}
}

// A scale that fails the kl proof, or answers in setup mode without one,
// gets DISCONNECT and nothing else (DEV-3).
func TestUnprovenScaleGetsNoCommand(t *testing.T) {
	cases := map[string]struct {
		mod  func(*fakeScale)
		kl   string
		want error
		cmds []uint16
	}{
		"bad proof":  {func(f *fakeScale) { f.badProof = true }, klCanary, ErrUnproven, []uint16{cmdProbe, cmdChallenge, cmdDisconnect}},
		"setup mode": {func(f *fakeScale) { f.setup = true }, klCanary, ErrSetupMode, []uint16{cmdProbe, cmdDisconnect}},
		"wrong kl":   {func(*fakeScale) {}, "CANARY-other-key", nil, []uint16{cmdProbe, cmdChallenge, cmdDisconnect}},
	}
	for name, c := range cases {
		f := newScale()
		twoWeighIns(f)
		c.mod(f)
		res, err := newRig(f, c.kl).read(t)
		var se ScaleError
		if c.want != nil && !errors.Is(err, c.want) || c.want == nil && !errors.As(err, &se) || len(res.Readings) != 0 {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		ws := f.frames()
		if len(ws) != len(c.cmds) {
			t.Fatalf("%s: %d frames written, want %d", name, len(ws), len(c.cmds))
		}
		for i, w := range ws {
			if m, _ := decode(w); m.cmd != c.cmds[i] {
				t.Fatalf("%s: frame %d is command %d", name, i, m.cmd)
			}
		}
	}
}

// The canary kl appears in no log line, error, result, written frame or
// printed prover or session (CLK-1).
func TestKlNeverLeaves(t *testing.T) {
	var seen []string
	for _, mod := range []func(*fakeScale){
		func(*fakeScale) {},
		func(f *fakeScale) { f.badProof = true },
		func(f *fakeScale) { f.kl = []byte("CANARY-other-key") },
		func(f *fakeScale) { f.after = [][]byte{message{cmd: 308 | deviceRequest}.encode()} },
	} {
		f := newScale()
		twoWeighIns(f)
		mod(f)
		r := newRig(f, klCanary)
		res, err := r.read(t)
		seen = append(seen, r.logs...)
		seen = append(seen, fmt.Sprintf("%v %+v %#v", err, res, res))
		for _, w := range f.frames() {
			seen = append(seen, string(w))
		}
		p := r.sess.Prover
		seen = append(seen, fmt.Sprintf("%v %+v %#v %s %q", p, p, p, p, p), fmt.Sprintf("%+v %#v", *r.sess, r.sess))
		kp := *p.(*KeyProver)
		seen = append(seen, fmt.Sprintf("%v %+v %#v", kp, kp, kp))
	}
	for _, s := range seen {
		if strings.Contains(s, klCanary) {
			t.Fatalf("kl leaked: %q", s)
		}
	}
}

// Every declared operation maps to read (DEV-4, DEV-12).
func TestDeclarationIsReadOnly(t *testing.T) {
	if len(Declaration.Operations) == 0 {
		t.Fatal("no operations")
	}
	for _, op := range Declaration.Operations {
		if op.Verb != key.Read {
			t.Fatalf("operation %s is %s", op.Name, op.Verb)
		}
	}
}

// No notification stream panics the reassembler or the record parser, and
// its buffer stays under one frame plus one fragment.
func FuzzReassemble(f *testing.F) {
	f.Add(allFrame, uint8(7))
	f.Add(append(statusFrame, probeFrame...), uint8(3))
	f.Add([]byte{0x01, 0xff, 0xff, 0xff, 0xff}, uint8(1))
	f.Fuzz(func(t *testing.T, b []byte, n uint8) {
		step := int(n%64) + 1
		var r reassembler
		var ms []message
		for len(b) > 0 {
			k := min(step, len(b))
			out, err := r.feed(b[:k])
			ms = append(ms, out...)
			if err != nil {
				break
			}
			if len(r.buf) > headerLen+0xffff+step {
				t.Fatalf("buffer %d bytes", len(r.buf))
			}
			b = b[k:]
		}
		parseRecords(ms)
		for _, m := range ms {
			firmware(m.find(tProbeReply))
		}
	})
}
