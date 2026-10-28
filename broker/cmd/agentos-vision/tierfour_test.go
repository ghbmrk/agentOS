package main

// REQ: DEV-7

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/vision"
	"github.com/ghbmrk/agentos/broker/vision/faces"
)

// Enrolment happens only on the owner's tier-4 step: an anchor's tap over
// the one change Begin named, after the consent notice. The feed socket
// cannot ask for a template, and an enrolment without the anchor's tap, or
// with a passkey that is no anchor's, makes no encoding and writes no slot
// (DEV-7, CH-3).
func TestEnrolOnlyFromTierFour(t *testing.T) {
	r := newFrig(t, true)
	fr := gray(64, 48, 1)
	frame, _ := json.Marshal(vision.Request{Op: vision.OpEnrol, Format: fr.Format, Width: 64, Height: 48, Bytes: 64 * 48})
	if got, _ := raw(t, r.feed.Path, append(append(frame, '\n'), fr.Data...)); got != `{"error":"bad_request"}` {
		t.Fatalf("enrol on the feed socket: %s", got)
	}
	ctx := context.Background()
	other := key.Ed25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)))
	for name, sign := range map[string]func(w [32]byte) key.Cosign{
		"no tap":         func([32]byte) key.Cosign { return key.Cosign{} },
		"another's key":  func(w [32]byte) key.Cosign { return key.Approve(other, w) },
		"another change": func([32]byte) key.Cosign { return key.Approve(anchor, [32]byte{7}) },
	} {
		w, err := r.fs.Begin("alice", "", fr)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.fs.Enrol(ctx, "alice", "", fr, w, sign(w)); !errors.Is(err, faces.ErrApproval) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r.f.mu.Lock()
	made := len(r.f.given)
	r.f.mu.Unlock()
	if made != 0 || r.sec.Len() != 0 {
		t.Fatalf("a refused enrolment made %d encodings and %d slots", made, r.sec.Len())
	}
	// The notice, whose version the anchor's change pins, says what the page
	// must. That the page shows it is the page's own test (VIS-A17).
	for _, w := range []string{"consent", "until you remove them", "after a restore"} {
		if !strings.Contains(faces.ConsentNotice, w) {
			t.Errorf("the consent notice does not say %q", w)
		}
	}
	r.enrol("alice", aliceFace)
	if got := r.sees(aliceFace); got != vision.FaceEnrolledAs+"alice" {
		t.Fatalf("after the tier-4 step: %q", got)
	}
}

// marker is placed in every synthetic frame and audio clip.
var marker = []byte("VIS-CAPTURE-CANARY")

func marked(n int) []byte {
	b := bytes.Repeat(marker, n/len(marker)+1)
	return b[:n]
}

// Nothing VIS-core hands a planner, the bus or a route carries capture or
// a template: the types that leave it hold no bytes or numbers that could
// (Detection, Sound, Ask, and the closed reasons), and after a run over
// marked frames and audio with alice enrolled, no marker byte and no
// encoding is in any reply, refusal or log line. Crops go only to the
// owner's page, and VIS-core serves none yet (brief point 8; part b adds
// the track outputs, part f the bus).
func TestNoCaptureLeavesVIS(t *testing.T) {
	for _, v := range []any{vision.Detection{}, vision.Sound{}, vision.Ask{}, vision.Count{}, vision.ZoneEvent{}, vision.PlateEvent{}, vision.SoundEvent{}} {
		if f, ok := carrier(reflect.TypeOf(v)); ok {
			t.Fatalf("%T.%s could carry capture or an encoding", v, f)
		}
	}
	r := newFrig(t, true)
	r.enrol("alice", aliceFace)
	var out [][]byte
	ctx := context.Background()
	for _, face := range [][]float32{aliceFace, strangerFace} {
		r.f.mu.Lock()
		r.f.face = face
		r.f.mu.Unlock()
		ds, err := r.feed.Detect(ctx, vision.Frame{Format: vision.FormatGray8, Width: 64, Height: 48, Data: marked(64 * 48)})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(ds)
		out = append(out, b)
	}
	ss, err := r.feed.Sound(ctx, marked(3200))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ss)
	out = append(out, b, []byte(r.log.String()))
	for _, a := range []vision.Ask{{Op: "find", Camera: "front-door"}, {Op: "crops", Camera: "front-door"}} {
		out = append(out, []byte(vision.CheckAsk(a).Error()))
	}
	for _, e := range []error{faces.ErrApproval, faces.ErrNoErase, faces.ErrID} {
		out = append(out, []byte(e.Error()))
	}
	for _, o := range out {
		if bytes.Contains(o, marker[:8]) {
			t.Fatalf("a marker left VIS-core: %q", o)
		}
		if near(o, aliceFace) || near(o, strangerFace) {
			t.Fatalf("an encoding left VIS-core: %q", o)
		}
	}
}

// carrier names a field of t, at any depth, that holds bytes or numbers
// beyond a scalar: a slice, array or map of anything, or a float.
func carrier(t reflect.Type) (string, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		switch f.Type.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map, reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
			return f.Name, true
		case reflect.Struct:
			if n, ok := carrier(f.Type); ok {
				return f.Name + "." + n, true
			}
		}
	}
	return "", false
}
