package main

// REQ: DEV-7, LOG-4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"math/rand/v2"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/vision"
	"github.com/ghbmrk/agentos/broker/vision/faces"
)

// Synthetic encodings: alice's, the one enrolled, and a stranger's, far
// from it. No real face is behind either.
var (
	aliceFace    = []float32{0.11, 0.73, -0.29, 0.41, 0.07, -0.44}
	strangerFace = []float32{-0.62, 0.05, 0.38, -0.17, 0.59, 0.31}
)

// failKeys is a key table whose Delete can be made to fail: the crash
// between subject.erased and the key's delete.
type failKeys struct {
	*kernel.MemKeys
	fail bool
}

func (f *failKeys) Delete(s string) error {
	if f.fail {
		return errors.New("crash before the key goes")
	}
	return f.MemKeys.Delete(s)
}

// krig is an in-process kernel with a key table and the vision content
// store, whose log, keys and store survive a restart (boot).
type krig struct {
	t      *testing.T
	log    *kernel.MemStore
	anchor *kernel.MemAnchor
	rnd    *rand.ChaCha8
	keys   *failKeys
	store  *kernel.MemContent
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	k      *kernel.Kernel
	now    int64
	open   bool // OpenContent runs at boot
}

func newKrig(t *testing.T, open bool) *krig {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 5
	priv := ed25519.NewKeyFromSeed(seed)
	r := &krig{t: t, log: &kernel.MemStore{}, anchor: &kernel.MemAnchor{}, rnd: rand.NewChaCha8([32]byte{3}),
		keys: &failKeys{MemKeys: kernel.NewMemKeys()}, store: kernel.NewMemContent(),
		pub: priv.Public().(ed25519.PublicKey), priv: priv, now: 1000, open: open}
	r.boot()
	return r
}

func (r *krig) boot() {
	r.t.Helper()
	l, err := kernel.Open(kernel.Config{Store: r.log, Anchor: r.anchor, Pub: r.pub, Sign: r.priv, Rand: r.rnd})
	if err != nil {
		r.t.Fatal(err)
	}
	if r.k, err = kernel.Boot(l, nil, nil, r.now); err != nil {
		r.t.Fatal(err)
	}
	if r.open {
		if _, err := r.k.OpenContent(r.keys, map[string]kernel.ContentStore{"vision": r.store}, r.now); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *krig) tick() int64 { r.now++; return r.now }

// The content seam over the in-process kernel: what the content socket
// (kernel/proc ContentSide) serves the side that holds the slots.
func (r *krig) OpenSubject() (string, error) { return r.k.OpenSubject(r.tick()) }
func (r *krig) Seal(sub, class string, data []byte) (faces.Hash, error) {
	h, err := r.k.Seal(r.tick(), sub, "vision", class, data)
	return faces.Hash(h), err
}
func (r *krig) ReadFor(h faces.Hash, lineage string) ([]byte, error) {
	return r.k.ReadFor(r.tick(), kernel.Hash(h), lineage)
}

// slotsOf is the wiring's Slots over a clerk.Secrets store.
func slotsOf(s *clerk.Secrets) faces.Slots {
	return faces.Slots{
		Names:  func() []string { return s.Names(clerk.VisionTemplateSlots) },
		Put:    func(slot string, rec []byte) error { return s.Put(slot, clerk.KindStatic, rec) },
		Remove: s.Remove,
		Lend:   s.VisionTemplate,
	}
}

// gone is part (f)'s reading of the kernel's answers: an erased or
// unknown subject, or an unknown item, opens nothing ever again.
func gone(err error) bool {
	return errors.Is(err, kernel.ErrErased) || errors.Is(err, kernel.ErrSubject) || errors.Is(err, kernel.ErrItem)
}

// frig is the service, its feed and control sockets, the slots and the
// kernel, wired as part (f) wires them.
type frig struct {
	t    *testing.T
	f    *fake
	svc  *service
	log  *lockedBuffer
	feed vision.Client
	ctl  vision.ControlClient
	k    *krig
	sec  *clerk.Secrets
	fs   *faces.Faces
	seen [][]byte // every detect reply as it crossed the feed socket
}

func newFrig(t *testing.T, open bool) *frig {
	t.Helper()
	r := &frig{t: t, f: newFake(), log: &lockedBuffer{}, k: newKrig(t, open)}
	r.svc = newService(Config{}, r.f, r.log)
	dir := t.TempDir()
	feed, ctl := filepath.Join(dir, "vision.sock"), filepath.Join(dir, "vision.sock.control")
	for path, serve := range map[string]func(net.Listener) error{feed: r.svc.Serve, ctl: r.svc.ServeControl} {
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go serve(ln)
	}
	sealer, err := clerk.NewAESSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r.sec = clerk.NewSecrets(sealer, nil)
	r.ctl = vision.ControlClient{Path: ctl, Timeout: 5 * time.Second}
	r.fs = &faces.Faces{Slots: slotsOf(r.sec), Content: r.k, Gone: gone, Control: r.ctl}
	r.feed = vision.Client{Path: feed, Timeout: 5 * time.Second, Enrolled: r.fs.Enrolled}
	return r
}

// enrol enrols the face the fake now sees as id.
func (r *frig) enrol(id string, face []float32) string {
	r.t.Helper()
	r.f.mu.Lock()
	r.f.face = face
	r.f.mu.Unlock()
	if err := r.fs.Enrol(context.Background(), id, "", gray(64, 48, 1)); err != nil {
		r.t.Fatalf("enrol %s: %v", id, err)
	}
	return r.subject(id)
}

// subject is the subject id's slot is bound to: in the wrap key's
// content.stored entry, the one item of class faces.WrapClass.
func (r *frig) subject(id string) string {
	r.t.Helper()
	var sub string
	err := r.sec.VisionTemplate(clerk.VisionTemplateSlots + id)(func(b []byte) error {
		var rec struct{ Subject string }
		err := json.Unmarshal(b, &rec)
		sub = rec.Subject
		return err
	})
	if err != nil {
		r.t.Fatalf("slot of %s: %v", id, err)
	}
	return sub
}

// sees returns the face the service names for face.
func (r *frig) sees(face []float32) string {
	r.t.Helper()
	r.f.mu.Lock()
	r.f.face = face
	r.f.mu.Unlock()
	ds, err := r.feed.Detect(context.Background(), gray(64, 48, 1))
	if err != nil || len(ds) != 1 {
		r.t.Fatalf("detect: %+v %v", ds, err)
	}
	b, _ := json.Marshal(ds)
	r.seen = append(r.seen, b)
	if !r.f.zeroed() {
		r.t.Fatal("an encoding outlived the call that made it")
	}
	return ds[0].Face
}

// An enrolled face is named, a stranger's is unknown, and neither reply
// carries an encoding: the face field is a name, and the service zeroed
// every encoding before it answered (DEV-7).
func TestEnrolledRecognisedUnknownNot(t *testing.T) {
	r := newFrig(t, true)
	if got := r.sees(aliceFace); got != vision.FaceUnknown {
		t.Fatalf("before enrolment: %q", got)
	}
	r.enrol("alice", aliceFace)
	if got := r.sees(aliceFace); got != vision.FaceEnrolledAs+"alice" {
		t.Fatalf("alice: %q", got)
	}
	if got := r.sees(strangerFace); got != vision.FaceUnknown {
		t.Fatalf("a stranger: %q", got)
	}
	// A noisy view of alice is still alice.
	noisy := append([]float32(nil), aliceFace...)
	noisy[0] += 0.05
	if got := r.sees(noisy); got != vision.FaceEnrolledAs+"alice" {
		t.Fatalf("alice, noisy: %q", got)
	}
	for _, b := range r.seen {
		var ds []map[string]any
		if err := json.Unmarshal(b, &ds); err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			for k, v := range d {
				if _, isList := v.([]any); isList || (k != "class" && k != "box" && k != "conf" && k != "face") {
					t.Fatalf("a reply field %q=%v beyond the closed shape", k, v)
				}
			}
		}
	}
}

// Un-enrolling empties the slot, and the same face is unknown at once.
func TestUnenrolDestroysTemplate(t *testing.T) {
	r := newFrig(t, true)
	r.enrol("alice", aliceFace)
	r.enrol("bob", strangerFace)
	if err := r.fs.Unenrol(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if r.sec.Has(clerk.VisionTemplateSlots + "alice") {
		t.Fatal("the slot outlived the un-enrolment")
	}
	if got := r.sees(aliceFace); got != vision.FaceUnknown {
		t.Fatalf("alice after un-enrolling: %q", got)
	}
	if got := r.sees(strangerFace); got != vision.FaceEnrolledAs+"bob" {
		t.Fatalf("bob: %q", got)
	}
	if r.fs.Enrolled("alice") || !r.fs.Enrolled("bob") {
		t.Fatal("the client's list does not follow the slots")
	}
}

// Erasing the subject makes the template unreadable even from a slot that
// survived, the next lend drops it from the service, and the slot then
// goes (LOG-4). Rewind, agentosd's D-169 rewind of svc-vision, does the
// same at once.
func TestEraseMakesTemplateUnusable(t *testing.T) {
	for _, how := range []string{"lend", "rewind"} {
		t.Run(how, func(t *testing.T) {
			r := newFrig(t, true)
			sub := r.enrol("alice", aliceFace)
			r.enrol("bob", strangerFace)
			kept, err := r.sec.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.k.k.Erase(r.k.tick(), sub); err != nil {
				t.Fatal(err)
			}
			if how == "rewind" {
				err = r.fs.Rewind(context.Background(), sub)
			} else {
				err = r.fs.Sync(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := r.sees(aliceFace); got != vision.FaceUnknown {
				t.Fatalf("alice after the erase: %q", got)
			}
			if r.sec.Has(clerk.VisionTemplateSlots + "alice") {
				t.Fatal("the slot was not removed")
			}
			// The slot put back, as a copy that survived: it opens nothing.
			if err := r.sec.UnmarshalBinary(kept); err != nil {
				t.Fatal(err)
			}
			r.fs.Sync(context.Background())
			if got := r.sees(aliceFace); got != vision.FaceUnknown {
				t.Fatalf("alice from a surviving slot: %q", got)
			}
			if got := r.sees(strangerFace); got != vision.FaceEnrolledAs+"bob" {
				t.Fatalf("bob after alice's erase: %q", got)
			}
		})
	}
}

// A crash between subject.erased and the key's delete: the restart
// deletes the key, and the template is unreadable from then on.
func TestCrashAfterEraseLogged(t *testing.T) {
	r := newFrig(t, true)
	sub := r.enrol("alice", aliceFace)
	r.k.keys.fail = true
	r.k.k.Erase(r.k.tick(), sub)
	r.k.keys.fail = false
	if _, ok, _ := r.k.keys.Get(sub); !ok {
		t.Fatal("setup: the key should have survived the crash")
	}
	r.k.boot()
	if _, ok, _ := r.k.keys.Get(sub); ok {
		t.Fatal("the restart did not delete the erased subject's key")
	}
	r.fs.Sync(context.Background())
	if got := r.sees(aliceFace); got != vision.FaceUnknown {
		t.Fatalf("alice after the restart: %q", got)
	}
	if r.sec.Has(clerk.VisionTemplateSlots + "alice") {
		t.Fatal("the slot outlived the restart's erase")
	}
}

// With no content store there is no erase, so enrolment is refused before
// any encoding is made, and no slot is written.
func TestEnrolmentRefusedWithoutErase(t *testing.T) {
	r := newFrig(t, false) // the kernel runs, its content stays closed
	for name, c := range map[string]faces.Content{"no seam": nil, "content closed": r.k} {
		fs := &faces.Faces{Slots: slotsOf(r.sec), Content: c, Gone: gone, Control: r.ctl}
		if err := fs.Enrol(context.Background(), "alice", "", gray(64, 48, 1)); !errors.Is(err, faces.ErrNoErase) {
			t.Fatalf("%s: %v", name, err)
		}
		if r.sec.Len() != 0 {
			t.Fatalf("%s: a slot was written", name)
		}
		if !r.f.zeroed() {
			t.Fatalf("%s: an encoding was left", name)
		}
	}
	r.f.mu.Lock()
	n := len(r.f.given)
	r.f.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d encodings made; only the closed store's enrolment reaches the service", n)
	}
}

// After enrolment the template is in the slot only: the kernel's log, its
// store, the subject's recall and a ReadFor of its one item hold the wrap
// key, never the template, and no other lend opens the slot (DEV-7, LOG-4).
func TestTemplatesNotInRecall(t *testing.T) {
	r := newFrig(t, true)
	sub := r.enrol("alice", aliceFace)
	tpl := leBytes(aliceFace)
	rc, ok := r.k.k.State().Recall(sub)
	if !ok || len(rc.Items) != 1 || rc.Items[0].Class != faces.WrapClass {
		t.Fatalf("recall: %+v", rc)
	}
	wk, err := r.k.k.ReadFor(r.k.tick(), rc.Items[0].Hash, "lin-agent")
	if err != nil || len(wk) != 32 || bytes.Contains(wk, tpl[:8]) {
		t.Fatalf("the item is not a wrap key: %d bytes, %v", len(wk), err)
	}
	var hay [][]byte
	for _, e := range r.k.k.Log().Entries() {
		b, _ := json.Marshal(e)
		hay = append(hay, b)
	}
	b, _ := json.Marshal(rc)
	hay = append(hay, b, r.k.log.B)
	for _, ct := range r.k.store.M {
		hay = append(hay, ct)
	}
	for _, h := range hay {
		if near(h, aliceFace) {
			t.Fatal("the template is in the kernel's log, store or recall")
		}
	}
	slot := clerk.VisionTemplateSlots + "alice"
	if err := r.sec.DeviceKey(slot)(func([]byte) error { return nil }); err == nil {
		t.Fatal("a device lend opened a template slot")
	}
	if _, err := r.sec.Login(slot, "x")(context.Background()); err == nil {
		t.Fatal("a mail login opened a template slot")
	}
}

// A stranger's encoding is in no reply, log line, slot, lent template or
// kernel record after a run that saw them many times: only alice's
// template is anywhere, and only where enrolment put it (A16 as amended,
// D-207).
func TestUnenrolledEncodingNeverLeaves(t *testing.T) {
	r := newFrig(t, true)
	r.enrol("alice", aliceFace)
	for range 20 {
		if got := r.sees(strangerFace); got != vision.FaceUnknown {
			t.Fatalf("the stranger: %q", got)
		}
	}
	atRest, _ := r.sec.MarshalBinary()
	hay := append([][]byte{[]byte(r.log.String()), atRest, r.k.log.B}, r.seen...)
	for _, e := range r.k.k.Log().Entries() {
		b, _ := json.Marshal(e)
		hay = append(hay, b)
	}
	for _, ct := range r.k.store.M {
		hay = append(hay, ct)
	}
	for _, h := range hay {
		if near(h, strangerFace) {
			t.Fatal("a stranger's encoding was kept")
		}
	}
	r.svc.tmu.RLock()
	defer r.svc.tmu.RUnlock()
	if len(r.svc.tpl) != 1 || r.svc.tpl["alice"] == nil {
		t.Fatalf("the service holds %d templates", len(r.svc.tpl))
	}
	if !r.f.zeroed() {
		t.Fatal("an encoding outlived its call")
	}
}

// After an erase no Rewind reported, the service drops the template within
// one lend period (comment 6459973175, point 2): Run's every.
func TestErasedTemplateDroppedWithinTheDelay(t *testing.T) {
	r := newFrig(t, true)
	sub := r.enrol("alice", aliceFace)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	every := 50 * time.Millisecond
	done := make(chan struct{})
	r.k.k.Erase(r.k.tick(), sub) // the kernel is called only under Run's lock below
	go func() { r.fs.Run(ctx, every, nil); close(done) }()
	deadline := time.Now().Add(20 * every)
	for r.svcHolds("alice") {
		if time.Now().After(deadline) {
			t.Fatal("the service still holds an erased subject's template")
		}
		time.Sleep(every / 5)
	}
	cancel()
	<-done
	if got := r.sees(aliceFace); got != vision.FaceUnknown {
		t.Fatalf("alice after the drop: %q", got)
	}
}

func (r *frig) svcHolds(id string) bool {
	r.svc.tmu.RLock()
	defer r.svc.tmu.RUnlock()
	_, ok := r.svc.tpl[id]
	return ok
}

// The control ops are the control socket's only, and the feed's ops are
// the feed socket's only: a feed that reaches the service can neither lend
// templates nor ask for one.
func TestControlOpsOnlyOnTheControlSocket(t *testing.T) {
	r := newFrig(t, true)
	lend, _ := vision.EncodeLend([]vision.Template{{ID: "mallory", Vec: leBytes(strangerFace)}})
	frame := gray(8, 8, 1)
	for _, tc := range []struct {
		path    string
		req     vision.Request
		payload []byte
	}{
		{r.feed.Path, vision.Request{Op: vision.OpLend, Bytes: len(lend)}, lend},
		{r.feed.Path, vision.Request{Op: vision.OpEnrol, Format: frame.Format, Width: 8, Height: 8, Bytes: 64}, frame.Data},
		{r.ctl.Path, vision.Request{Op: vision.OpDetect, Format: frame.Format, Width: 8, Height: 8, Bytes: 64}, frame.Data},
		{r.ctl.Path, vision.Request{Op: vision.OpHello}, nil},
	} {
		h, _ := json.Marshal(tc.req)
		if got, _ := raw(t, tc.path, append(append(h, '\n'), tc.payload...)); got != `{"error":"bad_request"}` {
			t.Errorf("%s on %s: %s", tc.req.Op, filepath.Base(tc.path), got)
		}
	}
	if r.svcHolds("mallory") {
		t.Fatal("the feed socket lent a template")
	}
	if _, err := r.ctl.Enrol(context.Background(), frame); err != nil {
		t.Fatalf("enrol on the control socket: %v", err)
	}
	r.f.failNext("noface", 1)
	if _, err := r.ctl.Enrol(context.Background(), frame); !isCause(err, vision.NoFace) {
		t.Fatalf("no face: %v", err)
	}
	// A frame with no face does not fail the runtime: no reload.
	if r.f.loads != 1 {
		t.Fatalf("%d loads", r.f.loads)
	}
}

func leBytes(v []float32) []byte {
	var b []byte
	for _, x := range v {
		b = binary.LittleEndian.AppendUint32(b, math.Float32bits(x))
	}
	return b
}

// near reports a run of little-endian float32s anywhere in b, at any byte
// offset, within cosine 0.99 of ref, or of ref scaled (the service keeps
// templates at unit length): an encoding, however it was stored.
func near(b []byte, ref []float32) bool {
	n := len(ref)
	for off := 0; off+4*n <= len(b); off++ {
		var dot, nv, nr float64
		for i := range n {
			x := float64(math.Float32frombits(binary.LittleEndian.Uint32(b[off+4*i:])))
			if math.IsNaN(x) || math.IsInf(x, 0) {
				nv = 0
				break
			}
			dot += x * float64(ref[i])
			nv += x * x
			nr += float64(ref[i]) * float64(ref[i])
		}
		if nv > 0 && dot/math.Sqrt(nv*nr) > 0.99 {
			return true
		}
	}
	return false
}
