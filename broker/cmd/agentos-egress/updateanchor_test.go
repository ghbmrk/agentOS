package main

// REQ: SR3-6f-2b, SR3-6f-2c
// SR3-6f-2b: the update store's outside-attestor record is anchored in a
// TPM NV counter the vault process keeps (swtpm, no hardware). A counter
// that was defined and is gone fails closed; the owner's re-trust defines
// a new one already raised. SR3-6f-2c: the counter is served on the
// broker-only verify socket, read and raise only.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/attest"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/google/go-tpm/tpm2"
)

// SR3-6f-2b: the first read defines the counter and reads 0; raise reads
// 1; raise again stays 1; a restart keeps it; the vault's own rollback
// counter still works beside it.
func TestUpdateAnchorCounter(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	if _, ok := r.c.v.Secret(UpdateAnchorName); ok {
		t.Fatal("the update counter was defined before the first read")
	}
	if anchored, n, err := r.c.updateAnchorRead(); err != nil || !anchored || n != 0 {
		t.Fatalf("first read = %v, %d, %v; want anchored at 0", anchored, n, err)
	}
	if !hasKind(r.c.v, UpdateAnchorName, KindUpdateAnchor) {
		t.Fatal("the first read did not record the counter in the vault")
	}
	if err := r.c.put(UpdateAnchorName, []byte("replacement-anchor-value")); err == nil {
		t.Fatal("the local UI's credential write replaced the update counter's record")
	}
	for i := 1; i <= 2; i++ {
		if _, _, err := r.c.updateAnchorRaise(); err != nil {
			t.Fatalf("raise %d: %v", i, err)
		}
		if anchored, n, err := r.c.updateAnchorRead(); err != nil || !anchored || n != 1 {
			t.Fatalf("after raise %d = %v, %d, %v; want anchored at 1", i, anchored, n, err)
		}
	}
	if err := r.c.put("openai", []byte(synthetic(t, "sk-canary-anchor-"))); err != nil {
		t.Fatalf("a vault write beside the update counter: %v", err)
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("restart: phase %v, notes %q", r.phase(), r.notes)
	}
	if anchored, n, err := r.c.updateAnchorRead(); err != nil || !anchored || n < 1 {
		t.Fatalf("after restart = %v, %d, %v; want anchored at 1 or more", anchored, n, err)
	}
}

// SR3-6f-2b: define, raise, undefine the NV index through the owner
// hierarchy, delete outside_attestor_listed: the read answers "anchor
// missing" (409 on the socket), the owner is told, and through the store a
// check with only interim keys grants no security authority.
func TestUndefinedUpdateCounterFailsClosed(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	box := newInterimBox(t, socketAnchor(r.c))
	if !box.interimCounts(t) {
		t.Fatal("setup: the interim rule did not hold on a fresh store")
	}
	box.listOutside(t)
	if box.interimCounts(t) {
		t.Fatal("setup: listing an outside attestor did not end the interim rule")
	}
	undefineUpdateCounter(t, r)
	box.deleteRecord(t)
	r.notes = nil

	if _, _, err := r.c.updateAnchorRead(); !errors.Is(err, errUpdateAnchorMissing) {
		t.Fatalf("read of an undefined counter = %v, want anchor missing", err)
	}
	if code := verifyStatus(r.c, http.MethodGet, update.AnchorPath); code != http.StatusConflict {
		t.Fatalf("socket read of an undefined counter: %d, want 409", code)
	}
	if code := verifyStatus(r.c, http.MethodPost, update.AnchorRaisePath); code != http.StatusConflict {
		t.Fatalf("socket raise of an undefined counter: %d, want 409", code)
	}
	if _, err := socketAnchor(r.c).Read(); err == nil || errors.Is(err, update.ErrNoAnchor) {
		t.Fatalf("client read of an undefined counter = %v; want an error, not ErrNoAnchor", err)
	}
	if box.interimCounts(t) {
		t.Fatal("an undefined counter and a deleted record revived the interim rule")
	}
	if n := countNote(r.notes, noteCounterReset); n != 1 {
		t.Fatalf("counter-reset notice shown %d times: %q", n, r.notes)
	}
}

// SR3-6f-2b: after the undefine, the owner's re-trust defines a new
// counter already at 1 or more; interim keys still never count.
func TestReanchorAfterClearStaysRaised(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	box := newInterimBox(t, socketAnchor(r.c))
	if !box.interimCounts(t) {
		t.Fatal("setup: the interim rule did not hold on a fresh store")
	}
	undefineUpdateCounter(t, r)
	box.deleteRecord(t)

	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatalf("re-trust: %v", err)
	}
	if anchored, n, err := r.c.updateAnchorRead(); err != nil || !anchored || n < 1 {
		t.Fatalf("after re-trust = %v, %d, %v; want anchored at 1 or more", anchored, n, err)
	}
	if box.interimCounts(t) {
		t.Fatal("re-anchoring after a clear revived the interim rule")
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("restart after re-trust: phase %v, notes %q", r.phase(), r.notes)
	}
	if box.interimCounts(t) {
		t.Fatal("the re-anchored counter did not survive a restart")
	}
}

// SR3-6f-2b: a first trust on a fresh install does not raise the counter,
// so the interim rule still holds until an outside attestor is listed.
func TestFirstTrustLeavesInterimRule(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatalf("trust again: %v", err)
	}
	box := newInterimBox(t, socketAnchor(r.c))
	if !box.interimCounts(t) {
		t.Fatal("trusting the PC ended the interim rule on a fresh install")
	}
}

// SR3-6f-2b: on a PC with no TPM the answer is "no anchor" (today's
// exposure, shown in STATUS), and while the vault is locked it is 503.
func TestUpdateAnchorWithoutTPM(t *testing.T) {
	r := newFastRig(t, true)
	if code := verifyStatus(r.c, http.MethodGet, update.AnchorPath); code != http.StatusServiceUnavailable {
		t.Fatalf("locked vault: %d, want 503", code)
	}
	r.c.confirm(r.unlock(t), r.code())
	if anchored, _, err := r.c.updateAnchorRead(); err != nil || anchored {
		t.Fatalf("no TPM: read = %v, %v; want not anchored", anchored, err)
	}
	a := socketAnchor(r.c)
	if _, err := a.Read(); !errors.Is(err, update.ErrNoAnchor) {
		t.Fatalf("no TPM: client read = %v, want ErrNoAnchor", err)
	}
	if err := a.Raise(); !errors.Is(err, update.ErrNoAnchor) {
		t.Fatalf("no TPM: client raise = %v, want ErrNoAnchor", err)
	}
}

// SR3-6f-2c: on the verify socket the broker's uid gets read and raise,
// there is no request that lowers the counter, and another uid is closed
// unread.
func TestUpdateAnchorSocket(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(srvs)
	a := update.NewSocketAnchor(filepath.Join(run, VerifySocket))
	if n, err := a.Read(); err != nil || n != 0 {
		t.Fatalf("socket read = %d, %v", n, err)
	}
	if err := a.Raise(); err != nil {
		t.Fatalf("socket raise: %v", err)
	}
	if n, err := a.Read(); err != nil || n != 1 {
		t.Fatalf("socket read after raise = %d, %v", n, err)
	}
	cl := unixClient(filepath.Join(run, VerifySocket))
	for _, req := range [][2]string{
		{http.MethodPost, "/update-anchor/lower"},
		{http.MethodPost, "/update-anchor/reset"},
		{http.MethodDelete, update.AnchorPath},
		{http.MethodPut, update.AnchorPath},
		{http.MethodGet, update.AnchorRaisePath},
	} {
		hr, _ := http.NewRequest(req[0], "http://x"+req[1], nil)
		resp, err := cl.Do(hr)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: %d, want 405", req[0], req[1], resp.StatusCode)
		}
	}
	if n, err := a.Read(); err != nil || n != 1 {
		t.Fatalf("the counter moved after refused requests: %d, %v", n, err)
	}

	other := filepath.Join(t.TempDir(), "run")
	srvs2, err := serve(other, r.c, testRouter(t), nil, nil, os.Getuid()+1, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(srvs2)
	if _, err := update.NewSocketAnchor(filepath.Join(other, VerifySocket)).Read(); err == nil {
		t.Fatal("another uid read the update counter")
	}
	if err := update.NewSocketAnchor(filepath.Join(other, VerifySocket)).Raise(); err == nil {
		t.Fatal("another uid raised the update counter")
	}
}

func closeAll(srvs []*http.Server) {
	for _, s := range srvs {
		s.Close()
	}
}

func countNote(notes []string, note string) int {
	n := 0
	for _, s := range notes {
		if s == note {
			n++
		}
	}
	return n
}

// undefineUpdateCounter removes the update counter's NV index through the
// owner hierarchy, as a TPM clear would.
func undefineUpdateCounter(t *testing.T, r *pcRig) {
	t.Helper()
	if _, _, err := r.c.updateAnchorRaise(); err != nil {
		t.Fatalf("raise before the undefine: %v", err)
	}
	sec, ok := r.c.v.Secret(UpdateAnchorName)
	if !ok {
		t.Fatal("no update counter record")
	}
	var rec updateAnchorRecord
	if err := json.Unmarshal([]byte(sec.Reveal()), &rec); err != nil {
		t.Fatal(err)
	}
	ref, err := tpmseal.ParseCounterRef(rec.Ref)
	if err != nil {
		t.Fatal(err)
	}
	tpm, err := r.tpm.Open()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(ref.Handle), Name: tpm2.TPM2BName{Buffer: ref.Name}},
	}.Execute(tpm)
	tpm.Close()
	if err != nil {
		t.Fatalf("undefine: %v", err)
	}
}

// socketAnchor is the store's client over the real verify handler, with
// no socket (the uid check has its own test).
func socketAnchor(c *custody) *update.SocketAnchor {
	return update.NewAnchorClient(&http.Client{Transport: handlerTransport{verifyHandler(c)}})
}

type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.h.ServeHTTP(w, req)
	return w.Result(), nil
}

func verifyStatus(c *custody, method, path string) int {
	w := httptest.NewRecorder()
	verifyHandler(c).ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w.Code
}

// interimBox is a 2-of-2 release repository with one security release and
// a box store anchored by anchor, whose only attestor is an interim one
// (UPD-8): the box's own key, as before any outside attestor is listed.
type interimBox struct {
	src   update.Source
	store *update.Store
	key   ed25519.PrivateKey
	pub   ed25519.PublicKey
}

func newInterimBox(t *testing.T, anchor update.Anchor) *interimBox {
	t.Helper()
	d := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		return pub, pk
	}
	p1, k1 := key()
	p2, k2 := key()
	sp, sk := key()
	tp, tk := key()
	repo, err := update.Init(filepath.Join(d, "repo"), update.RootConfig{
		Root: []ed25519.PublicKey{p1, p2}, Targets: []ed25519.PublicKey{p1, p2},
		Snapshot: []ed25519.PublicKey{sp}, Timestamp: []ed25519.PublicKey{tp},
		RootThreshold: 2, TargetsThreshold: 2})
	must(err)
	publish := func() {
		for _, k := range []ed25519.PrivateKey{k1, k2} {
			must(repo.Sign("targets", k))
		}
		must(repo.Publish(sk, tk))
	}
	for _, k := range []ed25519.PrivateKey{k1, k2} {
		must(repo.Sign("root", k))
	}
	publish()
	img := filepath.Join(d, "img")
	must(os.WriteFile(img, []byte("synthetic image"), 0o600))
	must(repo.AddRelease(update.Manifest{Version: 2, Channel: update.ChannelStable, Security: true,
		UsrRootHash: strings.Repeat("0f", 32), Files: []string{"host-image/usr.img"}},
		map[string]string{"host-image/usr.img": img}))
	publish()
	root, err := os.ReadFile(filepath.Join(repo.Dir, "metadata", "1.root.json"))
	must(err)
	st, err := update.InitStore(filepath.Join(d, "box"), root, 0)
	must(err)
	st.Anchor = anchor
	pub, pk := key()
	return &interimBox{src: update.DirSource(repo.Dir), store: st, key: pk, pub: pub}
}

// interimCounts reports whether a check with only the interim key, and
// its passing attestation, grants security authority.
func (b *interimBox) interimCounts(t *testing.T) bool {
	t.Helper()
	keys := []ed25519.PublicKey{b.pub}
	res, err := b.store.Check(b.src, update.Options{Attestors: keys, InterimAttestors: keys})
	if err != nil || res.Release == nil {
		return false
	}
	att, err := update.Attest(b.key, res.Release, update.Statement{Result: update.ResultPass, Channel: update.ChannelFast,
		Hardware: attest.Hardware{Vendor: attest.Unlisted, Model: attest.Unlisted, Firmware: attest.Unlisted}})
	if err != nil {
		t.Fatal(err)
	}
	v := res.Release.WithAttestations([][]byte{att}, nil)
	return v.Security() || v.InterimAttestation()
}

func (b *interimBox) listOutside(t *testing.T) {
	t.Helper()
	outside, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.store.NoteAttestors([]ed25519.PublicKey{b.pub, outside}, []ed25519.PublicKey{b.pub}); err != nil {
		t.Fatal(err)
	}
}

// deleteRecord removes the store's sticky outside-attestor record, as root
// on the box could.
func (b *interimBox) deleteRecord(t *testing.T) {
	t.Helper()
	p := filepath.Join(b.store.Dir, "outside_attestor_listed")
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// SR3-6f-2b: the counter's auth never holds a zero byte, which go-tpm cuts
// an auth value at (tpmseal T7); a random 32-byte auth has one about one
// time in eight, and the TPM then refuses to define the counter.
func TestUpdateAnchorAuthHasNoZeroByte(t *testing.T) {
	r := newFastRig(t, true)
	r.c.confirm(r.unlock(t), r.code())
	pc := &authCheckCounter{}
	for i := 0; i < 200; i++ {
		if _, err := defineUpdateAnchor(r.c.v, pc); err != nil {
			t.Fatalf("define %d: %v", i, err)
		}
	}
}

// authCheckCounter refuses an auth as tpmseal.DefineCounter does.
type authCheckCounter struct{}

func (*authCheckCounter) Host() string                        { return "synthetic-host" }
func (*authCheckCounter) Find([]byte) ([]byte, bool, error)   { return nil, true, nil }
func (*authCheckCounter) Read([]byte, []byte) (uint64, error) { return 0, nil }
func (*authCheckCounter) Increment([]byte, []byte) error      { return nil }
func (*authCheckCounter) Define(_, auth []byte) ([]byte, error) {
	if len(auth) == 0 || bytes.IndexByte(auth, 0) >= 0 {
		return nil, errors.New("synthetic: auth with a zero byte")
	}
	return []byte("synthetic-ref"), nil
}
