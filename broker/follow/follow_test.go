package follow

// REQ: OSS-10, OSS-9, CH-3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/maintain"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Synthetic keys only: every key is generated per test.
func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubs(ks ...ed25519.PrivateKey) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, k := range ks {
		out = append(out, k.Public().(ed25519.PublicKey))
	}
	return out
}

// rootOf is a fresh 2-of-2 repository's first root, signed by its two
// root keys.
func rootOf(t *testing.T, r1, r2 ed25519.PrivateKey) []byte {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo")
	repo, err := update.Init(dir, update.RootConfig{Root: pubs(r1, r2), Targets: pubs(r1, r2),
		Snapshot: pubs(newKey(t)), Timestamp: pubs(newKey(t)), RootThreshold: 2, TargetsThreshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []ed25519.PrivateKey{r1, r2} {
		if err := repo.Sign("root", k); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "staged", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// forged is a root that lists shipped's root-role key IDs but maps them
// to other key material, signed by that material under those IDs.
func forged(t *testing.T, shipped []byte) []byte {
	t.Helper()
	m, err := metadata.Root().FromBytes(shipped)
	if err != nil {
		t.Fatal(err)
	}
	m.Signatures = nil
	m.Signed.Version = 2
	ids := m.Signed.Roles[metadata.ROOT].KeyIDs
	var ks []ed25519.PrivateKey
	for _, id := range ids {
		k := newKey(t)
		key, err := metadata.KeyFromPublicKey(k.Public())
		if err != nil {
			t.Fatal(err)
		}
		m.Signed.Keys[id] = key
		ks = append(ks, k)
	}
	// Sign with the new material, then file each signature under the
	// shipped ID: the signature covers only the signed part.
	for i, k := range ks {
		sig, err := m.Sign(signerOf(k))
		if err != nil {
			t.Fatal(err)
		}
		sig.KeyID = ids[i]
		m.Signatures[len(m.Signatures)-1] = *sig
	}
	out, err := m.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type fakeClock struct {
	at    time.Time
	calls int
}

func (c *fakeClock) Latest(context.Context) (time.Time, clock.Status) {
	c.calls++
	return c.at, clock.Status{State: clock.Agreed}
}

type rig struct {
	t       *testing.T
	shipped []byte
	// pk are the shipped root's root keys.
	pk      []ed25519.PrivateKey
	fork    []byte
	store   *update.Store
	clk     *fakeClock
	alerts  []string
	pending string
	x       *Executor
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, clk: &fakeClock{at: time.Now().Add(time.Hour)}}
	r.pk = []ed25519.PrivateKey{newKey(t), newKey(t)}
	r.shipped = rootOf(t, r.pk[0], r.pk[1])
	r.fork = rootOf(t, newKey(t), newKey(t))
	st, err := update.InitStore(filepath.Join(t.TempDir(), "box"), r.shipped, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.store = st
	r.pending = filepath.Join(st.Dir, "follow-alert")
	x, err := New(Config{Store: st, Shipped: r.shipped, Clock: r.clk, Pending: r.pending,
		Alert: func(_ context.Context, text string) error { r.alerts = append(r.alerts, text); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	r.x = x
	return r
}

func (r *rig) describe(root []byte) string {
	r.t.Helper()
	sum, err := r.x.Describe(context.Background(), root)
	if err != nil {
		r.t.Fatal(err)
	}
	return sum.Digest
}

// request is what the follow clerk's step asks for: the root's digest and
// the owner's name for it, "" for the project's own root.
type request struct{ name, digest string }

// req is a request; id names the case only.
func req(_, name, digest string) request { return request{name, digest} }

// outcome is a switch's result and evidence.
type outcome struct {
	Result   Switched
	Evidence string
}

func run(x *Executor, q request) outcome {
	s, ev := x.Switch(context.Background(), q.digest, q.name)
	return outcome{s, ev}
}

func (r *rig) run(q request) outcome { return run(r.x, q) }

// settled is what the box's own trusted root says of q (Executor.Settled).
func settled(x *Executor, q request) outcome {
	s, ev := x.Settled(q.digest, q.name)
	return outcome{s, ev}
}

func (r *rig) settled(q request) outcome { return settled(r.x, q) }

func (r *rig) trusts(root []byte) bool {
	r.t.Helper()
	b, err := r.store.TrustedRoot()
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b) == string(root)
}

// GR26 wiring: the updater follows the root the page holds for the
// approved digest, the switch is the step's outcome, and the
// owner is alerted at once with FollowAlert.
func TestOSS10wFollowsTheHeldRootAndAlerts(t *testing.T) {
	r := newRig(t)
	in := req("a1", "Acme Fork", r.describe(r.fork))
	out := r.run(in)
	if out.Result != SwitchedOK || !r.trusts(r.fork) {
		t.Fatalf("%+v", out)
	}
	if src, err := r.store.Following(); err != nil || src.Name != "Acme Fork" {
		t.Fatalf("following %+v %v", src, err)
	}
	if len(r.alerts) != 1 || r.alerts[0] != maintain.FollowAlert("Acme Fork", r.clk.at) {
		t.Fatalf("alerts %q", r.alerts)
	}
	if out := r.settled(in); out.Result != SwitchedOK {
		t.Fatalf("settled %+v", out)
	}
}

// The updater follows only a root the page holds for that digest; any
// other request changes nothing and alerts no one.
func TestOSS10wRefusesARootThePageDoesNotHold(t *testing.T) {
	r := newRig(t)
	r.describe(r.fork)
	in := req("a1", "Acme", strings.Repeat("ab", 32))
	if out := r.run(in); out.Result != NotSwitched {
		t.Fatalf("%+v", out)
	}
	if out := r.settled(in); out.Result == SwitchedOK {
		t.Fatal("settled as done")
	}
	if !r.trusts(r.shipped) || len(r.alerts) != 0 {
		t.Fatalf("changed: alerts %q", r.alerts)
	}
	if _, err := r.x.Describe(context.Background(), []byte("{}")); err == nil {
		t.Fatal("described a malformed root")
	}
}

// WF1: an empty name (switching back) is admitted only for a root whose
// root-role keys are the shipped root's, compared by key material, not
// by the IDs a root may claim.
func TestOSS10wSwitchingBackNeedsTheShippedRootKeys(t *testing.T) {
	r := newRig(t)
	if out := r.run(req("a1", "", r.describe(r.fork))); out.Result != NotSwitched ||
		!strings.Contains(out.Evidence, "project's own root") || !r.trusts(r.shipped) {
		t.Fatalf("a fork's root as the project's: %+v", out)
	}
	fake := forged(t, r.shipped)
	// TUF accepts such a root (key IDs are labels); only the key material
	// tells it from the project's.
	if out := r.run(req("a2", "", r.describe(fake))); out.Result != NotSwitched ||
		!strings.Contains(out.Evidence, "project's own root") {
		t.Fatalf("a root claiming the shipped key IDs: %+v", out)
	}
	if !r.trusts(r.shipped) || len(r.alerts) != 0 {
		t.Fatal("changed on a refused switch back")
	}
	if out := r.run(req("a3", "Acme", r.describe(r.fork))); out.Result != SwitchedOK {
		t.Fatalf("%+v", out)
	}
	if out := r.run(req("a4", "", r.describe(r.shipped))); out.Result != SwitchedOK || !r.trusts(r.shipped) {
		t.Fatalf("switching back: %+v", out)
	}
	if src, _ := r.store.Following(); src != (update.Followed{}) {
		t.Fatalf("still following %+v", src)
	}
	if len(r.alerts) != 2 || r.alerts[1] != maintain.FollowAlert(ProjectName, r.clk.at) {
		t.Fatalf("alerts %q", r.alerts)
	}
}

// WF1 at describe time (UX lens): the page offers switching back only for
// a root Execute would admit it for, judged the same way.
func TestOSS10w2ProjectIsKnownAtDescribe(t *testing.T) {
	r := newRig(t)
	if !r.x.Project(context.Background(), r.describe(r.shipped)) {
		t.Fatal("the shipped root is not the project's")
	}
	if r.x.Project(context.Background(), r.describe(r.fork)) || r.x.Project(context.Background(), r.describe(forged(t, r.shipped))) {
		t.Fatal("a fork's root, or one claiming the shipped key IDs, read as the project's")
	}
	if r.x.Project(context.Background(), strings.Repeat("ab", 32)) {
		t.Fatal("a root not held read as the project's")
	}
}

// WF2: expiry is judged by the clock guard's Latest, never the wall
// clock: a root valid by the wall clock but expired by Latest is refused.
func TestOSS10wClockFromLatest(t *testing.T) {
	r := newRig(t)
	d := r.describe(r.fork)
	r.clk.at = time.Now().Add(update.RootExpiry + 24*time.Hour)
	calls := r.clk.calls
	out := r.run(req("a1", "Acme", d))
	if out.Result != NotSwitched || !strings.Contains(out.Evidence, "expired") || r.clk.calls == calls {
		t.Fatalf("followed a root expired by Latest: %+v", out)
	}
	if _, err := r.x.Describe(context.Background(), r.fork); err == nil {
		t.Fatal("described a root expired by Latest")
	}
	if !r.trusts(r.shipped) || len(r.alerts) != 0 {
		t.Fatal("changed")
	}
}

// Fail closed: without a store, the shipped root, the clock guard or the
// alert, there is no executor.
func TestOSS10wNeedsEveryPiece(t *testing.T) {
	r := newRig(t)
	alert := func(context.Context, string) error { return nil }
	for i, c := range []Config{
		{Shipped: r.shipped, Clock: r.clk, Alert: alert},
		{Store: r.store, Clock: r.clk, Alert: alert},
		{Store: r.store, Shipped: r.shipped, Alert: alert},
		{Store: r.store, Shipped: r.shipped, Clock: r.clk},
		{Store: r.store, Shipped: []byte("{}"), Clock: r.clk, Alert: alert},
	} {
		if _, err := New(c); err == nil {
			t.Fatalf("case %d made an executor", i)
		}
	}
}

// A failed alert does not undo the switch; the outcome says it was not
// sent.
func TestOSS10wAlertFailureIsRecorded(t *testing.T) {
	r := newRig(t)
	r.x.cfg.Alert = func(context.Context, string) error { return errors.New("no line") }
	out := r.run(req("a1", "Acme", r.describe(r.fork)))
	if out.Result != SwitchedOK || !strings.Contains(out.Evidence, "alert not sent") {
		t.Fatalf("%+v", out)
	}
}

// The page holds at most MaxHeld roots; the oldest goes first.
func TestOSS10wHeldIsBounded(t *testing.T) {
	r := newRig(t)
	first := r.describe(r.fork)
	for i := 0; i < MaxHeld; i++ {
		r.describe(rootOf(t, newKey(t), newKey(t)))
	}
	if out := r.run(req("a1", "Acme", first)); out.Result != NotSwitched {
		t.Fatalf("an evicted root was followed: %+v", out)
	}
}

func signerOf(k ed25519.PrivateKey) signature.Signer {
	s, err := signature.LoadED25519Signer(k)
	if err != nil {
		panic(err)
	}
	return s
}

// with is an executor over st sharing the rig's clock and alerts: a daemon
// restarted over the same store holds nothing the old one described.
func (r *rig) with(st Store) *Executor {
	r.t.Helper()
	x, err := New(Config{Store: st, Shipped: r.shipped, Clock: r.clk, Pending: r.pending,
		Alert: func(_ context.Context, text string) error { r.alerts = append(r.alerts, text); return nil }})
	if err != nil {
		r.t.Fatal(err)
	}
	return x
}

// L3 blocker 1 (GR26 "alerts again, at least once"): Settled runs after a
// crash, when nothing is held; it reads the box's own trusted root, and
// Realert sends the alert again (the follow clerk's Probe).
func TestOSS10wSettledAfterARestart(t *testing.T) {
	r := newRig(t)
	in := req("a1", "Acme Fork", r.describe(r.fork))
	if out := r.run(in); out.Result != SwitchedOK {
		t.Fatalf("%+v", out)
	}
	fresh := r.with(r.store)
	r.alerts = nil
	if out := settled(fresh, in); out.Result != SwitchedOK {
		t.Fatalf("settled %+v", out)
	}
	fresh.Realert(context.Background(), in.name)
	if len(r.alerts) != 1 || r.alerts[0] != maintain.FollowAlert("Acme Fork", r.clk.at) {
		t.Fatalf("alerts %q", r.alerts)
	}
	digest := in.digest
	for _, other := range []struct {
		in   request
		want Switched
	}{
		// The same root under another name, or another root under the
		// same name (the root may have rotated since): unknown.
		{req("a2", "Other Name", digest), SwitchedUnknown},
		{req("a3", "Acme Fork", r.describe(rootOf(t, newKey(t), newKey(t)))), SwitchedUnknown},
		// Neither the root nor the source: the switch back never landed.
		{req("a4", "", r.describe(r.shipped)), NotSwitched},
	} {
		r.alerts = nil
		if out := settled(fresh, other.in); out.Result != other.want || len(r.alerts) != 0 {
			t.Fatalf("%+v: %+v %q", other.in, out, r.alerts)
		}
	}
}

// REQ: OP-4, G1
// #1372 (L3/UX R1 on #1325): power pulled before the switch was written
// leaves the old root and the old source. Settled answers not switched;
// nothing runs and the owner is not alerted. A re-run finds nothing held
// (the held root lives in memory) and does not switch either.
func TestOSS10wSettledBeforeTheSwitchIsNotSwitched(t *testing.T) {
	r := newRig(t)
	in := req("a1", "Acme Fork", r.describe(r.fork))
	fresh := r.with(r.store)
	out := settled(fresh, in)
	if out.Result != NotSwitched || len(r.alerts) != 0 || !r.trusts(r.shipped) {
		t.Fatalf("settled %+v %q", out, r.alerts)
	}
	if src, _ := r.store.Following(); src != (update.Followed{}) {
		t.Fatalf("source %+v", src)
	}
	if out := run(fresh, in); out.Result != NotSwitched || !r.trusts(r.shipped) || len(r.alerts) != 0 {
		t.Fatalf("re-dispatch %+v", out)
	}
}

// failingStore fails FollowFork after (written) or instead of the real
// switch, and can fail reading the trusted root.
type failingStore struct {
	*update.Store
	written, unreadable bool
}

func (s failingStore) FollowFork(root []byte, links [][]byte, shipped []byte, approved, name string, o update.Options) error {
	if s.written {
		if err := s.Store.FollowFork(root, links, shipped, approved, name, o); err != nil {
			return err
		}
	}
	return errors.New("synthetic store failure")
}

func (s failingStore) TrustedRoot() ([]byte, error) {
	if s.unreadable {
		return nil, errors.New("synthetic read failure")
	}
	return s.Store.TrustedRoot()
}

// L3 blocker 2: a store failure with the root in place, or with the store
// unreadable, is Unknown (Settled decides), never NotSwitched; only a
// failure that left the old root is NotSwitched.
func TestOSS10wStoreFailureIsUnknownUnlessTheOldRootStands(t *testing.T) {
	for _, c := range []struct {
		name string
		st   failingStore
		want Switched
	}{
		{"root written", failingStore{written: true}, SwitchedUnknown},
		{"unreadable", failingStore{unreadable: true}, SwitchedUnknown},
		{"old root stands", failingStore{}, NotSwitched},
	} {
		r := newRig(t)
		c.st.Store = r.store
		x := r.with(c.st)
		sum, err := x.Describe(context.Background(), r.fork)
		if err != nil {
			t.Fatal(err)
		}
		in := req("a1", "Acme Fork", sum.Digest)
		if out := run(x, in); out.Result != c.want || len(r.alerts) != 0 {
			t.Fatalf("%s: %+v %q", c.name, out, r.alerts)
		}
		if c.name == "root written" {
			if out := r.settled(in); out.Result != SwitchedOK || len(r.alerts) != 0 {
				t.Fatalf("settled %+v %q", out, r.alerts)
			}
		}
	}
}

// OSS-10w L3 (GR26): an alert that could not be sent is held, retried
// until it goes out, and shown on STATUS meanwhile, so the owner learns of
// the switch even when the line was down at the time. A later switch's
// alert replaces it: it says where updates come from now.
func TestOSS10w2UnsentAlertIsRetriedAndShown(t *testing.T) {
	r := newRig(t)
	down := true
	r.x.cfg.Alert = func(_ context.Context, text string) error {
		if down {
			return errors.New("no line")
		}
		r.alerts = append(r.alerts, text)
		return nil
	}
	ctx := context.Background()
	if r.x.Note() != "" || r.x.RetryAlert(ctx) {
		t.Fatal("a note or a retry with nothing unsent")
	}
	if out := r.run(req("a1", "Acme", r.describe(r.fork))); out.Result != SwitchedOK {
		t.Fatalf("%+v", out)
	}
	want := maintain.FollowAlert("Acme", r.clk.at)
	if n := r.x.Note(); !strings.Contains(n, want) || !strings.HasPrefix(n, UnsentPrefix) {
		t.Fatalf("note %q", n)
	}
	if r.x.RetryAlert(ctx) || r.x.Note() == "" {
		t.Fatal("a failed retry cleared the alert")
	}
	if out := r.run(req("a2", "Acme Two", r.describe(rootOf(t, newKey(t), newKey(t))))); out.Result != SwitchedOK {
		t.Fatalf("%+v", out)
	}
	down = false
	if !r.x.RetryAlert(ctx) || len(r.alerts) != 1 || r.alerts[0] != maintain.FollowAlert("Acme Two", r.clk.at) {
		t.Fatalf("retry sent %q", r.alerts)
	}
	if r.x.Note() != "" || r.x.RetryAlert(ctx) || len(r.alerts) != 1 {
		t.Fatalf("still pending after delivery: %q", r.alerts)
	}
}

// OSS-10w2 L3 blocker: an alert queued but not yet sent survives a
// restart. The executor run after it reports it on STATUS and its retry
// delivers it exactly once; once sent, no later run owes it.
func TestOSS10w2UnsentAlertSurvivesARestart(t *testing.T) {
	r := newRig(t)
	r.x.cfg.Alert = func(context.Context, string) error { return errors.New("no line") }
	if out := r.run(req("a1", "Acme", r.describe(r.fork))); out.Result != SwitchedOK {
		t.Fatalf("%+v", out)
	}
	want := maintain.FollowAlert("Acme", r.clk.at)

	// Restart: a new executor over the same store and pending file.
	x := r.with(r.store)
	if n := x.Note(); n != UnsentPrefix+want {
		t.Fatalf("note after restart %q", n)
	}
	ctx := context.Background()
	if !x.RetryAlert(ctx) || len(r.alerts) != 1 || r.alerts[0] != want {
		t.Fatalf("retry after restart sent %q", r.alerts)
	}
	if x.Note() != "" || x.RetryAlert(ctx) {
		t.Fatal("still pending after delivery")
	}
	if x := r.with(r.store); x.Note() != "" || x.RetryAlert(ctx) || len(r.alerts) != 1 {
		t.Fatalf("owed again after a second restart: %q", r.alerts)
	}
}

// The pending file is part of the executor: without it, or with one that
// cannot be read, there is no executor (fails closed, not memory-only).
func TestOSS10w2PendingIsRequired(t *testing.T) {
	r := newRig(t)
	c := r.x.cfg
	c.Pending = ""
	if _, err := New(c); err == nil {
		t.Fatal("an executor without a pending file")
	}
	c.Pending = t.TempDir() // a directory cannot be read as the file
	if _, err := New(c); err == nil {
		t.Fatal("an executor over an unreadable pending file")
	}
}
