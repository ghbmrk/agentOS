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
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
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

func (r *rig) run(in journal.Intent) journal.Outcome {
	return r.x.Execute(context.Background(), in, 1)
}

func (r *rig) trusts(root []byte) bool {
	r.t.Helper()
	b, err := r.store.TrustedRoot()
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b) == string(root)
}

// GR26 wiring: the updater follows the root the page holds for the
// approved digest, the switch is the intent's journal outcome, and the
// owner is alerted at once with FollowAlert.
func TestOSS10wFollowsTheHeldRootAndAlerts(t *testing.T) {
	r := newRig(t)
	in := grants.FollowIntent("a1", "Acme Fork", r.describe(r.fork))
	out := r.run(in)
	if out.Result != journal.ResultSucceeded || !r.trusts(r.fork) {
		t.Fatalf("%+v", out)
	}
	if src, err := r.store.Following(); err != nil || src.Name != "Acme Fork" {
		t.Fatalf("following %+v %v", src, err)
	}
	if len(r.alerts) != 1 || r.alerts[0] != maintain.FollowAlert("Acme Fork", r.clk.at) {
		t.Fatalf("alerts %q", r.alerts)
	}
	if out := r.x.Reconcile(context.Background(), in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile %+v", out)
	}
}

// The updater follows only a root the page holds for that digest; any
// other request changes nothing and alerts no one.
func TestOSS10wRefusesARootThePageDoesNotHold(t *testing.T) {
	r := newRig(t)
	r.describe(r.fork)
	for _, in := range []journal.Intent{
		grants.FollowIntent("a1", "Acme", strings.Repeat("ab", 32)),
		{ID: "follow/n2", Action: journal.ActionUpdateFollow},
		{ID: grants.FollowID("a3", strings.Repeat("ab", 32), "Acme"), Action: journal.ActionGrantChange},
	} {
		if out := r.run(in); out.Result != journal.ResultNotApplied {
			t.Fatalf("%s: %+v", in.ID, out)
		}
		if out := r.x.Reconcile(context.Background(), in, 1); out.Result == journal.ResultSucceeded {
			t.Fatalf("%s reconciled as done", in.ID)
		}
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
	if out := r.run(grants.FollowIntent("a1", "", r.describe(r.fork))); out.Result != journal.ResultNotApplied ||
		!strings.Contains(out.Evidence, "project's own root") || !r.trusts(r.shipped) {
		t.Fatalf("a fork's root as the project's: %+v", out)
	}
	fake := forged(t, r.shipped)
	// TUF accepts such a root (key IDs are labels); only the key material
	// tells it from the project's.
	if out := r.run(grants.FollowIntent("a2", "", r.describe(fake))); out.Result != journal.ResultNotApplied ||
		!strings.Contains(out.Evidence, "project's own root") {
		t.Fatalf("a root claiming the shipped key IDs: %+v", out)
	}
	if !r.trusts(r.shipped) || len(r.alerts) != 0 {
		t.Fatal("changed on a refused switch back")
	}
	if out := r.run(grants.FollowIntent("a3", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	if out := r.run(grants.FollowIntent("a4", "", r.describe(r.shipped))); out.Result != journal.ResultSucceeded || !r.trusts(r.shipped) {
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
	out := r.run(grants.FollowIntent("a1", "Acme", d))
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "expired") || r.clk.calls == calls {
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
	out := r.run(grants.FollowIntent("a1", "Acme", r.describe(r.fork)))
	if out.Result != journal.ResultSucceeded || !strings.Contains(out.Evidence, "alert not sent") {
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
	if out := r.run(grants.FollowIntent("a1", "Acme", first)); out.Result != journal.ResultNotApplied {
		t.Fatalf("an evicted root was followed: %+v", out)
	}
}

// The "update" executor serves both release activation and following:
// Route sends each by action.
func TestOSS10wRoute(t *testing.T) {
	r := newRig(t)
	other := &countExec{}
	x := Route(r.x, other)
	x.Execute(context.Background(), journal.Intent{ID: "a", Action: journal.ActionReleaseActivate}, 1)
	if other.n != 1 {
		t.Fatal("release activation not routed to the applier")
	}
	if out := x.Execute(context.Background(), grants.FollowIntent("a1", "Acme", r.describe(r.fork)), 1); out.Result != journal.ResultSucceeded || other.n != 1 {
		t.Fatalf("follow not routed to the follower: %+v", out)
	}
	if out := Route(r.x, nil).Execute(context.Background(), journal.Intent{ID: "b", Action: journal.ActionReleaseActivate}, 1); out.Result != journal.ResultNotApplied {
		t.Fatalf("no applier: %+v", out)
	}
}

type countExec struct{ n int }

func (c *countExec) Execute(context.Context, journal.Intent, int) journal.Outcome {
	c.n++
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func (c *countExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
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

// L3 blocker 1 (GR26 "alerts again, at least once"): Reconcile runs after a
// crash, when nothing is held; it reads the box's own trusted root.
func TestOSS10wReconcileAfterARestart(t *testing.T) {
	r := newRig(t)
	in := grants.FollowIntent("a1", "Acme Fork", r.describe(r.fork))
	if out := r.run(in); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	fresh := r.with(r.store)
	r.alerts = nil
	if out := fresh.Reconcile(context.Background(), in, 2); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile %+v", out)
	}
	if len(r.alerts) != 1 || r.alerts[0] != maintain.FollowAlert("Acme Fork", r.clk.at) {
		t.Fatalf("alerts %q", r.alerts)
	}
	digest, _, _ := grants.FollowOf(in.ID)
	for _, other := range []journal.Intent{
		grants.FollowIntent("a2", "Other Name", digest),
		grants.FollowIntent("a3", "Acme Fork", r.describe(rootOf(t, newKey(t), newKey(t)))),
		grants.FollowIntent("a4", "", r.describe(r.shipped)),
	} {
		r.alerts = nil
		if out := fresh.Reconcile(context.Background(), other, 2); out.Result != journal.ResultUnknown || len(r.alerts) != 0 {
			t.Fatalf("%s: %+v %q", other.ID, out, r.alerts)
		}
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
// unreadable, is Unknown (Reconcile decides), never "not applied"; only a
// failure that left the old root is NotApplied.
func TestOSS10wStoreFailureIsUnknownUnlessTheOldRootStands(t *testing.T) {
	for _, c := range []struct {
		name string
		st   failingStore
		want journal.Result
	}{
		{"root written", failingStore{written: true}, journal.ResultUnknown},
		{"unreadable", failingStore{unreadable: true}, journal.ResultUnknown},
		{"old root stands", failingStore{}, journal.ResultNotApplied},
	} {
		r := newRig(t)
		c.st.Store = r.store
		x := r.with(c.st)
		sum, err := x.Describe(context.Background(), r.fork)
		if err != nil {
			t.Fatal(err)
		}
		in := grants.FollowIntent("a1", "Acme Fork", sum.Digest)
		if out := x.Execute(context.Background(), in, 1); out.Result != c.want || len(r.alerts) != 0 {
			t.Fatalf("%s: %+v %q", c.name, out, r.alerts)
		}
		if c.name == "root written" {
			if out := r.x.Reconcile(context.Background(), in, 2); out.Result != journal.ResultSucceeded || len(r.alerts) != 1 {
				t.Fatalf("reconcile %+v %q", out, r.alerts)
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
	if out := r.run(grants.FollowIntent("a1", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	want := maintain.FollowAlert("Acme", r.clk.at)
	if n := r.x.Note(); !strings.Contains(n, want) || !strings.HasPrefix(n, UnsentPrefix) {
		t.Fatalf("note %q", n)
	}
	if r.x.RetryAlert(ctx) || r.x.Note() == "" {
		t.Fatal("a failed retry cleared the alert")
	}
	if out := r.run(grants.FollowIntent("a2", "Acme Two", r.describe(rootOf(t, newKey(t), newKey(t))))); out.Result != journal.ResultSucceeded {
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
	if out := r.run(grants.FollowIntent("a1", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
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
