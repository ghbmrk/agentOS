package main

// REQ: OSS-10, CH-3, UPD-8, CH-10, KRN-4, OWN-4

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/follow/followclerk"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/update"
)

// Synthetic keys only: generated per test.
func followRoot(t *testing.T) []byte {
	t.Helper()
	key := func() ed25519.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	var signers []ed25519.PrivateKey
	var root []ed25519.PublicKey
	for i := 0; i < 2; i++ {
		pub, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signers, root = append(signers, k), append(root, pub)
	}
	dir := filepath.Join(t.TempDir(), "repo")
	repo, err := update.Init(dir, update.RootConfig{Root: root, Targets: root,
		Snapshot: []ed25519.PublicKey{key()}, Timestamp: []ed25519.PublicKey{key()}, RootThreshold: 2, TargetsThreshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range signers {
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

func noGuard() *clock.Guard { return nil }

// Following is off unless both the store and the shipped root are named,
// and the store must already trust a root: agentosd never initialises it.
func TestOSS10w2FollowSettingFlags(t *testing.T) {
	if s, err := newFollowSetting("", "", noGuard); s != nil || err != nil {
		t.Fatalf("off: %v %v", s, err)
	}
	shipped := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(shipped, followRoot(t), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{t.TempDir(), ""}, {"", shipped}, {t.TempDir(), shipped}, {t.TempDir(), shipped + ".missing"}} {
		if s, err := newFollowSetting(c[0], c[1], noGuard); s != nil || err == nil {
			t.Fatalf("%q: no error", c)
		}
	}
	b, _ := os.ReadFile(shipped)
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	s, err := newFollowSetting(dir, shipped, noGuard)
	if err != nil || s == nil {
		t.Fatalf("%v", err)
	}

	// Wired only with the page served.
	var cfg daemon.Config
	if s.wire(&cfg) || cfg.KernelRetryLines != nil || len(cfg.Notes) != 0 {
		t.Fatal("wired without the page")
	}
	cfg.PageSocket = &daemon.PageSocket{UID: 1000}
	if !s.wire(&cfg) || cfg.PageSocket.DescribeRoot == nil || cfg.KernelRetryLines[followclerk.Name] == nil || len(cfg.Notes) != 1 ||
		cfg.BrokerExecutors[grants.FollowExecutor] != nil {
		t.Fatalf("not wired: %+v", cfg)
	}
	if (*followSetting)(nil).wire(&cfg) {
		t.Fatal("nil setting wired")
	}

	// Before the clock guard runs, nothing is described.
	if sum, err := cfg.PageSocket.DescribeRoot(context.Background(), b, nil); err == nil || sum.Digest != "" || sum.Reason != "" {
		t.Fatalf("described without a clock guard: %+v %v", sum, err)
	}
	// With no owner channel the alert fails and is held (STATUS shows it).
	if err := s.alert(context.Background(), "x"); err == nil {
		t.Fatal("alert without a channel")
	}
}

// An unchecked clock reads as the far future, so every root is expired.
func TestOSS10w2GuardClockFailsClosed(t *testing.T) {
	now, st := guardClock{noGuard}.Latest(context.Background())
	if now.Before(time.Now().AddDate(1000, 0, 0)) || st.State != clock.Unchecked {
		t.Fatalf("%v %+v", now, st)
	}
}

// OSS-10w L3 decision: the page names only a coarse cause, never the
// verifier's text, and copies a verified summary.
func TestOSS10w2PageSummaryReason(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: root v3 expired 2026-01-01", update.ErrExpired), localapi.RootExpired},
		{fmt.Errorf("%w: 1 of 2", update.ErrSignatures), localapi.RootSignatures},
		{fmt.Errorf("%w: root 1 < 2", update.ErrWeakThreshold), localapi.RootThreshold},
		{errors.New("unexpected end of JSON input"), ""},
	} {
		sum, err := pageSummary(update.RootSummary{Version: 3, Digest: "d"}, c.err)
		if err == nil || sum.Reason != c.want || sum.Digest != "" || sum.Version != 0 {
			t.Fatalf("%v: %+v %v", c.err, sum, err)
		}
	}
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	sum, err := pageSummary(update.RootSummary{Version: 3, Keys: map[string][]string{"root": {"k1", "k2"}}, Thresholds: map[string]int{"root": 2}, Expires: exp, Digest: "d"}, nil)
	if err != nil || sum.Version != 3 || len(sum.Keys["root"]) != 2 || sum.Thresholds["root"] != 2 || !sum.Expires.Equal(exp) || sum.Digest != "d" || sum.Reason != "" {
		t.Fatalf("%+v %v", sum, err)
	}
}

// OSS-10w2 L3 blocker: the executor's pending alert lives in the update
// store dir, so an alert a previous run left unsent shows on STATUS after
// a restart.
func TestOSS10w2PendingAlertSurvivesARestart(t *testing.T) {
	shipped := filepath.Join(t.TempDir(), "root.json")
	b := followRoot(t)
	if err := os.WriteFile(shipped, b, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pendingAlert), []byte("switched"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newFollowSetting(dir, shipped, noGuard)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.x.Note(); n != follow.UnsentPrefix+"switched" {
		t.Fatalf("note %q", n)
	}
}

// L3 R2 (WF1 wiring): describe reports Project from the executor's check,
// true for the shipped root and false for any other.
func TestOSS10w2DescribeProject(t *testing.T) {
	shipped := filepath.Join(t.TempDir(), "root.json")
	b := followRoot(t)
	if err := os.WriteFile(shipped, b, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g, err := clock.New(clock.Config{
		Synced:  func() (bool, error) { return true, nil },
		Carrier: func(context.Context) (time.Time, error) { return now, nil },
		Now:     func() time.Time { return now },
		Elapsed: func() time.Duration { return time.Hour },
		BootID:  func() string { return "boot" },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Check(context.Background())
	s, err := newFollowSetting(dir, shipped, func() *clock.Guard { return g })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if sum, err := s.describe(ctx, b, nil); err != nil || !sum.Project {
		t.Fatalf("shipped root: %+v %v", sum, err)
	}
	if sum, err := s.describe(ctx, followRoot(t), nil); err != nil || sum.Project || sum.Digest == "" {
		t.Fatalf("fork root: %+v %v", sum, err)
	}
}

// OSS-10w-r: the page's bound on brought root files is the updater's, and
// describe hands the executor the chain (one over the bound is refused).
func TestOSS10wrDescribePassesTheChain(t *testing.T) {
	if localapi.MaxRootChain != update.MaxRootRotations {
		t.Fatalf("page bound %d, updater bound %d", localapi.MaxRootChain, update.MaxRootRotations)
	}
	shipped := filepath.Join(t.TempDir(), "root.json")
	b := followRoot(t)
	if err := os.WriteFile(shipped, b, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g, err := clock.New(clock.Config{
		Synced:  func() (bool, error) { return true, nil },
		Carrier: func(context.Context) (time.Time, error) { return now, nil },
		Now:     func() time.Time { return now },
		Elapsed: func() time.Duration { return time.Hour },
		BootID:  func() string { return "boot" },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Check(context.Background())
	s, err := newFollowSetting(dir, shipped, func() *clock.Guard { return g })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.describe(context.Background(), b, make([][]byte, update.MaxRootRotations+1)); err == nil {
		t.Fatal("a chain over the bound reached no check")
	}
	if sum, err := s.describe(context.Background(), b, [][]byte{b}); err != nil || !sum.Project {
		t.Fatalf("%+v %v", sum, err)
	}
}

// seedPair is seedKey's key with its public half.
func seedPair(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	p := seedKey(seed)
	return pubOf(p), p
}

// clerkRig is agentosd's follow setting hosting the follow clerk on a
// socket, and a kernel in this process calling it there as it calls any
// clerk process (proc.Remote), with the owner's bare root for
// change-account on the follow clerk and an enrolled phone passkey. The
// owner's anchors are in a file only this uid writes.
type clerkRig struct {
	t       *testing.T
	s       *followSetting
	store   *update.Store
	shipped []byte
	fork    []byte
	alerts  []string
	sock    string
	anchors []key.PublicKey
	k       *kernel.Kernel
	mem     *kernel.MemStore
	anc     *kernel.MemAnchor
	root    key.Key
	phone   ed25519.PrivateKey
	at      int64 // when the root was granted
}

func newClerkRig(t *testing.T) *clerkRig {
	t.Helper()
	r := &clerkRig{t: t, mem: &kernel.MemStore{}, anc: &kernel.MemAnchor{}}
	dir, err := os.MkdirTemp("", "fc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.shipped, r.fork = followRoot(t), followRoot(t)
	shipped := filepath.Join(dir, "root.json")
	if err := os.WriteFile(shipped, r.shipped, 0o600); err != nil {
		t.Fatal(err)
	}
	if r.store, err = update.InitStore(filepath.Join(dir, "box"), r.shipped, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g, err := clock.New(clock.Config{
		Synced:  func() (bool, error) { return true, nil },
		Carrier: func(context.Context) (time.Time, error) { return now, nil },
		Now:     func() time.Time { return now },
		Elapsed: func() time.Duration { return time.Hour },
		BootID:  func() string { return "boot" },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Check(context.Background())
	if r.s, err = newFollowSetting(r.store.Dir, shipped, func() *clock.Guard { return g }); err != nil {
		t.Fatal(err)
	}
	r.s.post = func(text string) error { r.alerts = append(r.alerts, text); return nil }
	opub, opriv := seedPair(1)
	bpub, bpriv := seedPair(12)
	r.anchors = []key.PublicKey{key.Ed25519(opub), key.Ed25519(bpub)}
	b, err := handoff.EncodeAnchors(r.anchors)
	if err != nil {
		t.Fatal(err)
	}
	anchors := filepath.Join(dir, "anchors")
	if err := os.WriteFile(anchors, b, 0o600); err != nil {
		t.Fatal(err)
	}
	r.sock = filepath.Join(dir, "follow.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := r.s.serveClerk(ctx, r.sock, anchors, os.Getuid(), os.Getuid(), t.Logf); err != nil {
		t.Fatal(err)
	}
	r.boot(proc.Remote{Socket: r.sock, UID: os.Getuid(), Timeout: 10 * time.Second})
	// Granted a minute past the hold before the guard clock's reading,
	// which is the clerk's own time (Latest).
	at := now.UnixMilli() - kernel.GrantHold - time.Minute.Milliseconds()
	r.at = at
	r.root = key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: followclerk.Name, Verbs: []key.Verb{key.ChangeAccount}, Serial: "r1"})
	batch := []key.Key{r.root}
	if err := r.k.Issue(at, []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	phonePub, phone := seedPair(8)
	if err := r.k.Enroll(at, key.Enroll(key.Ed25519Signer(opriv), key.Ed25519(phonePub))); err != nil {
		t.Fatal(err)
	}
	r.phone = phone
	return r
}

func (r *clerkRig) now() int64 { return time.Now().UnixMilli() }

// boot (re)starts the kernel over the rig's log, reaching the follow
// clerk through rm.
func (r *clerkRig) boot(rm proc.Remote) {
	r.t.Helper()
	kpub, kpriv := seedPair(3)
	l, err := kernel.Open(kernel.Config{Store: r.mem, Anchor: r.anc, Pub: kpub, Sign: kpriv, Rand: mrand.NewChaCha8([32]byte{1})})
	if err != nil {
		r.t.Fatal(err)
	}
	if r.k, err = kernel.Boot(l, r.anchors, map[string]kernel.Clerk{followclerk.Name: rm.Clerk(r.anchors)}, r.now()); err != nil {
		r.t.Fatal(err)
	}
}

// describe is the page showing root to the owner.
func (r *clerkRig) describe(root []byte) string {
	r.t.Helper()
	sum, err := r.s.describe(context.Background(), root, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	return sum.Digest
}

// approved is the owner's tap: the phone passkey signs the plan of this
// one switch under the bare root (CH-10's tier 4).
func (r *clerkRig) approved(id, digest, name string) kernel.Plan {
	return kernel.SignPlan(kernel.Plan{ID: id, Key: r.root, Steps: []kernel.PlanStep{followclerk.Step(digest, name)}}, r.phone)
}

// run submits p and ticks; a plan the kernel did not admit is an error.
func (r *clerkRig) run(p kernel.Plan) (kernel.StepState, error) {
	r.t.Helper()
	if err := r.k.Submit(r.now(), p); err != nil {
		return kernel.StepState{}, err
	}
	if err := r.k.Tick(r.now()); err != nil {
		r.t.Fatal(err)
	}
	ps, ok := r.k.State().Plans[p.ID]
	if !ok || len(ps.Steps) == 0 {
		return kernel.StepState{}, errors.New("not admitted")
	}
	return ps.Steps[0], nil
}

func (r *clerkRig) trusts(root []byte) bool {
	r.t.Helper()
	b, err := r.store.TrustedRoot()
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b) == string(root)
}

// CH-10, KRN-4, OWN-4 (#3430 acceptance): the owner's approval of a root
// the page showed reaches the kernel as their own plan, the kernel calls
// agentosd's follow clerk on its socket, the box follows that root under
// the owner's name, and the owner is alerted at once. The switch runs
// once: the step is done, and a kernel restarted over the same log runs
// nothing again.
func TestOwnerApprovedFollowRunsOnce(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	st, err := r.run(r.approved("p1", d, "Acme Fork"))
	if err != nil || st.Phase != kernel.PDone || !r.trusts(r.fork) {
		t.Fatalf("%+v %v", st, err)
	}
	if src, err := r.store.Following(); err != nil || src.Name != "Acme Fork" {
		t.Fatalf("following %+v %v", src, err)
	}
	if len(r.alerts) != 1 || !strings.Contains(r.alerts[0], "Acme Fork") {
		t.Fatalf("alerts %q", r.alerts)
	}
	r.boot(proc.Remote{Socket: r.sock, UID: os.Getuid(), Timeout: 10 * time.Second})
	if err := r.k.Tick(r.now()); err != nil {
		t.Fatal(err)
	}
	if st := r.k.State().Plans["p1"].Steps[0]; st.Phase != kernel.PDone || len(r.alerts) != 1 {
		t.Fatalf("after a restart: %+v, alerts %q", st, r.alerts)
	}
	// The page's RETRY line reads the switch from the box.
	if obj, detail := r.s.retryLine(); obj != "updates, now from Acme Fork" || !strings.HasPrefix(detail, "root "+d[:12]) || !strings.HasSuffix(detail, "RETRY replaces it") {
		t.Fatalf("retry line %q, %q", obj, detail)
	}
}

// CH-10, KRN-4 (#3430 acceptance): a follow without the owner's tier-4
// approval changes nothing. A plan the owner's passkey did not sign is
// refused by the kernel, and one under a standing clerk key the owner
// granted is refused by the clerk: a switch of update source is the
// owner's own approval of that switch, never a standing key's.
func TestUnapprovedFollowRefused(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	unchanged := func(what string) {
		t.Helper()
		if !r.trusts(r.shipped) || len(r.alerts) != 0 {
			t.Fatalf("%s: switched or alerted: %q", what, r.alerts)
		}
		if src, _ := r.store.Following(); src != (update.Followed{}) {
			t.Fatalf("%s: source %+v", what, src)
		}
	}
	forged := r.approved("forged", d, "Acme")
	forged.Steps[0].Args[followclerk.ArgName] = "Other"
	if st, err := r.run(forged); err == nil && st.Phase == kernel.PDone {
		t.Fatalf("an edited plan ran: %+v", st)
	}
	_, stranger := seedPair(9)
	if st, err := r.run(kernel.SignPlan(kernel.Plan{ID: "stranger", Key: r.root, Steps: []kernel.PlanStep{followclerk.Step(d, "Acme")}}, stranger)); err == nil && st.Phase == kernel.PDone {
		t.Fatalf("a stranger's plan ran: %+v", st)
	}
	unchanged("unsigned")
	hpub, hpriv := seedPair(2)
	_, opriv := seedPair(1)
	_, bpriv := seedPair(12)
	ck, err := key.ClerkKey(r.root, key.Ed25519Signer(opriv), hpub, r.at, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	batch := []key.Key{ck}
	if err := r.k.Issue(r.at, []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	st, err := r.run(kernel.SignPlan(kernel.Plan{ID: "standing", Key: ck, Steps: []kernel.PlanStep{followclerk.Step(d, "Acme")}}, hpriv))
	if err != nil || st.Phase != kernel.PFailed || st.Detail != followclerk.ROwner {
		t.Fatalf("standing key: %+v %v", st, err)
	}
	unchanged("standing key")
}

// #3444's carried review point: the kernel sends an unsent step again
// without asking the owner, so the transport to the follow clerk answers
// unsent only when the call provably never reached it. No socket, and a
// socket served by a uid other than the clerk's, are unsent and change
// nothing; a clerk that took the call and lost its answer is unknown,
// never unsent.
func TestFollowClerkUnsentOnlyWhenNothingLeft(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	p := r.approved("p1", d, "Acme Fork")
	req := kernel.Request{Plan: p}
	for _, c := range []struct {
		name string
		rm   proc.Remote
	}{
		{"no socket", proc.Remote{Socket: r.sock + ".missing", UID: os.Getuid(), Timeout: time.Second}},
		{"another uid", proc.Remote{Socket: r.sock, UID: os.Getuid() + 1, Timeout: time.Second}},
	} {
		if res := c.rm.Clerk(r.anchors).Do(req, r.k.State()); res.Outcome != kernel.OUnsent {
			t.Fatalf("%s: %+v", c.name, res)
		}
		if !r.trusts(r.shipped) || len(r.alerts) != 0 {
			t.Fatalf("%s: switched", c.name)
		}
	}
	// A socket that reads the call and closes without answering.
	lost := filepath.Join(filepath.Dir(r.sock), "lost.sock")
	ln, err := proc.ListenClerk(lost, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			b := make([]byte, 1)
			conn.Read(b)
			conn.Close()
		}
	}()
	if res := (proc.Remote{Socket: lost, UID: os.Getuid(), Timeout: time.Second}).Clerk(r.anchors).Do(req, r.k.State()); res.Outcome != "unknown" {
		t.Fatalf("lost answer: %+v", res)
	}
}

// The follow clerk's flags go together, as absolute paths, beside the
// follow setting and the kernel's uid; its anchors are a file only their
// owner writes, in a directory the same holds for (D-146).
func TestFollowClerkFlagsAndAnchors(t *testing.T) {
	s := &followSetting{}
	for _, c := range []struct {
		sock, anchors string
		uid           int
		s             *followSetting
	}{
		{"/run/f.sock", "", 900, s},
		{"", "/run/a", 900, s},
		{"f.sock", "/run/a", 900, s},
		{"/run/f.sock", "a", 900, s},
		{"/run/f.sock", "/run/a", 900, nil},
		{"/run/f.sock", "/run/a", -1, s},
		{"/run/f.sock", "/run/a", 0, s},
	} {
		if err := followClerkFlags(c.sock, c.anchors, c.uid, c.s); err == nil {
			t.Fatalf("%+v: no error", c)
		}
	}
	if err := followClerkFlags("", "", -1, nil); err != nil {
		t.Fatal(err)
	}
	if err := followClerkFlags("/run/f.sock", "/run/a", 900, s); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "fa")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	pub, _ := seedPair(1)
	b, err := handoff.EncodeAnchors([]key.PublicKey{key.Ed25519(pub)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "anchors")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if a, err := readAnchors(path, os.Getuid()); err != nil || len(a) != 1 {
		t.Fatalf("%v %v", a, err)
	}
	if _, err := readAnchors(path, os.Getuid()+1); err == nil {
		t.Fatal("another owner's file read")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAnchors(link, os.Getuid()); err == nil {
		t.Fatal("a link read")
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := readAnchors(path, os.Getuid()); err == nil {
		t.Fatal("a group-writable file read")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := readAnchors(path, os.Getuid()); err == nil {
		t.Fatal("anchors in a group-writable directory read")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad"), []byte("not anchors"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readAnchors(filepath.Join(dir, "bad"), os.Getuid()); err == nil {
		t.Fatal("a malformed file read")
	}
}
