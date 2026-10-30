package apply

// REQ: UPD-5, UPD-7, UPD-4, UPD-8, UPD-1, CH-12

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/attest"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// testMirror is a 2-of-2 release repository whose releases name their
// image, so one image can be published under two versions (a fast
// release promoted to stable).
type testMirror struct {
	t      *testing.T
	repo   update.Repo
	dir    string
	signer []ed25519.PrivateKey
	snap   ed25519.PrivateKey
	stamp  ed25519.PrivateKey
}

func newTestMirror(t *testing.T) *testMirror {
	t.Helper()
	m := &testMirror{t: t, dir: t.TempDir()}
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		m.must(err)
		return pub, pk
	}
	p1, k1 := key()
	p2, k2 := key()
	sp, sk := key()
	tp, tk := key()
	m.signer, m.snap, m.stamp = []ed25519.PrivateKey{k1, k2}, sk, tk
	var err error
	m.repo, err = update.Init(filepath.Join(m.dir, "repo"), update.RootConfig{
		Root: []ed25519.PublicKey{p1, p2}, Targets: []ed25519.PublicKey{p1, p2},
		Snapshot: []ed25519.PublicKey{sp}, Timestamp: []ed25519.PublicKey{tp},
		RootThreshold: 2, TargetsThreshold: 2})
	m.must(err)
	for _, k := range m.signer {
		m.must(m.repo.Sign("root", k))
	}
	m.publish()
	return m
}

func (m *testMirror) must(err error) {
	m.t.Helper()
	if err != nil {
		m.t.Fatal(err)
	}
}

func (m *testMirror) publish() {
	m.t.Helper()
	for _, k := range m.signer {
		m.must(m.repo.Sign("targets", k))
	}
	m.must(m.repo.Publish(m.snap, m.stamp))
}

// add publishes release version on channel carrying image.
func (m *testMirror) add(version int64, channel string, security bool, image string) {
	m.t.Helper()
	f := filepath.Join(m.dir, fmt.Sprint("img", version))
	m.must(os.WriteFile(f, []byte(image), 0o600))
	h := sha256.Sum256([]byte(image))
	rel := update.Manifest{Version: version, Channel: channel, Security: security, UsrRootHash: hex.EncodeToString(h[:]),
		Files: []string{"host-image/usr.img"}}
	m.must(m.repo.AddRelease(rel, map[string]string{"host-image/usr.img": f}))
	m.publish()
}

func (m *testMirror) source() update.Source { return update.DirSource(m.repo.Dir) }

func (m *testMirror) box(installed int64) *update.Store {
	m.t.Helper()
	root, err := os.ReadFile(filepath.Join(m.repo.Dir, "metadata", "1.root.json"))
	m.must(err)
	st, err := update.InitStore(filepath.Join(m.t.TempDir(), "box"), root, installed)
	m.must(err)
	return st
}

// runner is a requalification sandbox: every suite passes, or the
// candidate fails held-out, or every run errs.
type runner struct {
	fail bool
	err  error
}

func (r *runner) Run(_ context.Context, rel *update.Verified, suite string) (update.Score, error) {
	if r.err != nil {
		return update.Score{}, r.err
	}
	sc := update.Score{Suite: suite, Digest: "d", Cases: 1, Passed: 1}
	if r.fail && rel != nil && suite == update.SuiteHeldOut {
		sc.Passed = 0
	}
	return sc, nil
}

type scheduled struct {
	v   *update.Verified
	id  string
	err error
}

// crig is a release check driving the rig's real Applier, over a test
// mirror and a box store installed at release 1.
type crig struct {
	*rig
	m       *testMirror
	c       *Check
	cstate  *change.MemStore
	failAt  string // the check's state saves fail while they contain this
	allow   []ed25519.PublicKey
	attKey  ed25519.PrivateKey
	pass    bool // one listed fast pass for every release
	attErr  error
	attsErr error
	channel string
	chErr   error
	early   time.Duration // the clock guard's bounds, from the rig clock
	late    time.Duration
	earlyNo bool
	lateNo  bool
	trusted bool
	run     update.Runner // nil: the box cannot requalify
	requals int
	mirrors []update.Source // nil: the test mirror
	looked  int             // Mirrors calls
	sched   []scheduled
	// withdrawErr: the applier refuses every Withdraw with it.
	withdrawErr error
}

// lateStager is the applier's Stager: the check, made after the applier.
type lateStager struct{ cr *crig }

func (s lateStager) ConfirmStaged(id string) error { return s.cr.c.ConfirmStaged(id) }
func (s lateStager) StageFailed(ctx context.Context, id string) error {
	return s.cr.c.StageFailed(ctx, id)
}
func (s lateStager) StageDropped(ctx context.Context, id string) error {
	return s.cr.c.StageDropped(ctx, id)
}

// recApplier is the rig's current Applier, recording each Schedule.
type recApplier struct{ cr *crig }

func (a recApplier) Schedule(v *update.Verified, id string) error {
	err := a.cr.a.Schedule(v, id)
	a.cr.sched = append(a.cr.sched, scheduled{v, id, err})
	return err
}

func (a recApplier) FellBack(version int64) bool { return a.cr.a.FellBack(version) }

func (a recApplier) Withdraw(id, why string) error {
	if a.cr.withdrawErr != nil {
		return a.cr.withdrawErr
	}
	return a.cr.a.Withdraw(id, why)
}

type checkState0 struct{ cr *crig }

func (s checkState0) Load() ([]byte, error) { return s.cr.cstate.Load() }
func (s checkState0) Save(b []byte) error {
	if s.cr.failAt != "" && strings.Contains(string(b), s.cr.failAt) {
		return errors.New("disk full")
	}
	return s.cr.cstate.Save(b)
}

func newCheckRig(t *testing.T, channel string) *crig {
	t.Helper()
	cr := &crig{rig: newRig(t), m: newTestMirror(t), cstate: &change.MemStore{}, channel: channel, trusted: true}
	ap, ak := seedKey(70)
	cr.allow, cr.attKey = []ed25519.PublicKey{ap}, ak
	cr.store = cr.m.box(1)
	cr.stager = lateStager{cr}
	cr.restart()
	cr.c = cr.newCheck()
	return cr
}

func (cr *crig) config() CheckConfig {
	return CheckConfig{Store: cr.store, Applier: recApplier{cr},
		Mirrors: func() []update.Source {
			cr.looked++
			if cr.mirrors != nil {
				return cr.mirrors
			}
			return []update.Source{cr.m.source()}
		},
		Attestors: func() ([]ed25519.PublicKey, []ed25519.PublicKey, error) { return cr.allow, nil, cr.attsErr },
		Attestations: func(_ context.Context, v *update.Verified) ([][]byte, error) {
			if !cr.pass {
				return nil, cr.attErr
			}
			a, err := update.Attest(cr.attKey, v, update.Statement{Result: update.ResultPass, Channel: update.ChannelFast,
				Hardware: attest.Hardware{Vendor: attest.Unlisted, Model: attest.Unlisted, Firmware: attest.Unlisted}})
			if err == nil {
				err = cr.attErr // a pass that came with an error
			}
			return [][]byte{a}, err
		},
		Channel:  func() (string, error) { return cr.channel, cr.chErr },
		Earliest: func(context.Context) (time.Time, bool) { return cr.clk.now().Add(cr.early), !cr.earlyNo },
		Latest:   func(context.Context) (time.Time, bool) { return cr.clk.now().Add(cr.late), !cr.lateNo },
		Trusted:  func() bool { return cr.trusted },
		Requalify: func(ctx context.Context, v *update.Verified) (update.Verdict, error) {
			cr.requals++
			q, err := update.NewRequalifier(cr.store, cr.run, filepath.Join(cr.t.TempDir(), "requal.json"))
			if err != nil {
				return update.Verdict{}, err
			}
			return q.Requalify(ctx, v)
		},
		State: checkState0{cr}}
}

func (cr *crig) newCheck() *Check {
	cr.t.Helper()
	c, err := NewCheck(cr.config())
	if err != nil {
		cr.t.Fatal(err)
	}
	return c
}

func (cr *crig) step() error { return cr.c.Step(context.Background()) }

func (cr *crig) mustStep() {
	cr.t.Helper()
	if err := cr.step(); err != nil {
		cr.t.Fatal(err)
	}
}

func (cr *crig) days(n int) { cr.clk.add(time.Duration(n) * 24 * time.Hour) }

// taken is the adoption IDs the applier took.
func (cr *crig) taken() []string {
	var out []string
	for _, s := range cr.sched {
		if s.err == nil {
			out = append(out, s.id)
		}
	}
	return out
}

func (cr *crig) takenAre(want ...string) {
	cr.t.Helper()
	if got := cr.taken(); !slices.Equal(got, want) {
		cr.t.Fatalf("scheduled %q, want %q (calls %+v)", got, want, cr.sched)
	}
}

func (cr *crig) lineIs(want string) {
	cr.t.Helper()
	if got := cr.c.Line(); got != want {
		cr.t.Fatalf("line %q, want %q", got, want)
	}
}

func soakText(v int64, until time.Time) string {
	return fmt.Sprintf(soakLine, v, until.Local().Format("2 Jan 2006"))
}

// The stable gate end to end on the real applier: the soak, then an
// independent pass, then requalification, then one schedule.
// Mutant: schedule without StableReady (first step schedules); drop the
// adopted() return (a further step schedules again).
func TestStableSchedulesAfterSoakAndPass(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	cr.run = &runner{}
	cr.m.add(2, update.ChannelStable, false, "two")
	start := cr.clk.now()
	cr.mustStep()
	cr.takenAre()
	cr.lineIs(soakText(2, start.Add(7*24*time.Hour)))
	if len(cr.c.st.Seen) == 0 {
		t.Fatal("no sighting recorded")
	}
	cr.days(7)
	cr.mustStep()
	cr.takenAre()
	cr.lineIs(fmt.Sprintf(passesLine, 2))
	cr.pass = true
	cr.mustStep()
	cr.takenAre("upd:2:1")
	cr.lineIs("")
	cr.days(1)
	cr.mustStep()
	cr.takenAre("upd:2:1")
}

// A release keyed by its image: an image first seen on fast and later
// published on stable under a new version is not soaked again, and a
// different image under one version is a different sighting.
// Mutant: key sightings by version, or skip the fast-channel check.
func TestPromotedReleaseSoaksFromFastSighting(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	cr.run, cr.pass = &runner{}, true
	cr.m.add(2, update.ChannelFast, false, "image")
	cr.mustStep()
	cr.takenAre()
	cr.lineIs("") // nothing on stable yet
	cr.days(7)
	cr.m.add(3, update.ChannelStable, false, "image")
	cr.mustStep()
	cr.takenAre("upd:3:1")

	a := updatetest.Release(t, 5, false, map[string][]byte{"host-image/usr.img": []byte("a")})
	b := updatetest.Release(t, 5, false, map[string][]byte{"host-image/usr.img": []byte("b")})
	a2 := updatetest.Release(t, 6, false, map[string][]byte{"host-image/usr.img": []byte("a")})
	if imageKey(a) == imageKey(b) || imageKey(a) != imageKey(a2) {
		t.Fatalf("keys: a %s b %s a-again %s", imageKey(a), imageKey(b), imageKey(a2))
	}
}

// The sighting is recorded at the clock guard's Latest and the soak judged
// at its Earliest, so a skewed clock only lengthens a soak.
// Mutant: record the sighting with Earliest; judge with Latest.
func TestSightingUsesLatestAndSoakUsesEarliest(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	cr.run, cr.pass = &runner{}, true
	cr.late = 48 * time.Hour
	cr.m.add(2, update.ChannelStable, false, "two")
	start := cr.clk.now()
	cr.mustStep()
	cr.lineIs(soakText(2, start.Add(9*24*time.Hour)))
	cr.days(7)
	cr.mustStep()
	cr.takenAre()
	cr.days(2)
	cr.mustStep()
	cr.takenAre("upd:2:1")

	t.Run("no Latest records nothing", func(t *testing.T) {
		cr := newCheckRig(t, update.ChannelStable)
		cr.lateNo = true
		cr.m.add(2, update.ChannelStable, false, "two")
		cr.mustStep()
		if len(cr.c.st.Seen) != 0 {
			t.Fatalf("recorded %v", cr.c.st.Seen)
		}
		cr.lineIs(fmt.Sprintf(soakOpenLine, 2))
	})
	t.Run("no Earliest holds an ordinary release", func(t *testing.T) {
		cr := newCheckRig(t, update.ChannelStable)
		cr.run, cr.pass = &runner{}, true
		cr.m.add(2, update.ChannelStable, false, "two")
		cr.mustStep()
		cr.earlyNo = true
		cr.mustStep()
		cr.lineIs(fmt.Sprintf(soakOpenLine, 2)) // its date is still ahead by Latest
		cr.days(8)
		cr.mustStep()
		cr.takenAre()
		// An untrusted clock dates nothing: the soak date is long past.
		cr.lineIs(fmt.Sprintf(soakOpenLine, 2))
		cr.m.add(3, update.ChannelStable, true, "three")
		cr.mustStep()
		cr.takenAre("upd:3:1")
	})
}

// CH-12: the soak line never shows a date already past. With Earliest
// behind the clock, the soak is judged unfinished after its date has
// passed by Latest, and the line has no date.
// Mutant: drop the Latest comparison.
func TestSoakLineNeverDatesThePast(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	cr.early = -48 * time.Hour
	cr.m.add(2, update.ChannelStable, false, "two")
	start := cr.clk.now()
	cr.mustStep()
	cr.lineIs(soakText(2, start.Add(7*24*time.Hour)))
	cr.days(8)
	cr.mustStep()
	cr.takenAre()
	cr.lineIs(fmt.Sprintf(soakOpenLine, 2))
	// No trusted Latest: no date can be checked against it.
	cr.days(-7)
	cr.mustStep()
	cr.lineIs(soakText(2, start.Add(7*24*time.Hour)))
	cr.lateNo = true
	cr.mustStep()
	cr.lineIs(fmt.Sprintf(soakOpenLine, 2))
}

// A sighting is kept for exactly twice MaxSoakDays once its image is no
// longer offered; one still offered is kept, so its soak never restarts.
// Mutant: change the bound or its comparison; prune by age alone.
func TestOldSightingsPruned(t *testing.T) {
	keep := 2 * update.MaxSoakDays * 24 * time.Hour
	cr := newCheckRig(t, update.ChannelStable)
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	two := maps.Clone(cr.c.st.Seen)
	cr.m.add(3, update.ChannelStable, false, "three")
	cr.days(1)
	cr.mustStep() // two is no longer offered
	three := map[string]time.Time{}
	for k, at := range cr.c.st.Seen {
		if _, ok := two[k]; !ok {
			three[k] = at
		}
	}
	cr.clk.add(keep - 24*time.Hour)
	cr.mustStep()
	if len(cr.c.st.Seen) != 2 {
		t.Fatalf("pruned at the bound: %v", cr.c.st.Seen)
	}
	cr.clk.add(time.Second)
	cr.mustStep()
	if !maps.Equal(cr.c.st.Seen, three) {
		t.Fatalf("after the bound: %v, want %v", cr.c.st.Seen, three)
	}
	cr.days(1) // three is past the bound but still offered
	cr.mustStep()
	if !maps.Equal(cr.c.st.Seen, three) {
		t.Fatalf("offered sighting moved: %v, want %v", cr.c.st.Seen, three)
	}
}

// UPD-4: a fast box takes an ordinary release at once.
func TestFastSchedulesAtOnce(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.m.add(2, update.ChannelFast, false, "two")
	cr.mustStep()
	cr.takenAre("upd:2:1")
}

// UPD-4: a pinned box, or one whose channel cannot be read or is unknown,
// checks nothing and schedules nothing, a security fix included. An
// unreadable channel never says the owner pinned it (CH-12).
// Mutant: treat an error as stable; show the pinned line for an error.
func TestPinnedOrUnreadableChannelSchedulesNothing(t *testing.T) {
	for _, tc := range []struct {
		ch   string
		err  error
		line string
	}{{"pinned", nil, checkPinned}, {"", nil, checkPinned}, {"beta", nil, checkPinned},
		{update.ChannelStable, errors.New("settings unreadable"), checkUnreadable}} {
		cr := newCheckRig(t, tc.ch)
		cr.chErr, cr.pass = tc.err, true
		cr.m.add(2, update.ChannelStable, true, "two")
		cr.mustStep()
		cr.takenAre()
		cr.lineIs(tc.line)
		if cr.looked != 0 {
			t.Fatalf("%q: mirrors read", tc.ch)
		}
	}
}

// UPD-8: a security fix needs one listed independent pass, then goes with
// no soak, as a security fix the applier sees as one.
func TestSecurityFixNeedsListedAttestation(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	cr.m.add(2, update.ChannelStable, true, "two")
	cr.mustStep()
	cr.takenAre()
	cr.lineIs(fmt.Sprintf(securityLine, 2))
	cr.pass = true
	cr.mustStep()
	cr.takenAre("upd:2:1")
	if !cr.sched[0].v.Security() {
		t.Fatal("scheduled without Security()")
	}
}

// SR3-6f-1: an unreadable attestor list fails the step closed, before any
// mirror is read.
func TestAttestorReadErrorFailsClosed(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.attsErr = errors.New("list unreadable")
	cr.m.add(2, update.ChannelFast, true, "two")
	cr.pass = true
	if err := cr.step(); err == nil {
		t.Fatal("step passed")
	}
	cr.takenAre()
	if cr.looked != 0 {
		t.Fatal("mirrors read")
	}
}

// An attestation fetch error counts as none: it narrows, never widens.
func TestAttestationFetchErrorCountsAsNone(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	cr.pass, cr.attErr = true, errors.New("offline")
	cr.m.add(2, update.ChannelStable, true, "two")
	cr.mustStep()
	cr.takenAre()
	cr.lineIs(fmt.Sprintf(securityLine, 2))
}

// UPD-1: a release that fell back is never offered again, its adoption is
// failed, and a newer release is.
// Mutant: drop the FellBack check, or let StageDropped revive a failed
// adoption.
func TestFallenBackReleaseNotOffered(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	cr.m.add(2, update.ChannelFast, false, "two")
	cr.mustStep()
	cr.takenAre("upd:2:1")
	cr.clk.add(7 * time.Hour)
	cr.act.failBoot = true
	if ok, err := cr.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	cr.restart()
	cr.must(cr.a.Resume(ctx))
	if got := cr.c.st.Adoptions["upd:2:1"].State; got != adFailed {
		t.Fatalf("adoption %q", got)
	}
	cr.act.failBoot = false
	for range 2 {
		cr.days(1)
		cr.mustStep()
		cr.takenAre("upd:2:1")
		cr.lineIs(fmt.Sprintf(checkFellBack, 2))
	}
	cr.m.add(3, update.ChannelFast, false, "three")
	cr.mustStep()
	cr.takenAre("upd:2:1", "upd:3:2")
}

// A5: a restart drops the pending release; once the drop settles, the next
// step offers it under a new ID, and not before.
func TestDroppedAdoptionReofferedUnderNewID(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.m.add(2, update.ChannelFast, false, "two")
	cr.mustStep()
	cr.restart()
	cr.mustStep()
	cr.takenAre("upd:2:1")                                     // still staged until the applier settles it
	if _, err := cr.a.Tick(context.Background()); err != nil { // settles the drop
		t.Fatal(err)
	}
	if got := cr.c.st.Adoptions["upd:2:1"].State; got != adDropped {
		t.Fatalf("adoption %q", got)
	}
	cr.mustStep()
	cr.takenAre("upd:2:1", "upd:2:2")
}

// The Stager answers for IDs an earlier Check minted, idempotently, and
// refuses an unknown or confirmed one for good (A16).
func TestStagerAnswersAcrossRestart(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	ref := func(v int64) update.Ref { return update.Ref{Version: v, UsrRootHash: "r", ManifestSHA256: "m"} }
	var ids []string
	for v := int64(2); v <= 5; v++ {
		id, err := cr.c.mint(ref(v), false)
		cr.must(err)
		ids = append(ids, id)
	}
	c := cr.newCheck()
	for range 2 {
		cr.must(c.ConfirmStaged(ids[0]))
		cr.must(c.StageFailed(ctx, ids[1]))
		cr.must(c.StageDropped(ctx, ids[2]))
	}
	cr.must(c.StageDropped(ctx, ids[1])) // a failed adoption stays failed
	if err := c.ConfirmStaged(ids[1]); err == nil || permanent(err) {
		t.Fatalf("confirm of a failed adoption: %v", err)
	}
	if err := c.StageDropped(ctx, ids[0]); !permanent(err) {
		t.Fatalf("drop of a confirmed adoption: %v", err)
	}
	if err := c.StageFailed(ctx, ids[0]); !permanent(err) {
		t.Fatalf("fail of a confirmed adoption: %v", err)
	}
	for _, f := range []func(string) error{c.ConfirmStaged,
		func(id string) error { return c.StageFailed(ctx, id) },
		func(id string) error { return c.StageDropped(ctx, id) }} {
		if err := f("upd:9:99"); !permanent(err) {
			t.Fatalf("unknown adoption: %v", err)
		}
	}
	got := cr.newCheck().st.Adoptions
	for i, want := range []string{adConfirmed, adFailed, adDropped, adStaged} {
		if got[ids[i]].State != want {
			t.Fatalf("%s is %q, want %q", ids[i], got[ids[i]].State, want)
		}
	}
	// A newer confirmation prunes settled adoptions below it, never a
	// staged one.
	id, err := c.mint(ref(6), false)
	cr.must(err)
	cr.must(c.ConfirmStaged(id))
	left := cr.newCheck().st.Adoptions
	if len(left) != 2 || left[ids[3]].State != adStaged || left[id].State != adConfirmed {
		t.Fatalf("after pruning: %+v", left)
	}
	if err := c.StageDropped(ctx, ids[2]); !permanent(err) {
		t.Fatalf("pruned adoption: %v", err)
	}
	// A dropped adoption can still settle as confirmed or failed: an
	// abandon that never took lets its release boot (A14).
	late := make([]string, 2)
	for i := range late {
		id, err := c.mint(ref(8), false)
		cr.must(err)
		late[i] = id
		cr.must(c.StageDropped(ctx, late[i]))
	}
	cr.must(c.ConfirmStaged(late[0]))
	cr.must(c.StageFailed(ctx, late[1]))
	left = cr.newCheck().st.Adoptions
	if left[late[0]].State != adConfirmed || left[late[1]].State != adFailed {
		t.Fatalf("from dropped: %+v %+v", left[late[0]], left[late[1]])
	}
}

// The adoption is saved as staged before Schedule: a failed save
// schedules nothing.
// Mutant: Schedule before the save.
func TestSaveBeforeSchedule(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.failAt = `"adoptions"`
	cr.m.add(2, update.ChannelFast, false, "two")
	if err := cr.step(); err == nil {
		t.Fatal("step passed")
	}
	if len(cr.sched) != 0 {
		t.Fatalf("scheduled %+v", cr.sched)
	}
}

// UPD-3: nothing happens until first boot has finished.
func TestNothingBeforeFirstBootTrusted(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.trusted = false
	cr.m.add(2, update.ChannelFast, true, "two")
	cr.pass = true
	cr.mustStep()
	cr.takenAre()
	cr.lineIs("")
	if cr.looked != 0 {
		t.Fatal("mirrors read")
	}
}

// soaked is a stable rig whose release 2 is soaked and attested.
func soaked(t *testing.T) *crig {
	cr := newCheckRig(t, update.ChannelStable)
	cr.pass = true
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.days(7)
	return cr
}

// The ship gate (Mark's decision C on #3961): an ordinary stable release
// is scheduled only on a Passed requalification, once.
// Mutant: drop the Requalify call; treat any verdict as passed.
func TestStableHoldsUntilRequalified(t *testing.T) {
	cr := soaked(t)
	for range 2 {
		cr.mustStep()
		cr.takenAre()
		cr.lineIs(fmt.Sprintf(unavailableLine, 2))
		cr.days(1)
	}
	cr.run = &runner{fail: true}
	cr.mustStep()
	cr.takenAre()
	cr.lineIs(fmt.Sprintf(requalFailLine, 2))
	cr.run = &runner{}
	cr.mustStep()
	cr.takenAre("upd:2:1")
	n := cr.requals
	cr.mustStep()
	cr.takenAre("upd:2:1")
	if cr.requals != n {
		t.Fatal("requalified a release already adopted")
	}
}

// A requalification error holds the release (fail closed).
func TestRequalifyErrorHoldsTheRelease(t *testing.T) {
	cr := soaked(t)
	cr.run = &runner{err: errors.New("sandbox down")}
	cr.mustStep()
	cr.takenAre()
	cr.lineIs(fmt.Sprintf(unavailableLine, 2))
}

// A fast box and a security fix are not requalified (UPD-5's table).
func TestFastAndSecuritySkipRequalification(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.m.add(2, update.ChannelFast, false, "two")
	cr.mustStep()
	cr.takenAre("upd:2:1")
	sec := newCheckRig(t, update.ChannelStable)
	sec.pass = true
	sec.m.add(2, update.ChannelStable, true, "two")
	sec.mustStep()
	sec.takenAre("upd:2:1")
	if cr.requals+sec.requals != 0 {
		t.Fatal("requalified")
	}
}

func TestNewCheckRequiresEveryFunction(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	for _, drop := range []func(*CheckConfig){
		func(c *CheckConfig) { c.Store = nil }, func(c *CheckConfig) { c.Applier = nil },
		func(c *CheckConfig) { c.Mirrors = nil }, func(c *CheckConfig) { c.Attestors = nil },
		func(c *CheckConfig) { c.Attestations = nil }, func(c *CheckConfig) { c.Channel = nil },
		func(c *CheckConfig) { c.Earliest = nil }, func(c *CheckConfig) { c.Latest = nil },
		func(c *CheckConfig) { c.Trusted = nil }, func(c *CheckConfig) { c.Requalify = nil },
		func(c *CheckConfig) { c.State = nil },
	} {
		cfg := cr.config()
		drop(&cfg)
		if _, err := NewCheck(cfg); err == nil {
			t.Fatal("NewCheck took a config missing a function")
		}
	}
}

// The lifecycle matrix's channel changes: stable to fast schedules at the
// next step; fast to stable soaks from the fast sighting; to pinned
// schedules nothing.
func TestChannelChange(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.takenAre()
	cr.channel = "pinned"
	cr.mustStep()
	cr.takenAre()
	cr.channel = update.ChannelFast
	cr.mustStep()
	cr.takenAre("upd:2:1")

	fs := newCheckRig(t, update.ChannelFast)
	fs.run, fs.pass = &runner{}, true
	fs.m.add(2, update.ChannelStable, false, "two")
	fs.mustStep()
	fs.restart() // the pending release is dropped (A5)
	if _, err := fs.a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	fs.channel = update.ChannelStable
	fs.days(6)
	fs.mustStep()
	fs.takenAre("upd:2:1")
	fs.days(1)
	fs.mustStep()
	fs.takenAre("upd:2:1", "upd:2:2")
}

// UPD-4, UPD-5: a box moved from fast to stable while an ordinary
// release adopted on fast is pending installs nothing the stable gate did
// not pass: the adoption is withdrawn and the release offered again under
// the stable gate. A security fix adopted on fast stays.
// Mutant: skip withdrawFast; withdraw every staged adoption.
func TestFastToStableWithdrawsPendingRelease(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.takenAre("upd:2:1")
	cr.channel = update.ChannelStable
	// A release being installed is left to install (ErrApplying); any
	// other refusal, or a failed save of the drop, fails the step and the
	// next step tries again.
	cr.withdrawErr = ErrApplying
	cr.mustStep()
	cr.withdrawErr = errors.New("state unwritable")
	if err := cr.step(); err == nil {
		t.Fatal("a refused withdraw passed")
	}
	cr.withdrawErr, cr.failAt = nil, `"dropped"`
	if err := cr.step(); err == nil {
		t.Fatal("an unsaved drop passed")
	}
	cr.failAt = ""
	cr.mustStep()
	cr.clk.add(7 * time.Hour)
	if ok, err := cr.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if len(cr.act.installed) != 0 {
		t.Fatalf("installed %v on stable with no gate", cr.act.installed)
	}
	if got := cr.c.st.Adoptions["upd:2:1"].State; got != adDropped {
		t.Fatalf("adoption %q", got)
	}
	cr.run, cr.pass = &runner{}, true
	cr.days(7)
	cr.mustStep()
	cr.takenAre("upd:2:1", "upd:2:2")
	if cr.requals != 1 {
		t.Fatalf("requalified %d times", cr.requals)
	}

	sec := newCheckRig(t, update.ChannelFast)
	sec.pass = true
	sec.m.add(2, update.ChannelStable, true, "two")
	sec.mustStep()
	sec.channel = update.ChannelStable
	sec.mustStep()
	if got := sec.c.st.Adoptions["upd:2:1"].State; got != adStaged {
		t.Fatalf("security fix withdrawn: %q", got)
	}
	sec.takenAre("upd:2:1")

	// Handed over, the restart held by a call: the stable step undoes the
	// handover, so the release never boots on a stable box (Security
	// round 2 on #4075).
	ho := newCheckRig(t, update.ChannelFast)
	ho.m.add(2, update.ChannelStable, false, "two")
	ho.mustStep()
	ho.clk.add(7 * time.Hour)
	ho.act.onInstall = func() { ho.inCall = true }
	if ok, err := ho.a.Tick(ctx); ok || err != nil {
		t.Fatalf("handover tick: %v %v", ok, err)
	}
	if pt := ho.a.st.Applying; pt == nil || !pt.Installed {
		t.Fatalf("not handed over: %+v", pt)
	}
	ho.channel = update.ChannelStable
	ho.act.abandonErr = errors.New("activator busy")
	if err := ho.step(); err != nil {
		t.Fatalf("step with the abandon failing: %v", err)
	}
	if got, want := ho.a.Status(), fmt.Sprintf(stableMayStartLine, 2); got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
	// A security refusal since names its own cause.
	if err := ho.a.Withdraw("upd:2:1", WhySecurity); !errors.Is(err, ErrApplying) {
		t.Fatalf("security withdraw with the abandon failing: %v", err)
	}
	if got, want := ho.a.Status(), fmt.Sprintf(mayStartLine, 2); got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
	ho.act.abandonErr = nil
	ho.mustStep()
	ho.inCall = false
	if ok, err := ho.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick after the switch: %v %v", ok, err)
	}
	if ho.act.restarts != 0 || ho.act.abandoned != 1 || ho.a.st.Applying != nil {
		t.Fatalf("restarts %d, abandoned %d, applying %+v", ho.act.restarts, ho.act.abandoned, ho.a.st.Applying)
	}
	if got := ho.c.st.Adoptions["upd:2:1"].State; got != adDropped {
		t.Fatalf("handed-over adoption %q", got)
	}

	// The install still executing: the refusal is recorded, execute marks
	// the point withdrawing, and the next Tick undoes it.
	ex := newCheckRig(t, update.ChannelFast)
	ex.m.add(2, update.ChannelStable, false, "two")
	ex.mustStep()
	ex.clk.add(7 * time.Hour)
	var during string
	ex.act.onInstall = func() {
		ex.channel = update.ChannelStable
		if err := ex.step(); err != nil {
			t.Errorf("step while installing: %v", err)
		}
		during = ex.a.Status()
	}
	ex.act.abandonErr = errors.New("activator busy")
	if ok, err := ex.a.Tick(ctx); ok || err == nil {
		t.Fatalf("installing tick: %v %v", ok, err)
	}
	if want := fmt.Sprintf(stableWontStartLine, 2); during != want {
		t.Fatalf("status while installing %q, want %q", during, want)
	}
	// One line names update 2: the applier's, while it withdraws it.
	ex.lineIs("")
	if pt := ex.a.st.Applying; pt == nil || !pt.Withdrawing || !pt.Stable || pt.Pinned {
		t.Fatalf("point %+v", pt)
	}
	if got, want := ex.a.Status(), fmt.Sprintf(stableMayStartLine, 2); got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
	ex.act.abandonErr = nil
	if ok, err := ex.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if ex.act.restarts != 0 || ex.act.abandoned != 1 || ex.a.st.Applying != nil {
		t.Fatalf("restarts %d, abandoned %d, applying %+v", ex.act.restarts, ex.act.abandoned, ex.a.st.Applying)
	}
	if got := ex.c.st.Adoptions["upd:2:1"].State; got != adDropped {
		t.Fatalf("executing adoption %q", got)
	}
	// Withdrawn, the applier says nothing more of it, and the check's
	// soak line is the one line.
	if got := ex.a.Status(); got != "" {
		t.Fatalf("applier status %q", got)
	}
	if got := ex.c.Line(); !strings.HasPrefix(got, "Update 2 installs after ") {
		t.Fatalf("line %q", got)
	}
	if got := ex.a.Digest(); len(got) != 0 {
		t.Fatalf("digest %q", got)
	}
}

// A security refusal of the apply in flight keeps its reason when a move
// to stable is refused for it too: STATUS still says it failed a
// security check.
// Mutant: let the stable refusal replace the security one.
func TestStableRefusalKeepsSecurityReason(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.clk.add(7 * time.Hour)
	var got string
	cr.act.onInstall = func() {
		for _, why := range []string{WhySecurity, WhyStable} {
			if err := cr.a.Withdraw("upd:2:1", why); !errors.Is(err, ErrApplying) {
				t.Errorf("%s withdraw while installing: %v", why, err)
			}
		}
		got = cr.a.Status()
	}
	cr.act.abandonErr = errors.New("activator busy")
	if _, err := cr.a.Tick(context.Background()); err == nil {
		t.Fatal("tick undid the handover with the abandon failing")
	}
	if want := fmt.Sprintf(wontStartLine, 2); got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
	// Saved by execute, the point keeps the security cause across a
	// process restart, which forgets the refusal.
	cr.restart()
	if got, want := cr.a.Status(), fmt.Sprintf(mayStartLine, 2); got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
}

// The fast mark is saved: a check reloaded from its state between the
// fast adoption and the stable step still withdraws the release.
// Mutant: do not persist Fast.
func TestFastMarkSurvivesCheckReload(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.c = cr.newCheck()
	cr.channel = update.ChannelStable
	cr.mustStep()
	cr.clk.add(7 * time.Hour)
	if ok, err := cr.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if len(cr.act.installed) != 0 {
		t.Fatalf("installed %v on stable with no gate", cr.act.installed)
	}
}

// A fast adoption that booted and was confirmed stays: the stable step
// leaves it, succeeds and offers a security fix.
// Mutant: withdraw a fast adoption whatever its state.
func TestConfirmedFastAdoptionKeepsStableStep(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.clk.add(7 * time.Hour)
	if ok, err := cr.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	cr.restart()
	cr.must(cr.a.Resume(ctx))
	if got := cr.c.st.Adoptions["upd:2:1"].State; got != adConfirmed {
		t.Fatalf("adoption %q", got)
	}
	cr.channel, cr.pass = update.ChannelStable, true
	cr.m.add(3, update.ChannelStable, true, "three")
	cr.mustStep()
	cr.takenAre("upd:2:1", "upd:3:2")
}

// A9: a security fix dropped because its attestor left the list is
// offered again only under the current list.
func TestNarrowedListReoffersUnderCurrentPolicy(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	ctx := context.Background()
	cr.pass = true
	cr.m.add(2, update.ChannelStable, true, "two")
	cr.mustStep()
	cr.takenAre("upd:2:1")
	listed := cr.allow
	cr.allow = nil
	cr.mustStep()
	cr.lineIs(fmt.Sprintf(securityLine, 2))
	if _, err := cr.a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cr.c.st.Adoptions["upd:2:1"].State; got != adDropped {
		t.Fatalf("adoption %q", got)
	}
	cr.mustStep()
	cr.takenAre("upd:2:1")
	cr.allow = listed
	cr.mustStep()
	cr.takenAre("upd:2:1", "upd:2:2")
}

// Mirrors are tried in order; when none verifies, nothing is scheduled
// and the sightings stay.
func TestMirrorFailureSchedulesNothing(t *testing.T) {
	cr := newCheckRig(t, update.ChannelStable)
	bad := update.DirSource(t.TempDir())
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	seen := len(cr.c.st.Seen)
	cr.mirrors = []update.Source{bad}
	if err := cr.step(); err == nil {
		t.Fatal("step passed")
	}
	if len(cr.c.st.Seen) != seen || seen == 0 {
		t.Fatalf("sightings %d, had %d", len(cr.c.st.Seen), seen)
	}
	cr.takenAre()
	fast := newCheckRig(t, update.ChannelFast)
	fast.m.add(2, update.ChannelFast, false, "two")
	fast.mirrors = []update.Source{bad, fast.m.source()}
	fast.mustStep()
	fast.takenAre("upd:2:1")
}

// CH-12: every line, at the longest version and date, is one GSM-7
// segment, names no reason code, and ends saying what the owner needs.
func TestCheckLinesAreOneGSM7Segment(t *testing.T) {
	const v = math.MaxInt64
	c := &Check{}
	until := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	lines := []string{checkPinned, checkUnreadable,
		fmt.Sprintf(securityLine, v), fmt.Sprintf(unavailableLine, v), fmt.Sprintf(requalFailLine, v), fmt.Sprintf(checkFellBack, v)}
	for _, w := range []update.Wait{{Reason: update.WaitSoak, Until: until}, {Reason: update.WaitSoak},
		{Reason: update.WaitAttestations, Need: 1}, {Reason: update.WaitNoAttestor}} {
		lines = append(lines, c.waitLine(v, w))
	}
	codes := []string{update.WaitSoak, update.WaitAttestations, update.WaitNoAttestor, update.RequalUnavailable,
		update.SuiteHeldOut, update.SuiteReplay, "requalif", "upd:"}
	for _, l := range lines {
		if !control.IsGSM7(l) || utf8.RuneCountInString(l) > 160 {
			t.Errorf("%d characters, GSM-7 %v: %q", utf8.RuneCountInString(l), control.IsGSM7(l), l)
		}
		for _, code := range codes {
			if strings.Contains(strings.ToLower(l), code) {
				t.Errorf("names %q: %q", code, l)
			}
		}
		if l != checkPinned && !strings.HasSuffix(l, " Nothing is needed from you.") {
			t.Errorf("no owner step: %q", l)
		}
	}
}

// #4112: a stable Withdraw refused because the boot cannot be read is
// saved, so a process restart before the next Tick still never restarts
// into the fast release.
// Mutant: return the refusal without marking the point.
func TestStableWithdrawSurvivesUnreadBootAndRestart(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.clk.add(7 * time.Hour)
	cr.act.onInstall = func() { cr.inCall = true }
	if ok, err := cr.a.Tick(ctx); ok || err != nil {
		t.Fatalf("handover tick: %v %v", ok, err)
	}
	cr.act.bootedErr = errors.New("boot unreadable")
	cr.channel = update.ChannelStable
	cr.mustStep()
	if got, want := cr.a.Status(), fmt.Sprintf(stableMayStartLine, 2); got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
	cr.act.bootedErr = nil
	cr.restart()
	cr.must(cr.a.Resume(ctx))
	cr.inCall = false
	if ok, err := cr.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick after the restart: %v %v", ok, err)
	}
	if cr.act.restarts != 0 || cr.a.st.Applying != nil {
		t.Fatalf("restarts %d, applying %+v", cr.act.restarts, cr.a.st.Applying)
	}
	if got := cr.c.st.Adoptions["upd:2:1"].State; got != adDropped {
		t.Fatalf("adoption %q", got)
	}
}

// A refusal's reason is the one asked for: an owner UNDO of a point
// withdrawn for a move to stable keeps the stable line, and a security
// withdraw saves its own cause, so it survives a process restart.
// Mutant: record any other reason as security; skip the security save.
func TestWithdrawReasonsKeepTheirCause(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.clk.add(7 * time.Hour)
	cr.act.onInstall = func() { cr.inCall = true }
	if ok, err := cr.a.Tick(ctx); ok || err != nil {
		t.Fatalf("handover tick: %v %v", ok, err)
	}
	cr.act.abandonErr = errors.New("activator busy")
	cr.channel = update.ChannelStable
	cr.mustStep()
	if err := cr.a.Withdraw("upd:2:1", "undo"); !errors.Is(err, ErrApplying) {
		t.Fatalf("undo: %v", err)
	}
	if got, want := cr.a.Status(), fmt.Sprintf(stableMayStartLine, 2); got != want {
		t.Fatalf("after undo %q, want %q", got, want)
	}
	if err := cr.a.Withdraw("upd:2:1", WhySecurity); !errors.Is(err, ErrApplying) {
		t.Fatalf("security: %v", err)
	}
	cr.restart()
	if got, want := cr.a.Status(), fmt.Sprintf(mayStartLine, 2); got != want {
		t.Fatalf("after restart %q, want %q", got, want)
	}
}

// #4102: a Schedule refusal the applier never settles does not strand
// the release. A refusal before the applier took anything leaves no
// record, so a release refused on every step does not grow it; any other
// error drops the adoption, and the next step offers the release again.
// Mutant: leave the adoption staged on an error; keep refused adoptions.
func TestScheduleRefusalsSettleInTheCheck(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	cr.m.add(2, update.ChannelFast, false, "two")
	cr.state.Fail = errors.New("disk full")
	if err := cr.step(); err == nil {
		t.Fatal("a failed applier save passed")
	}
	if got := cr.c.st.Adoptions["upd:2:1"].State; got != adDropped {
		t.Fatalf("after a failed save %q", got)
	}
	cr.state.Fail = nil
	cr.restart()
	cr.mustStep()
	cr.takenAre("upd:2:2")

	ref := newCheckRig(t, update.ChannelFast)
	ref.m.add(2, update.ChannelFast, false, "two")
	ref.a.st.Retired = []string{"upd:2:1"} // a lost check state reuses an ID
	if err := ref.step(); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired: %v", err)
	}
	for range 3 {
		ref.a.st.Applying = &point{Adoption: "other"} // the applier refuses with ErrApplying
		ref.mustStep()
	}
	if n := len(ref.c.st.Adoptions); n != 0 {
		t.Fatalf("record grew to %d: %+v", n, ref.c.st.Adoptions)
	}
	ref.a.st.Applying = nil
	ref.mustStep()
	if got := ref.taken(); len(got) != 1 {
		t.Fatalf("taken %q", got)
	}
}

// A confirmed or failed adoption counts as adopted, so the release is
// not offered again; a dropped one does not.
// Mutant: count only staged adoptions.
func TestAdoptedCountsSettledAdoptions(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	r := func(v int64) update.Ref { return update.Ref{Version: v, UsrRootHash: "h", ManifestSHA256: "m"} }
	for v, settle := range map[int64]func(string) error{
		2: cr.c.ConfirmStaged,
		3: func(id string) error { return cr.c.StageFailed(ctx, id) },
		4: func(id string) error { return cr.c.StageDropped(ctx, id) },
	} {
		id, err := cr.c.mint(r(v), false)
		cr.must(err)
		cr.must(settle(id))
	}
	if !cr.c.adopted(r(2)) || !cr.c.adopted(r(3)) || cr.c.adopted(r(4)) {
		t.Fatalf("adopted: confirmed %v, failed %v, dropped %v", cr.c.adopted(r(2)), cr.c.adopted(r(3)), cr.c.adopted(r(4)))
	}
}

// A security withdraw of a point withdrawn for a move to stable names
// security even when its save fails; a mark that cannot be saved on an
// unread boot is refused with the cause.
// Mutant: take the refusal reason from the point for a security
// withdraw; read another adoption's refusal; drop the mark's error.
func TestSecurityCauseWithoutItsSave(t *testing.T) {
	cr := newCheckRig(t, update.ChannelFast)
	ctx := context.Background()
	cr.m.add(2, update.ChannelStable, false, "two")
	cr.mustStep()
	cr.clk.add(7 * time.Hour)
	cr.act.onInstall = func() { cr.inCall = true }
	if ok, err := cr.a.Tick(ctx); ok || err != nil {
		t.Fatalf("handover tick: %v %v", ok, err)
	}
	disk := errors.New("disk full")
	cr.act.bootedErr = errors.New("boot unreadable")
	cr.state.Fail = disk
	if err := cr.a.Withdraw("upd:2:1", WhyStable); !errors.Is(err, ErrApplying) || !errors.Is(err, disk) {
		t.Fatalf("unsaved mark: %v", err)
	}
	cr.act.bootedErr, cr.state.Fail = nil, nil
	cr.act.abandonErr = errors.New("activator busy")
	if err := cr.a.Withdraw("upd:2:1", WhyStable); !errors.Is(err, ErrApplying) {
		t.Fatalf("stable: %v", err)
	}
	cr.state.Fail = disk
	if err := cr.a.Withdraw("upd:2:1", WhySecurity); !errors.Is(err, ErrApplying) {
		t.Fatalf("security: %v", err)
	}
	if got, want := cr.a.Status(), fmt.Sprintf(mayStartLine, 2); got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
}
