package firstboot

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// fakeApplier stands in for apply.Applier: it records what first boot
// schedules; a test plays the restart by staging and committing.
type fakeApplier struct {
	mu        sync.Mutex
	scheduled []int64
	fellBack  map[int64]bool
	err       error
}

func (f *fakeApplier) ScheduleFirstBoot(v *update.Verified) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := v.Manifest()
	if err != nil {
		return err
	}
	if f.fellBack[m.Version] {
		return apply.ErrFellBack
	}
	if f.err != nil {
		return f.err
	}
	f.scheduled = append(f.scheduled, m.Version)
	return nil
}

// opener counts mirror reads.
type opener struct {
	src update.Source
	n   *int
}

func (o opener) Open(name string) (io.ReadCloser, error) {
	*o.n++
	return o.src.Open(name)
}

type rig struct {
	t      *testing.T
	m      *updatetest.Mirror
	box    *update.Store
	app    *fakeApplier
	state  *change.MemStore
	online bool
	now    time.Time
	opens  int
	mirror []update.Source
	g      *Gate
}

func newRig(t *testing.T, installed int64) *rig {
	r := &rig{t: t, m: updatetest.NewMirror(t), app: &fakeApplier{fellBack: map[int64]bool{}},
		state: &change.MemStore{}, online: true, now: time.Now()}
	r.box = r.m.Box(installed)
	r.mirror = []update.Source{opener{r.m.Source(), &r.opens}}
	r.restart()
	return r
}

func (r *rig) restart() {
	r.t.Helper()
	g, err := New(Config{Store: r.box, Applier: r.app, State: r.state,
		Mirrors: func() []update.Source { return r.mirror },
		Online:  func() bool { return r.online },
		Now:     func() time.Time { return r.now }})
	if err != nil {
		r.t.Fatal(err)
	}
	r.g = g
}

func (r *rig) step() {
	r.t.Helper()
	_ = r.g.Step(context.Background())
}

// finish plays the applier's restart into release v: staged, booted
// cleanly, committed.
func (r *rig) finish(v int64) {
	r.t.Helper()
	res, err := r.box.Check(r.m.Source(), update.Options{Channel: update.ChannelStable, Now: func() time.Time { return r.now }})
	if err != nil || res.Release == nil || res.Release.Version() != strconv.FormatInt(v, 10) {
		r.t.Fatalf("finish %d: %v %v", v, res.Release, err)
	}
	if err := r.box.Stage(res.Release); err != nil {
		r.t.Fatal(err)
	}
	if err := r.box.CommitStaged(v); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) held(why string) {
	r.t.Helper()
	if r.g.Trusted() || !errors.Is(r.g.Hold(), ErrUpdating) {
		r.t.Fatalf("%s: gate open", why)
	}
	if _, updated := r.g.Progress(); updated {
		r.t.Fatalf("%s: progress says updated", why)
	}
}

func (r *rig) open(why string) {
	r.t.Helper()
	if !r.g.Trusted() || r.g.Hold() != nil {
		r.t.Fatalf("%s: gate held: %s", why, r.g.Status())
	}
	if phase, updated := r.g.Progress(); phase != "ready" || !updated || r.g.Status() != "" {
		r.t.Fatalf("%s: progress %q %v status %q", why, phase, updated, r.g.Status())
	}
}

// REQ: UPD-3
func TestOfflineFirstBootRunsShippedImageSaysSoAndContactsNoMirror(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	r.online = false
	r.step()
	r.held("offline")
	if r.opens != 0 {
		t.Fatalf("offline first boot read the mirror %d times", r.opens)
	}
	if phase, _ := r.g.Progress(); phase != "offline" {
		t.Fatalf("phase %q", phase)
	}
	if s := r.g.Status(); !strings.Contains(s, "offline") || !strings.Contains(s, "version I shipped with") || !strings.Contains(s, "next online") {
		t.Fatalf("status %q", s)
	}
	if err := r.g.Hold(); !strings.Contains(err.Error(), "offline") {
		t.Fatalf("hold text %q", err)
	}
	if len(r.app.scheduled) != 0 {
		t.Fatal("scheduled offline")
	}
	// Next online, it updates.
	r.online = true
	r.step()
	if len(r.app.scheduled) != 1 || r.app.scheduled[0] != 2 {
		t.Fatalf("scheduled %v", r.app.scheduled)
	}
	r.held("installing")
}

// REQ: UPD-3
// Online: the newest stable release is scheduled, never a fast one, and
// the gate opens only once it is committed and a fresh check finds
// nothing newer.
func TestOnlineFirstBootUpdatesToLatestStableBeforeTrust(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	r.m.Add(3, update.ChannelFast, false)
	r.step()
	if len(r.app.scheduled) != 1 || r.app.scheduled[0] != 2 {
		t.Fatalf("scheduled %v, want [2]", r.app.scheduled)
	}
	r.held("scheduled")
	if s := r.g.Status(); !strings.Contains(s, "updating to version 2") {
		t.Fatalf("status %q", s)
	}
	if phase, _ := r.g.Progress(); phase != "updating" {
		t.Fatalf("phase %q", phase)
	}
	r.finish(2)
	r.restart()
	r.held("restarted, not yet checked")
	r.step()
	r.open("updated to latest stable")
}

// REQ: UPD-3
func TestCurrentBoxOpensAfterOneFreshCheck(t *testing.T) {
	r := newRig(t, 1)
	r.held("before any check")
	r.step()
	r.open("already current")
	if len(r.app.scheduled) != 0 {
		t.Fatal("scheduled with nothing newer")
	}
}

// REQ: UPD-3
// A frozen mirror (expired metadata) or one that cannot be reached is no
// proof the box is current: the gate stays held and says why.
func TestFrozenOrUnreachableMirrorKeepsGateHeld(t *testing.T) {
	r := newRig(t, 1)
	r.now = r.now.Add(60 * 24 * time.Hour)
	r.step()
	r.held("frozen mirror")
	if s := r.g.Status(); !strings.Contains(s, "could not be verified") {
		t.Fatalf("frozen status %q", s)
	}
	r.now = time.Now()
	r.mirror = []update.Source{update.DirSource(filepath.Join(t.TempDir(), "gone"))}
	r.step()
	r.held("unreachable mirror")
	if s := r.g.Status(); !strings.Contains(s, "could not reach") {
		t.Fatalf("unreachable status %q", s)
	}
	// A second mirror that works is enough.
	r.mirror = append(r.mirror, r.m.Source())
	r.step()
	r.open("second mirror")
}

// REQ: UPD-3
// A first-boot release that fell back is not retried and does not open
// the gate: credentials never reach the outdated image.
func TestFallbackHoldsAndIsNotRetried(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	r.app.fellBack[2] = true
	r.step()
	r.step()
	r.held("fell back")
	if len(r.app.scheduled) != 0 {
		t.Fatalf("retried %v", r.app.scheduled)
	}
	if s := r.g.Status(); !strings.Contains(s, "did not start cleanly") {
		t.Fatalf("status %q", s)
	}
	// A newer release is tried.
	r.m.Add(3, update.ChannelStable, false)
	r.step()
	if len(r.app.scheduled) != 1 || r.app.scheduled[0] != 3 {
		t.Fatalf("scheduled %v", r.app.scheduled)
	}
}

// REQ: UPD-3
// While the applier is mid-restart the gate stays held.
func TestApplyingKeepsGateHeld(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	r.app.err = apply.ErrApplying
	if err := r.g.Step(context.Background()); err != nil {
		t.Fatalf("applying is not an error: %v", err)
	}
	r.held("applying")
}

// REQ: UPD-3
// Trust, once established, is sticky: a restart or going offline does not
// close setup again, and later updates are Loop 3's.
func TestTrustIsSticky(t *testing.T) {
	r := newRig(t, 1)
	r.step()
	r.open("current")
	r.online = false
	r.m.Add(2, update.ChannelStable, false)
	r.restart()
	r.step()
	r.open("after restart offline")
	r.online = true
	r.step()
	r.open("online with a newer release")
	if len(r.app.scheduled) != 0 {
		t.Fatal("first boot scheduled after trust; later updates are Loop 3's")
	}
}

// REQ: UPD-3
// A release installed from a drive offline has not been checked for
// freshness; it opens nothing until an online check confirms it.
func TestDriveInstallOpensOnlyAfterOnlineConfirmation(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	res, err := r.box.Check(r.m.Source(), update.Options{Offline: true})
	if err != nil || res.Release == nil {
		t.Fatal(res, err)
	}
	if err := r.box.Commit(res.Release); err != nil {
		t.Fatal(err)
	}
	r.online = false
	r.step()
	r.held("drive install offline")
	r.online = true
	r.step()
	r.open("confirmed online")
}

// REQ: UPD-3
// A drive release the fresh metadata does not list (withdrawn, or changed)
// is not trusted, even with nothing newer to install.
func TestWithdrawnDriveReleaseKeepsGateHeld(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	res, err := r.box.Check(r.m.Source(), update.Options{Offline: true})
	if err != nil || res.Release == nil {
		t.Fatal(res, err)
	}
	if err := r.box.Commit(res.Release); err != nil {
		t.Fatal(err)
	}
	// The drive's manifest differs from the one the mirror lists.
	p := filepath.Join(r.box.Dir, "installed.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var in update.Installed
	if err := json.Unmarshal(b, &in); err != nil {
		t.Fatal(err)
	}
	in.ManifestSHA256 = strings.Repeat("0", 64)
	b, _ = json.Marshal(in)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	r.step()
	r.held("withdrawn drive release")
	if s := r.g.Status(); !strings.Contains(s, "could not be verified") {
		t.Fatalf("status %q", s)
	}
}

const waitText = " AI and accounts can be connected after that."

// REQ: UPD-3, CH-21
// An unexpected scheduling error is not "updating": STATUS and Hold say the
// update could not be started. The error is returned; the gate stays held.
func TestUnexpectedScheduleErrorIsNotSaidToBeUpdating(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	boom := errors.New("boom")
	r.app.err = boom
	if err := r.g.Step(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	r.held("schedule error")
	if s, want := r.g.Status(), "First start: update 2 could not be started. I will try again."+waitText; s != want {
		t.Fatalf("status %q", s)
	}
	want := "firstboot: I am updating first: update 2 could not be started, so AI and accounts stay closed while I try again"
	if h := r.g.Hold().Error(); h != want {
		t.Fatalf("hold %q", h)
	}
}

// REQ: UPD-3, CH-21
// With several failing mirrors STATUS reflects all of them, whatever the
// order; a single kind of failure keeps its own text.
func TestSeveralFailingMirrorsAreAllReflected(t *testing.T) {
	gone := update.DirSource(filepath.Join(t.TempDir(), "gone"))
	const mixed = "First start: one update server's answer could not be verified and another could not be reached, so I cannot tell I am current. I will try again." + waitText
	const unverified = "First start: the update server's answer could not be verified, so I cannot tell I am current. I will try again." + waitText
	const unreached = "First start: I could not reach the update server. I will try again." + waitText
	for _, tc := range []struct {
		name string
		src  func(r *rig) []update.Source
		want string
	}{
		{"unverified then unreachable", func(r *rig) []update.Source { return []update.Source{r.m.Source(), gone} }, mixed},
		{"unreachable then unverified", func(r *rig) []update.Source { return []update.Source{gone, r.m.Source()} }, mixed},
		{"all unverified", func(r *rig) []update.Source { return []update.Source{r.m.Source(), r.m.Source()} }, unverified},
		{"all unreachable", func(r *rig) []update.Source { return []update.Source{gone, gone} }, unreached},
	} {
		r := newRig(t, 1)
		r.now = r.now.Add(60 * 24 * time.Hour) // the mirror's metadata is expired
		r.mirror = tc.src(r)
		r.step()
		r.held(tc.name)
		if s := r.g.Status(); s != tc.want {
			t.Fatalf("%s: status %q", tc.name, s)
		}
	}
}

// REQ: UPD-3, CH-21
// After a fallback, Hold and Status give the same wait.
func TestFallbackHoldAndStatusAgree(t *testing.T) {
	r := newRig(t, 1)
	r.m.Add(2, update.ChannelStable, false)
	r.app.fellBack[2] = true
	r.step()
	r.held("fell back")
	const wait = "AI and accounts stay closed until a newer update is out"
	if h := r.g.Hold().Error(); h != "firstboot: I am updating first: "+wait {
		t.Fatalf("hold %q", h)
	}
	if s, want := r.g.Status(), "First start: update 2 did not start cleanly, so I went back to the version I shipped with. "+wait+"."; s != want {
		t.Fatalf("status %q", s)
	}
}

// REQ: UPD-3, CH-21
// The other held texts stay as they were.
func TestOtherHeldTextsUnchanged(t *testing.T) {
	r := newRig(t, 1)
	if s, want := r.g.Status(), "First start: checking for updates before AI and accounts can be connected."; s != want {
		t.Fatalf("starting %q", s)
	}
	r.online = false
	r.step()
	if s, want := r.g.Status(), "First start: I am offline, so I run the version I shipped with. I will update when I am next online."+waitText; s != want {
		t.Fatalf("offline %q", s)
	}
	if h, want := r.g.Hold().Error(), "firstboot: I am updating first: I am offline and have not updated yet; AI and accounts can be connected once I am online and updated"; h != want {
		t.Fatalf("offline hold %q", h)
	}
	r.online = true
	r.m.Add(2, update.ChannelStable, false)
	r.step()
	if s, want := r.g.Status(), "First start: updating to version 2. I will restart once."+waitText; s != want {
		t.Fatalf("installing %q", s)
	}
	if h, want := r.g.Hold().Error(), "firstboot: I am updating first: AI and accounts can be connected when the update finishes"; h != want {
		t.Fatalf("installing hold %q", h)
	}
}
