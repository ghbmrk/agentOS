package maintain

// REQ: LOOP-11

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/update"
)

func TestIsLoop3Source(t *testing.T) {
	r := newRig(t)
	var src loops.Source = r.l
	if src.Loop() != loops.Maintain {
		t.Fatalf("loop %q", src.Loop())
	}
	if _, ok := src.(loops.Digester); !ok {
		t.Fatal("Loop 3 has digest lines")
	}
}

func TestUpToDateOnlyAfterOnlineCheck(t *testing.T) {
	r := newRig(t)
	if st := r.l.Status(); st.Current {
		t.Fatalf("current before any check: %+v", st)
	}
	if ok, v := r.tick(); !ok || v != 0 {
		t.Fatalf("first check: ran %v value %v", ok, v)
	}
	st := r.l.Status()
	if !st.Current || !strings.Contains(st.Line, "up to date") {
		t.Fatalf("after an online check with nothing new: %+v", st)
	}
	// Not due again until the daily interval passes.
	if ok, _ := r.tick(); ok {
		t.Fatal("checked twice in a row")
	}
	r.clk.add(23 * time.Hour)
	if ok, _ := r.tick(); ok {
		t.Fatal("checked before a day passed")
	}
	r.clk.add(time.Hour)
	r.refresh()
	if ok, _ := r.tick(); !ok {
		t.Fatal("no daily check")
	}
}

func TestOfflineNeverReportedCurrent(t *testing.T) {
	r := newRig(t)
	r.online = false
	if ok, _ := r.tick(); ok {
		t.Fatal("offered a check while offline")
	}
	st := r.l.Status()
	if st.Current || strings.Contains(st.Line, "up to date") || !strings.Contains(st.Line, "offline") {
		t.Fatalf("offline, never checked: %+v", st)
	}
	if d := r.digest(); strings.Contains(d, "up to date") || !strings.Contains(d, "offline") {
		t.Fatalf("digest: %q", d)
	}

	// Checked online, then the box goes offline: no longer current.
	r.online = true
	r.tick()
	if !r.l.Status().Current {
		t.Fatal("online check should be current")
	}
	r.online = false
	st = r.l.Status()
	if st.Current || strings.Contains(st.Line, "up to date") || !strings.Contains(st.Line, "offline") {
		t.Fatalf("offline after a good check: %+v", st)
	}
	if !strings.Contains(st.Line, "Mon 5 Oct") {
		t.Fatalf("offline line should say when it last checked: %q", st.Line)
	}

	// Back online: checked at once, without waiting for the daily interval.
	if ok, _ := r.tick(); ok {
		t.Fatal("offered a check while offline")
	}
	r.online = true
	r.clk.add(time.Hour)
	if ok, _ := r.tick(); !ok {
		t.Fatal("no check on coming back online")
	}
}

func TestUnreachableMirrorNotCurrent(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.mirrors = []update.Source{failSource{}}
	r.clk.add(24 * time.Hour)
	if ok, _ := r.tick(); !ok {
		t.Fatal("no check")
	}
	st := r.l.Status()
	if st.Current || strings.Contains(st.Line, "up to date") || !strings.Contains(st.Line, "could not check") {
		t.Fatalf("unreachable mirror: %+v", st)
	}
	// Retried within the hour, not a day later.
	r.clk.add(time.Hour)
	if ok, _ := r.tick(); !ok {
		t.Fatal("no retry after a failed check")
	}
}

func TestSecondMirrorUsedWhenFirstFails(t *testing.T) {
	r := newRig(t)
	r.mirrors = []update.Source{failSource{}, update.DirSource(r.repo.Dir)}
	r.tick()
	if st := r.l.Status(); !st.Current {
		t.Fatalf("a working second mirror: %+v", st)
	}
}

func TestFrozenMirrorNotCurrent(t *testing.T) {
	r := newRig(t)
	// The timestamp expires after a day; a mirror that stops refreshing
	// is frozen, and might be hiding a security fix (UPD-8).
	r.clk.add(48 * time.Hour)
	r.tick()
	st := r.l.Status()
	if st.Current || !strings.Contains(st.Line, "expired") {
		t.Fatalf("frozen mirror: %+v", st)
	}
}

func TestStaleCheckNotCurrent(t *testing.T) {
	r := newRig(t)
	r.tick()
	// The box was busy for days and Loop 3 never ran: the last check is
	// too old to call the box current.
	r.clk.add(72 * time.Hour)
	if st := r.l.Status(); st.Current || strings.Contains(st.Line, "up to date") {
		t.Fatalf("stale check: %+v", st)
	}
}

func TestSecurityFixWaitsForIndependentAttestation(t *testing.T) {
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Security = true })
	if ok, v := r.tick(); !ok || v != 0 {
		t.Fatalf("value %v without an attestation", v)
	}
	if len(r.p.proposed()) != 0 {
		t.Fatal("proposed a security fix with no independent attestation (D6)")
	}
	if d := r.digest(); !strings.Contains(d, "Security update 2") || !strings.Contains(d, "independent") {
		t.Fatalf("digest: %q", d)
	}
	if r.l.Status().Current {
		t.Fatal("current with a security fix outstanding")
	}
	// Security is prioritised: looked at again within the hour.
	r.attest()
	r.clk.add(time.Hour)
	ok, v := r.tick()
	if !ok {
		t.Fatal("no retry for a waiting security fix")
	}
	got := r.p.proposed()
	if len(got) != 1 || !got[0].Security() || got[0].Version() != "2" {
		t.Fatalf("proposed %+v", got)
	}
	if v <= 1 {
		t.Fatalf("a security fix should count for more than an ordinary release: %v", v)
	}
}

func TestOwnAttestationDoesNotCount(t *testing.T) {
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Security = true })
	other, _ := update.InitStore(t.TempDir(), r.rootJSON, 1)
	res, _ := other.Check(update.DirSource(r.repo.Dir), update.Options{Channel: update.ChannelFast, Now: r.clk.now})
	b, err := update.Attest(r.own, res.Release, update.Statement{Result: update.ResultPass, Channel: update.ChannelFast})
	r.must(err)
	r.atts = [][]byte{b}
	r.tick()
	if len(r.p.proposed()) != 0 {
		t.Fatal("this box's own attestation counted as independent")
	}
}

func TestStableReleaseSoaksBeforeProposal(t *testing.T) {
	r := newRig(t)
	r.release(2, nil)
	r.attest()
	r.tick()
	if len(r.p.proposed()) != 0 {
		t.Fatal("stable release proposed before its soak")
	}
	if d := r.digest(); !strings.Contains(d, "Update 2") {
		t.Fatalf("digest: %q", d)
	}
	for i := 0; i < 7; i++ {
		r.clk.add(24 * time.Hour)
		r.refresh()
		r.tick()
	}
	got := r.p.proposed()
	if len(got) != 1 || got[0].Version() != "2" || got[0].Security() {
		t.Fatalf("after the soak: %+v", got)
	}
}

func TestStableReleaseNeedsAnAttestationAfterSoak(t *testing.T) {
	r := newRig(t)
	r.release(2, nil)
	for i := 0; i < 8; i++ {
		r.tick()
		r.clk.add(24 * time.Hour)
		r.refresh()
	}
	if len(r.p.proposed()) != 0 {
		t.Fatal("stable release proposed with no independent passing attestation")
	}
	r.attest()
	r.tick()
	if len(r.p.proposed()) != 1 {
		t.Fatal("not proposed once attested")
	}
}

func TestFastChannelTakesFastReleasesWithoutSoak(t *testing.T) {
	r := newRig(t)
	r.channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	got := r.p.proposed()
	if len(got) != 1 || got[0].Version() != "2" {
		t.Fatalf("fast box: %+v", got)
	}
}

func TestStableBoxIgnoresFastRelease(t *testing.T) {
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	if len(r.p.proposed()) != 0 || !r.l.Status().Current {
		t.Fatalf("stable box and a fast release: %v", r.l.Status())
	}
}

func TestPinnedBoxGetsSecurityNoticeOnly(t *testing.T) {
	r := newRig(t)
	r.channel = ChannelPinned
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.tick()
	if len(r.p.proposed()) != 0 {
		t.Fatal("pinned box proposed an update")
	}
	d := r.digest()
	if !strings.Contains(d, "Security update 2") || !strings.Contains(d, "pinned") {
		t.Fatalf("digest: %q", d)
	}
	if r.l.Status().Current {
		t.Fatal("pinned box with a security fix out is not current")
	}
}

func TestPinnedBoxSaysNothingOfOrdinaryReleases(t *testing.T) {
	r := newRig(t)
	r.channel = ChannelPinned
	r.release(2, nil)
	r.tick()
	if d := r.digest(); strings.Contains(d, "Update 2") {
		t.Fatalf("digest: %q", d)
	}
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "pinned") {
		t.Fatalf("pinned status: %+v", st)
	}
}

func TestReleaseProposedOnce(t *testing.T) {
	r := newRig(t)
	r.channel = update.ChannelFast
	r.p.state = change.StateRejected
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	r.clk.add(24 * time.Hour)
	r.refresh()
	r.tick()
	if n := len(r.p.proposed()); n != 1 {
		t.Fatalf("proposed %d times", n)
	}
	// A restart keeps that: the rejection is persisted.
	r.l = r.newLoop()
	r.clk.add(24 * time.Hour)
	r.refresh()
	r.tick()
	if n := len(r.p.proposed()); n != 1 {
		t.Fatalf("proposed %d times after restart", n)
	}
}

func TestAwaitingOwnerReproposedAfterRestart(t *testing.T) {
	// The pipeline keeps proposals waiting for the owner in memory only
	// (change C9), so after a restart Loop 3 proposes again.
	r := newRig(t)
	r.channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	r.l = r.newLoop()
	if ok, _ := r.tick(); !ok {
		t.Fatal("no check after restart with a proposal pending")
	}
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("proposed %d times", n)
	}
}

func TestOfflineInstallNotCurrentUntilCheckedOnline(t *testing.T) {
	r := newRig(t)
	r.release(2, nil)
	// The owner installs release 2 from a drive (DEP-4, UPD-8).
	res, err := r.store.Check(update.DirSource(r.repo.Dir), update.Options{Offline: true})
	r.must(err)
	r.must(r.store.Commit(res.Release))
	r.online = false
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "drive") {
		t.Fatalf("offline drive install: %+v", st)
	}
	r.online = true
	r.tick()
	if st := r.l.Status(); !st.Current {
		t.Fatalf("after the online check: %+v", st)
	}
	if d := r.digest(); !strings.Contains(d, "confirmed") {
		t.Fatalf("digest: %q", d)
	}
}

func TestPreemptedCheckDoesNothing(t *testing.T) {
	r := newRig(t)
	r.channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	job, ok := r.l.Next(context.Background(), true)
	if !ok {
		t.Fatal("no job")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job.Run(ctx)
	if len(r.p.proposed()) != 0 {
		t.Fatal("cancelled job proposed")
	}
	if ok, _ := r.tick(); !ok || len(r.p.proposed()) != 1 {
		t.Fatal("cancelled work not offered again")
	}
}

func TestRunsUnderScheduler(t *testing.T) {
	r := newRig(t)
	r.channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	spare, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "spare.json"),
		MachineCap: meter.Limits{Calls: 50, Tokens: 500_000},
		OverallCap: loops.SpareLimits(loops.DefaultSpareCalls),
		Now:        r.clk.now,
	})
	r.must(err)
	busy := true
	s, err := loops.New(loops.Config{Store: &change.MemStore{}, Spare: spare, Sources: []loops.Source{r.l},
		Busy: func() bool { return busy }, Now: r.clk.now})
	r.must(err)
	if ran, _ := s.Tick(context.Background()); ran || len(r.p.proposed()) != 0 {
		t.Fatal("ran while the box was busy (LOOP-1)")
	}
	busy = false
	if ran, _ := s.Tick(context.Background()); !ran || len(r.p.proposed()) != 1 {
		t.Fatal("did not run in spare time")
	}
}
