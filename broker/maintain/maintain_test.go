package maintain

// REQ: LOOP-11

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

// REQ: UPD-4
//
// TR2: maintain's channels. Stable (the default) soaks, fast takes fast
// releases, and pinned takes no automatic update but still surfaces
// security notices (the tests from here to TestPinnedBoxSaysNothingOfOrdinaryReleases).
// Changing the channel by text or the local UI is UPD-c.

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

func TestFastChannelTakesFastReleasesWithoutSoak(t *testing.T) {
	r := newRig(t)
	r.settings.Updates.Channel = update.ChannelFast
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
	r.settings.Updates.Channel = ChannelPinned
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
	r.settings.Updates.Channel = ChannelPinned
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
	r.settings.Updates.Channel = update.ChannelFast
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
	r.settings.Updates.Channel = update.ChannelFast
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
	if d := r.digest(); !strings.Contains(d, "has now been checked online") {
		t.Fatalf("digest: %q", d)
	}
}

func TestPreemptedCheckDoesNothing(t *testing.T) {
	r := newRig(t)
	r.settings.Updates.Channel = update.ChannelFast
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
	r.settings.Updates.Channel = update.ChannelFast
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

func TestStaleCheckSaysWhy(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.clk.add(72 * time.Hour)
	if st := r.l.Status(); !strings.Contains(st.Line, "check again soon") {
		t.Fatalf("busy box: %q", st.Line)
	}
	r.settings = loops.Settings{Paused: map[loops.Loop]bool{loops.Maintain: true}}
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "Reply UPDATE CHECKS ON") {
		t.Fatalf("Loop 3 off: %q", st.Line)
	}
	r.settings = loops.Settings{Off: true}
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "Reply LOOPS ON") {
		t.Fatalf("loops off: %q", st.Line)
	}
}

func TestChecksOffNeverCurrent(t *testing.T) {
	// Even a fresh check does not make a box with checks off current: it
	// will stop checking.
	r := newRig(t)
	r.tick()
	r.settings = loops.Settings{Off: true}
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "off") {
		t.Fatalf("checks off: %+v", st)
	}
}

func TestExpiredMentionsClock(t *testing.T) {
	r := newRig(t)
	r.clk.add(48 * time.Hour)
	r.tick()
	if st := r.l.Status(); !strings.Contains(st.Line, "clock") || strings.Contains(st.Line, "server") {
		t.Fatalf("expired: %q", st.Line)
	}
}

func TestDigestQuietWhileCurrent(t *testing.T) {
	r := newRig(t)
	r.tick()
	if d := r.digest(); !strings.Contains(d, "up to date") {
		t.Fatalf("first digest after becoming current: %q", d)
	}
	r.clk.add(24 * time.Hour)
	r.refresh()
	r.tick()
	if d := r.digest(); d != "" {
		t.Fatalf("still current, nothing changed: %q", d)
	}
	r.online = false
	if d := r.digest(); !strings.Contains(d, "offline") {
		t.Fatalf("not current: %q", d)
	}
	r.online = true
	if d := r.digest(); !strings.Contains(d, "up to date") {
		t.Fatalf("current again: %q", d)
	}
}

func TestApprovalLineSaysWhenAsked(t *testing.T) {
	r := newRig(t)
	r.settings.Updates.Channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	if st := r.l.Status(); !strings.Contains(st.Line, "waiting for your approval since Mon 5 Oct") {
		t.Fatalf("approval line: %q", st.Line)
	}
}

func TestSoakCountsFromFirstSightOnFast(t *testing.T) {
	r0 := newRig(t)
	r0.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r0.tick()
	if len(r0.p.proposed()) != 0 {
		t.Fatal("stable box took a fast release")
	}

	// A stable box notes a release when it reaches fast, so its promotion
	// to stable does not start a second 7-day wait.
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	r.clk.add(7 * 24 * time.Hour)
	r.refresh()
	// Maintainers promote it: stable release 3 with the same image.
	r.promote(2, 3)
	r.attest()
	r.tick()
	got := r.p.proposed()
	if len(got) != 1 || got[0].Version() != "3" {
		t.Fatalf("after 7 days on fast: %+v", got)
	}
}

func TestClockBackwardsNotCurrent(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.clk.add(-2 * time.Hour)
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "clock") {
		t.Fatalf("clock went back: %+v", st)
	}
	if ok, _ := r.tick(); !ok {
		t.Fatal("no fresh check after the clock went back")
	}
}

func TestOnlineRequired(t *testing.T) {
	r := newRig(t)
	if _, err := New(Config{Store: r.store, Pipeline: r.p, State: r.state}); err == nil {
		t.Fatal("New without Online: the wiring must say how the box knows it is online")
	}
}

func TestDriveConfirmedOnlyWhenNothingNewer(t *testing.T) {
	r := newRig(t)
	r.release(2, nil)
	res, err := r.store.Check(update.DirSource(r.repo.Dir), update.Options{Offline: true})
	r.must(err)
	r.must(r.store.Commit(res.Release))
	r.release(3, nil)
	r.tick()
	if d := r.digest(); strings.Contains(d, "checked online") || strings.Contains(d, "latest") {
		t.Fatalf("a newer release is out: %q", d)
	}
}

func TestPreemptedProposalNotShownAsAwaitingApproval(t *testing.T) {
	r := newRig(t)
	r.settings.Updates.Channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.p.err = context.Canceled
	ctx, cancel := context.WithCancel(context.Background())
	job, _ := r.l.Next(ctx, true)
	r.l.cfg.Attestations = func(context.Context, string) ([][]byte, error) { cancel(); return nil, nil }
	job.Run(ctx)
	if st := r.l.Status(); strings.Contains(st.Line, "approval") {
		t.Fatalf("preempted: %q", st.Line)
	}
}

func TestKeyRotationReportedOnce(t *testing.T) {
	r := newRig(t)
	r.tick()
	_, pub := keys(t, t.TempDir(), "targets-new", 1)
	r.must(r.repo.Rotate("targets", pub, nil, 0))
	r.must(r.repo.Sign("root", r.root[0]))
	r.must(r.repo.Sign("root", r.root[1]))
	r.must(r.repo.Publish(r.snap, r.ts))
	r.clk.add(24 * time.Hour)
	r.refresh()
	r.tick()
	if d := r.digest(); !strings.Contains(d, "signing keys changed to version 2") {
		t.Fatalf("digest: %q", d)
	}
	if d := r.digest(); strings.Contains(d, "signing keys") {
		t.Fatalf("said twice: %q", d)
	}
}

func TestWakeUnparksLoop3(t *testing.T) {
	// Three daily checks that find nothing park Loop 3 as dry (LOOP-3);
	// a Wake (network up, channel change, new release) brings it back.
	r := newRig(t)
	spare, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "spare.json"),
		MachineCap: meter.Limits{Calls: 50, Tokens: 500_000},
		OverallCap: loops.SpareLimits(loops.DefaultSpareCalls),
		Now:        r.clk.now,
	})
	r.must(err)
	s, err := loops.New(loops.Config{Store: &change.MemStore{}, Spare: spare, Sources: []loops.Source{r.l}, Now: r.clk.now})
	r.must(err)
	for d := 0; d < 3; d++ {
		if d > 0 {
			r.clk.add(24 * time.Hour)
			r.refresh()
		}
		s.Tick(context.Background())
	}
	if s.Share()[loops.Maintain] != 0 {
		t.Fatalf("not parked after 3 dry checks: %v", s.Share())
	}
	s.Wake()
	if s.Share()[loops.Maintain] == 0 {
		t.Fatal("Wake did not unpark Loop 3")
	}
}

func TestSecurityFixAutoStagesWithAllowListedAttestation(t *testing.T) {
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	ok, v := r.tick()
	got := r.p.proposed()
	if !ok || len(got) != 1 || !got[0].Security() || got[0].Version() != "2" {
		t.Fatalf("proposed %+v", got)
	}
	if v <= valueRelease {
		t.Fatalf("a security fix should count for more than an ordinary release: %v", v)
	}
}

func TestUnlistedAttestorsDoNotCount(t *testing.T) {
	// D6 (arbitrator ruling): only allow-listed attestors count, so a
	// signing-key holder cannot mint the "independent" test report. This
	// box's own key never counts, even if listed.
	for name, k := range map[string]func(r *rig) ed25519.PrivateKey{
		"unlisted": func(*rig) ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k },
		"own": func(r *rig) ed25519.PrivateKey {
			r.allow = append(r.allow, r.own.Public().(ed25519.PublicKey))
			return r.own
		},
	} {
		r := newRig(t)
		r.release(2, func(m *update.Manifest) { m.Security = true })
		r.attestWith(k(r))
		r.l = r.newLoop()
		r.tick()
		r.clk.add(time.Hour)
		r.tick()
		for _, v := range r.p.proposed() {
			if v.Security() {
				t.Fatalf("%s attestation counted", name)
			}
		}
	}
}

func TestSecurityFixGoesToOwnerWithNoAttestors(t *testing.T) {
	// Until an attestor exists, security fixes take the owner path (CH-3)
	// at once instead of waiting.
	r := newRig(t)
	r.allow = nil
	r.l = r.newLoop()
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.tick()
	got := r.p.proposed()
	if len(got) != 1 || got[0].Security() {
		t.Fatalf("proposed %+v", got)
	}
	if st := r.l.Status(); st.Current || !strings.Contains(st.Line, "Security update 2 needs your approval") {
		t.Fatalf("status: %q", st.Line)
	}
}

func TestSecurityFixWaitsADayForAttestorThenAsksOwner(t *testing.T) {
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.tick()
	if len(r.p.proposed()) != 0 {
		t.Fatal("did not wait for the listed attestor")
	}
	if !r.l.Urgent() {
		t.Fatal("not urgent while a security fix waits for its attestation")
	}
	if d := r.digest(); !strings.Contains(d, "Security update 2") || !strings.Contains(d, "independent") {
		t.Fatalf("digest: %q", d)
	}
	for h := 0; h < 24; h++ {
		r.clk.add(time.Hour)
		if h%12 == 11 {
			r.refresh()
		}
		r.tick()
	}
	got := r.p.proposed()
	if len(got) != 1 || got[0].Security() {
		t.Fatalf("after a day with no attestation: %+v", got)
	}
}

func TestFailedChecksNotParkedByScheduler(t *testing.T) {
	// LOOP-3 parks a loop after 3 runs without value; a failed check
	// retried hourly must not be parked for a day (arbitrator ruling).
	r := newRig(t)
	r.settings.Updates.Channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.mirrors = []update.Source{failSource{}}
	spare, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "spare.json"),
		MachineCap: meter.Limits{Calls: 50, Tokens: 500_000},
		OverallCap: loops.SpareLimits(loops.DefaultSpareCalls),
		Now:        r.clk.now,
	})
	r.must(err)
	s, err := loops.New(loops.Config{Store: &change.MemStore{}, Spare: spare, Sources: []loops.Source{r.l}, Now: r.clk.now})
	r.must(err)
	for h := 0; h < 6; h++ {
		if h == 4 {
			r.mirrors = []update.Source{update.DirSource(r.repo.Dir)}
		}
		s.Tick(context.Background())
		r.clk.add(time.Hour)
	}
	if got := r.p.proposed(); len(got) != 1 {
		t.Fatalf("source back at hour 4, proposed by hour 6: %+v (share %v)", got, s.Share())
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
		t.Fatal("stable release proposed with no listed attestation")
	}
	r.attest()
	r.tick()
	if len(r.p.proposed()) != 1 {
		t.Fatal("not proposed once attested")
	}
}

func TestStableReleaseSoakOnlyWithNoAttestors(t *testing.T) {
	// With no attestor listed, an ordinary stable release is offered to the
	// owner after its soak alone, rather than never.
	r := newRig(t)
	r.allow = nil
	r.l = r.newLoop()
	r.release(2, nil)
	for i := 0; i < 8 && len(r.p.proposed()) == 0; i++ {
		r.tick()
		r.clk.add(24 * time.Hour)
		r.refresh()
	}
	if len(r.p.proposed()) != 1 {
		t.Fatal("not offered after the soak")
	}
}

func TestUrgentWhileRetryDue(t *testing.T) {
	r := newRig(t)
	r.tick()
	if r.l.Urgent() {
		t.Fatal("urgent while current")
	}
	r2 := newRig(t)
	r2.mirrors = []update.Source{failSource{}}
	r2.tick()
	if !r2.l.Urgent() {
		t.Fatal("not urgent while a failed check is retried")
	}
}

func TestSecurityFixBehindNewerReleaseNotSoaked(t *testing.T) {
	// Security fix 2 is followed by ordinary release 3 before the box
	// checks: 3 carries the fix, so it is treated as a security update
	// (no soak) and, since 3 itself is not marked security and cannot
	// auto-stage, goes to the owner at once (security lens C2, PM1).
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.release(3, nil)
	r.tick()
	got := r.p.proposed()
	if len(got) != 1 || got[0].Version() != "3" || got[0].Security() {
		t.Fatalf("proposed %+v", got)
	}
	if st := r.l.Status(); !strings.Contains(st.Line, "Security update 3 needs your approval") {
		t.Fatalf("status: %q", st.Line)
	}
}

func TestDigestSaysWhoTestedAnAutoStagedSecurityFix(t *testing.T) {
	// D6 interim (Mark, 2026-10-05): while the allow-list holds only the
	// project's own test box, its report counts, and the digest says the
	// fix was tested by the project, not an independent tester, for as
	// long as it waits to install.
	for name, c := range map[string]struct {
		interim bool
		want    string
	}{
		"interim":     {true, "Security update 2 is ready and installs at the next quiet time. It was tested by the AgentOS project's own test box, not an independent tester."},
		"independent": {false, "Security update 2 is ready and installs at the next quiet time. An independent tester's report passed."},
	} {
		r := newRig(t)
		r.p.state = change.StateAdopted
		if c.interim {
			r.interim = r.allow // the test box key, pinned in the image
			r.l = r.newLoop()
		}
		r.release(2, func(m *update.Manifest) { m.Security = true })
		r.attest()
		r.tick()
		if got := r.p.proposed(); len(got) != 1 || !got[0].Security() {
			t.Fatalf("%s: proposed %+v", name, got)
		}
		if d := r.digest(); !strings.Contains(d, c.want) {
			t.Fatalf("%s: digest %q, want %q", name, d, c.want)
		}
	}
}

func TestComingBackOnlineChecksEvenWhenParked(t *testing.T) {
	// M3, UPD-8 (#53 L3 round 2): dry daily checks park Loop 3, its
	// resting state; coming back online still checks at once, and a
	// security fix found then keeps it offered (Urgent) and in the share.
	r := newRig(t)
	spare, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "spare.json"),
		MachineCap: meter.Limits{Calls: 50, Tokens: 500_000},
		OverallCap: loops.SpareLimits(loops.DefaultSpareCalls),
		Now:        r.clk.now,
	})
	r.must(err)
	s, err := loops.New(loops.Config{Store: &change.MemStore{}, Spare: spare, Sources: []loops.Source{r.l}, Now: r.clk.now})
	r.must(err)
	for d := 0; d < 3; d++ {
		if d > 0 {
			r.clk.add(24 * time.Hour)
			r.refresh()
		}
		s.Tick(context.Background())
	}
	if s.Share()[loops.Maintain] != 0 {
		t.Fatalf("not parked after 3 dry checks: %v", s.Share())
	}
	r.online = false
	for h := 0; h < 6; h++ {
		r.clk.add(time.Hour)
		s.Tick(context.Background())
	}
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.online = true
	r.clk.add(time.Minute)
	s.Tick(context.Background())
	if st := r.l.Status(); !strings.Contains(st.Line, "Security update 2") {
		t.Fatalf("back online but not checked: %q", st.Line)
	}
	if s.Share()[loops.Maintain] == 0 {
		t.Fatalf("an urgent Loop 3 shows no share: %v", s.Share())
	}
}

func TestListedReportHeldForOwnerNotCalledUntested(t *testing.T) {
	// #53 L3 round 2: a listed report passed, but the pipeline still asks
	// the owner; the line must not say there is no trusted report.
	r := newRig(t)
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.attest()
	r.tick()
	st := r.l.Status()
	if strings.Contains(st.Line, "no trusted independent test report") ||
		!strings.Contains(st.Line, "Security update 2 has been waiting for your approval since") {
		t.Fatalf("line %q", st.Line)
	}
}

func TestBackOnlineStaysDueUntilACheckRuns(t *testing.T) {
	// #53 L3 round 3: an offer the scheduler does not run (the box turned
	// busy) must not use up the check owed for coming back online.
	r := newRig(t)
	r.tick()
	r.online = false
	r.l.Next(context.Background(), true)
	r.online = true
	r.clk.add(time.Hour)
	if _, ok := r.l.Next(context.Background(), true); !ok {
		t.Fatal("not due on coming back online")
	}
	if _, ok := r.l.Next(context.Background(), true); !ok {
		t.Fatal("an offer that never ran used up the check")
	}
	if !r.l.Urgent() {
		t.Fatal("not urgent before the check ran")
	}
	r.tick()
	if _, ok := r.l.Next(context.Background(), true); ok {
		t.Fatal("still due after the check ran")
	}
}
