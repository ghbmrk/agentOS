package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// REQ: BAK-1, BAK-2

// backupFake is the kernel's backups as the owner socket shows them. A
// backup call writes one verified backup per current destination at the
// fake's recipient, unless fail names the outcome.
type backupFake struct {
	v       kernelsock.BackupsView
	now     func() time.Time
	calls   int
	fail    error  // the call's error
	failOne string // a Taken.Error for every destination
	unver   bool   // backups written but not verified
	unkept  bool   // the call claims verified backups the view never shows
	readErr error
}

func (k *backupFake) Backups(context.Context) (kernelsock.BackupsView, error) {
	if k.readErr != nil {
		return kernelsock.BackupsView{}, k.readErr
	}
	return k.v, nil
}

func (k *backupFake) Backup(context.Context) ([]kernelsock.Taken, error) {
	k.calls++
	if k.fail != nil {
		return nil, k.fail
	}
	var out []kernelsock.Taken
	for _, t := range current(k.v) {
		if k.failOne != "" {
			out = append(out, kernelsock.Taken{Target: t.Name, Error: k.failOne})
			continue
		}
		b := kernelsock.BackupView{Target: t.Name, BackupID: t.Name + itoaTest(k.calls), Recipient: k.v.Recipient,
			Created: k.now().UnixMilli(), Verified: !k.unver}
		if !k.unkept {
			k.v.Backups = append(k.v.Backups, b)
		}
		out = append(out, kernelsock.Taken{Target: t.Name, Backup: &b})
	}
	return out, nil
}

func itoaTest(n int) string { return string(rune('0' + n%10)) }

func driveAt(name string, appendOnly bool) kernelsock.TargetView {
	return kernelsock.TargetView{Name: name, Kind: "dir", Locator: "/mnt/" + name, AppendOnly: appendOnly, Rewritable: !appendOnly}
}

// rig is a schedule over a fake on a clock the test moves.
func rig(v kernelsock.BackupsView) (*backupSchedule, *backupFake, *time.Time) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	k := &backupFake{v: v, now: func() time.Time { return now }}
	s := newBackupSchedule(k)
	s.Now, s.started = k.now, now.Add(-backupStartGrace)
	return s, k, &now
}

// TestBackupLinesAreOwnerWorded: every STATUS line reads as one.
func TestBackupLinesAreOwnerWorded(t *testing.T) {
	for _, l := range []string{backupStarting, backupUnread, backupNoKey, backupNoTarget, backupNotYet, backupFailed, backupOnePlace,
		backupWipeable(1), backupWipeable(2), backupWipeable(12), backupLastFailed(time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC).UnixMilli()),
		backupPageLastFailed, backupPageWipeable} {
		if err := ownerWorded(l); err != nil {
			t.Errorf("%q: %v", l, err)
		}
	}
}

// The only-copy notice stands with no destination, before a backup is
// verified, and when the kernel has no recipient, and nothing is taken
// in those cases but the one with a destination.
func TestOnlyCopyNoticeUntilAVerifiedBackup(t *testing.T) {
	ctx := context.Background()

	s, k, _ := rig(kernelsock.BackupsView{Recipient: "r1"})
	s.tick(ctx)
	if got := s.onlyCopyNote(); got != backupNoTarget || k.calls != 0 {
		t.Fatalf("no destination: %q, %d calls", got, k.calls)
	}

	s, k, _ = rig(kernelsock.BackupsView{Targets: []kernelsock.TargetView{driveAt("a", true)}})
	s.tick(ctx)
	if got := s.onlyCopyNote(); got != backupNoKey || k.calls != 0 {
		t.Fatalf("no recipient: %q, %d calls", got, k.calls)
	}

	// Not read yet: the notice stands (never assumed away).
	s, _, _ = rig(kernelsock.BackupsView{})
	if got := s.onlyCopyNote(); got != backupUnread {
		t.Fatalf("unread: %q", got)
	}
	// Kernel not reached: still unread.
	s.K.(*backupFake).readErr = kernelsock.ErrUnreachable
	s.tick(ctx)
	if got := s.onlyCopyNote(); got != backupUnread {
		t.Fatalf("unreachable: %q", got)
	}
	// A setup-only kernel: no line, and no backup.
	s, k, _ = rig(kernelsock.BackupsView{})
	k.readErr = kernelsock.ErrSetupOnly
	s.tick(ctx)
	if l := s.lines(); len(l) != 0 || k.calls != 0 {
		t.Fatalf("setup-only: %q, %d calls", l, k.calls)
	}

	// A destination whose backup is unverified: the notice stays.
	s, k, _ = rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true)}})
	k.unver = true
	s.tick(ctx)
	if got := s.onlyCopyNote(); got != backupFailed || k.calls != 1 {
		t.Fatalf("unverified: %q, %d calls", got, k.calls)
	}
	// A pending or other-recipient backup that the kernel calls verified
	// still does not count.
	s, _, _ = rig(kernelsock.BackupsView{Recipient: "r2", Targets: []kernelsock.TargetView{driveAt("a", true)},
		Backups: []kernelsock.BackupView{{Target: "a", Recipient: "r1", Verified: true}, {Target: "a", Recipient: "r2", Verified: true, Pending: true}}})
	s.K.(*backupFake).fail = errors.New("down")
	s.tick(ctx)
	if got := s.onlyCopyNote(); got != backupFailed {
		t.Fatalf("old recipient or pending counted: %q", got)
	}
	// Nothing called yet and none counts: not yet checked.
	s, _, _ = rig(kernelsock.BackupsView{Recipient: "r2", Targets: []kernelsock.TargetView{driveAt("a", true)},
		Backups: []kernelsock.BackupView{{Target: "a", Recipient: "r1", Verified: true}}})
	s.read(ctx)
	if got := s.onlyCopyNote(); got != backupNotYet {
		t.Fatalf("before the first call: %q", got)
	}
	// A removed destination's verified backup does not count either.
	s, _, _ = rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{{Name: "a", Removed: true}, driveAt("b", true)},
		Backups: []kernelsock.BackupView{{Target: "a", Recipient: "r1", Verified: true}}})
	s.read(ctx)
	if got := s.onlyCopyNote(); got != backupNotYet {
		t.Fatalf("removed destination counted: %q", got)
	}
}

// One verified backup clears the notice; one place, or a place that is
// not append-only, each keeps a line; two verified backups on two
// append-only places leave none.
func TestNoticeOnePlaceAndWipeableLines(t *testing.T) {
	ctx := context.Background()
	s, _, _ := rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", false)}})
	s.tick(ctx)
	got := s.lines()
	if len(got) != 2 || got[0] != backupOnePlace || got[1] != backupWipeable(1) {
		t.Fatalf("one rewritable place: %q", got)
	}

	s, _, _ = rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true), driveAt("b", false)}})
	s.tick(ctx)
	if got := s.lines(); len(got) != 1 || got[0] != backupWipeable(1) {
		t.Fatalf("two places, one rewritable: %q", got)
	}

	s, _, _ = rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true), driveAt("b", true)}})
	s.tick(ctx)
	if got := s.lines(); len(got) != 0 {
		t.Fatalf("two append-only places, both verified: %q", got)
	}
	// One of the two failing to verify brings the one-place line back.
	s.view.Backups = s.view.Backups[:1]
	if got := s.lines(); len(got) != 1 || got[0] != backupOnePlace {
		t.Fatalf("one of two verified: %q", got)
	}
}

// One backup a day while a destination exists, and none in between.
func TestOneBackupADay(t *testing.T) {
	ctx := context.Background()
	s, k, now := rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true)}})
	s.tick(ctx)
	if k.calls != 1 {
		t.Fatalf("first backup not taken at once: %d", k.calls)
	}
	for range 23 {
		*now = now.Add(time.Hour)
		s.tick(ctx)
	}
	if k.calls != 1 {
		t.Fatalf("taken within the day: %d", k.calls)
	}
	*now = now.Add(time.Hour)
	s.tick(ctx)
	if k.calls != 2 {
		t.Fatalf("not taken after a day: %d", k.calls)
	}
	// A second destination added gets its first backup at once.
	k.v.Targets = append(k.v.Targets, driveAt("b", true))
	*now = now.Add(time.Minute)
	s.tick(ctx)
	if k.calls != 3 {
		t.Fatalf("new destination waited: %d", k.calls)
	}
	// With every destination removed, none is taken.
	k.v.Targets = []kernelsock.TargetView{{Name: "a", Removed: true}, {Name: "b", Removed: true}}
	*now = now.Add(48 * time.Hour)
	s.tick(ctx)
	if k.calls != 3 {
		t.Fatalf("taken with no current destination: %d", k.calls)
	}
}

// A recovery-key rotation changes the recipient: nothing counts, the
// notice returns at once, and a backup is taken at once (REC-4).
func TestRecipientChangeBacksUpAtOnce(t *testing.T) {
	ctx := context.Background()
	s, k, now := rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true), driveAt("b", true)}})
	s.tick(ctx)
	if k.calls != 1 || len(s.lines()) != 0 {
		t.Fatalf("first: %d calls, %q", k.calls, s.lines())
	}
	k.v.Recipient = "r2"
	*now = now.Add(time.Minute)
	s.read(ctx)
	if got := s.onlyCopyNote(); got != backupNotYet {
		t.Fatalf("after the change: %q", got)
	}
	s.tick(ctx)
	if k.calls != 2 || len(s.lines()) != 0 {
		t.Fatalf("not at once: %d calls, %q", k.calls, s.lines())
	}
}

// A failed or unverified backup is retried with a doubling backoff, and
// a verified one resets it.
func TestBackoffAfterAFailure(t *testing.T) {
	ctx := context.Background()
	s, k, now := rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true)}})
	k.failOne = "write failed"
	s.tick(ctx)
	if k.calls != 1 || s.onlyCopyNote() != backupFailed {
		t.Fatalf("first: %d calls, %q", k.calls, s.onlyCopyNote())
	}
	step := func(d time.Duration) {
		*now = now.Add(d)
		s.tick(ctx)
	}
	step(backupRetry - time.Second)
	if k.calls != 1 {
		t.Fatalf("retried inside the backoff: %d", k.calls)
	}
	step(time.Second)
	if k.calls != 2 {
		t.Fatalf("not retried after the backoff: %d", k.calls)
	}
	step(2*backupRetry - time.Second) // doubled
	if k.calls != 2 {
		t.Fatalf("backoff did not double: %d", k.calls)
	}
	step(time.Second)
	if k.calls != 3 {
		t.Fatalf("not retried after the doubled backoff: %d", k.calls)
	}
	k.failOne, k.fail = "", errors.New("kernel lost")
	step(4 * backupRetry)
	if k.calls != 4 || s.fails != 4 {
		t.Fatalf("call error not counted: %d calls, %d fails", k.calls, s.fails)
	}
	k.fail = nil
	step(8 * backupRetry)
	if k.calls != 5 || s.fails != 0 || s.onlyCopyNote() != "" {
		t.Fatalf("success did not reset: %d calls, %d fails, %q", k.calls, s.fails, s.onlyCopyNote())
	}
	if backoff(100) != backupRetryMax {
		t.Fatalf("backoff not capped: %v", backoff(100))
	}
}

// Release points from the reviews of #3392 (e4a), carried by e4b (#3390).

// A kernel that answered setup-only and then went unreachable reads as
// unread, not as silence (Security 6441653053 point 1).
func TestSetupOnlyThenUnreachableIsUnread(t *testing.T) {
	ctx := context.Background()
	s, k, _ := rig(kernelsock.BackupsView{})
	k.readErr = kernelsock.ErrSetupOnly
	s.tick(ctx)
	if l := s.lines(); len(l) != 0 {
		t.Fatalf("setup-only: %q", l)
	}
	k.readErr = kernelsock.ErrUnreachable
	s.tick(ctx)
	if got := s.onlyCopyNote(); got != backupUnread {
		t.Fatalf("unreachable after setup-only: %q", got)
	}
}

// A call that claims verified backups the read after does not show still
// backs off, so agentosd does not call backup every minute (Security
// 6441653053 point 2).
func TestBackoffHoldsWhenTheViewDisagrees(t *testing.T) {
	ctx := context.Background()
	s, k, now := rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true)}})
	k.unkept = true
	s.tick(ctx)
	if k.calls != 1 || s.fails != 1 {
		t.Fatalf("first: %d calls, %d fails", k.calls, s.fails)
	}
	*now = now.Add(backupCheckEvery)
	s.tick(ctx)
	if k.calls != 1 {
		t.Fatalf("called again inside the backoff: %d", k.calls)
	}
	// A read after the call that fails is no proof either.
	s, k, _ = rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true)}})
	k2 := &flakyAfterCall{backupFake: k}
	s.K = k2
	s.tick(ctx)
	if k.calls != 1 || s.fails != 1 {
		t.Fatalf("unread after the call: %d calls, %d fails", k.calls, s.fails)
	}
}

// flakyAfterCall answers reads until a backup call, then none.
type flakyAfterCall struct{ *backupFake }

func (k *flakyAfterCall) Backups(ctx context.Context) (kernelsock.BackupsView, error) {
	if k.calls > 0 {
		return kernelsock.BackupsView{}, kernelsock.ErrUnreachable
	}
	return k.backupFake.Backups(ctx)
}

// tookAll's guards, one case each (L3/Potency 6441659912 point 1).
func TestTookAllNeedsEveryBackupVerifiedAndFinished(t *testing.T) {
	ok := &kernelsock.BackupView{Verified: true}
	for name, c := range map[string]struct {
		taken []kernelsock.Taken
		want  bool
	}{
		"empty":                 {nil, false},
		"error beside a backup": {[]kernelsock.Taken{{Target: "a", Backup: ok, Error: "read-back differs"}}, false},
		"verified but pending":  {[]kernelsock.Taken{{Target: "a", Backup: &kernelsock.BackupView{Verified: true, Pending: true}}}, false},
		"no backup":             {[]kernelsock.Taken{{Target: "a"}}, false},
		"unverified":            {[]kernelsock.Taken{{Target: "a", Backup: &kernelsock.BackupView{}}}, false},
		"one of two failed":     {[]kernelsock.Taken{{Target: "a", Backup: ok}, {Target: "b", Error: "full"}}, false},
		"all verified":          {[]kernelsock.Taken{{Target: "a", Backup: ok}, {Target: "b", Backup: ok}}, true},
	} {
		if got := tookAll(c.taken); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// Once an older backup counts, a later failure keeps a line naming the
// newest that counts (L3/UX 6441659912 point 2); the status page has it in
// fixed words.
func TestALaterFailureKeepsALine(t *testing.T) {
	ctx := context.Background()
	s, k, now := rig(kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{driveAt("a", true), driveAt("b", true)}})
	s.tick(ctx)
	first := now.UnixMilli()
	if len(s.lines()) != 0 {
		t.Fatalf("after a verified backup: %q", s.lines())
	}
	*now = now.Add(backupDaily)
	k.failOne = "the drive is full"
	s.tick(ctx)
	if got := s.lines(); !slices.Equal(got, []string{backupLastFailed(first)}) {
		t.Fatalf("after a failure: %q", got)
	}
	if got := s.pageLines(); !slices.Equal(got, []string{backupPageLastFailed}) {
		t.Fatalf("status page after a failure: %q", got)
	}
	k.failOne = ""
	*now = now.Add(backoff(1))
	s.tick(ctx)
	if got := s.lines(); len(got) != 0 {
		t.Fatalf("after the retry took: %q", got)
	}
}

// In the first moments of a start the unread line says I keep trying;
// "restart me" is for a failure that persists (L3/UX 6441659912 point 3).
func TestUnreadAtStartKeepsTrying(t *testing.T) {
	ctx := context.Background()
	s, k, now := rig(kernelsock.BackupsView{})
	s.started = *now
	k.readErr = kernelsock.ErrUnreachable
	s.tick(ctx)
	if got := s.onlyCopyNote(); got != backupStarting {
		t.Fatalf("at start: %q", got)
	}
	*now = now.Add(backupStartGrace)
	if got := s.onlyCopyNote(); got != backupUnread {
		t.Fatalf("after the grace: %q", got)
	}
}
