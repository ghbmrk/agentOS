package main

// REQ: BAK-1, BAK-2, HW-17

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// The real kernel's destinations behind the owner seam, as kernelsock
// answers them. Backup writes one verified backup per current destination
// at recipient "r1"; the kernel process's directory checks are not here.

func (k *testKernel) Backups(context.Context) (kernelsock.BackupsView, error) {
	if err := k.answer(nil); err != nil {
		return kernelsock.BackupsView{}, err
	}
	v := kernelsock.BackupsView{Recipient: "r1", Targets: []kernelsock.TargetView{}, Backups: slices.Clone(k.taken)}
	for _, t := range k.k.State().BackupTargets() {
		v.Targets = append(v.Targets, kernelsock.TargetView{Name: t.Name, Kind: t.Kind, Locator: t.Locator,
			AppendOnly: t.AppendOnly, Removed: t.Removed, Rewritable: !t.AppendOnly})
	}
	return v, nil
}

func (k *testKernel) Backup(ctx context.Context) ([]kernelsock.Taken, error) {
	v, err := k.Backups(ctx)
	if err != nil {
		return nil, err
	}
	var out []kernelsock.Taken
	for _, t := range current(v) {
		b := kernelsock.BackupView{Target: t.Name, BackupID: t.Name, Recipient: "r1", Created: time.Now().UnixMilli(), Verified: true}
		k.taken = append(k.taken, b)
		out = append(out, kernelsock.Taken{Target: t.Name, Backup: &b})
	}
	return out, nil
}

func (k *testKernel) BackupTarget(_ context.Context, t kernelsock.Target, c key.Cosign) error {
	if err := k.answer(nil); err != nil {
		return err
	}
	return targetTyped(k.answer(k.k.BackupTarget(time.Now().UnixMilli(), t, c)))
}

func (k *testKernel) Untarget(_ context.Context, name string) error {
	if err := k.answer(nil); err != nil {
		return err
	}
	return targetTyped(k.answer(k.k.Untarget(time.Now().UnixMilli(), name)))
}

// targetTyped is kernelsock's typing of the destination refusals, which
// TestBackupTargetReachesTheKernel holds on the real socket.
func targetTyped(err error) error {
	var r kernelsock.Refused
	if !errors.As(err, &r) {
		return err
	}
	for k, e := range map[error]error{kernel.ErrTargetSig: kernelsock.ErrTargetSig,
		kernel.ErrTargetExists: kernelsock.ErrTargetExists, kernel.ErrNoTarget: kernelsock.ErrNoTarget} {
		if r.Text == k.Error() {
			return fmt.Errorf("%w (%w)", e, r)
		}
	}
	return err
}

type choiceRig struct {
	*passkeyRig
	c *backupChoice
}

func newChoiceRig(t *testing.T) *choiceRig {
	r := newPasskeyRig(t)
	return &choiceRig{r, &backupChoice{K: r.k, S: newBackupSchedule(r.k)}}
}

func drivePlace(name string, appendOnly bool) localapi.BackupPlace {
	return localapi.BackupPlace{Name: name, Kind: localapi.BackupKindDir, Locator: "/media/" + name + "/agentos", AppendOnly: appendOnly}
}

// add runs the page's add: Begin, then by's tap over its challenge.
func (r *choiceRig) add(p localapi.BackupPlace, by *authenticator) error {
	r.t.Helper()
	b, err := r.c.Begin(context.Background(), p)
	if err != nil {
		return err
	}
	ad, cd, sig := by.get(r.t, b.Challenge)
	return r.c.Add(context.Background(), p, b.N, ad, cd, sig)
}

func (r *choiceRig) added() int { return r.k.k.State().TargetsAdded() }

// Begin's challenge is over adding the place as destination n, n the
// destinations added so far, removed ones included; the kernel's
// unsigned check logs nothing.
func TestBackupBeginChallengesTheNextAdd(t *testing.T) {
	r := newChoiceRig(t)
	ctx := context.Background()
	if err := r.add(drivePlace("a", true), r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Remove(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	p := drivePlace("b", false)
	b, err := r.c.Begin(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	want := key.Challenge(key.CosignMsg(kernel.BackupTargetHash(1, kernel.BackupTarget{Name: "b", Kind: "dir", Locator: p.Locator})))
	if b.N != 1 || string(b.Challenge) != string(want[:]) {
		t.Fatalf("begun %+v", b)
	}
	if r.added() != 1 {
		t.Fatalf("Begin logged an add: %d", r.added())
	}
}

// An unsigned add, or one signed by a phone passkey, refuses with a page
// code and logs nothing; an anchor's logs it (BAK-1, HW-17).
func TestBackupAddNeedsAnAnchorTap(t *testing.T) {
	r := newChoiceRig(t)
	ctx := context.Background()
	p := drivePlace("a", true)
	b, err := r.c.Begin(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	// No tap: an assertion that is not one.
	if err := r.c.Add(ctx, p, b.N, []byte{1}, []byte{2}, []byte{3}); code(err) != localapi.ErrBackupBadAssertion {
		t.Fatalf("unsigned: %v", err)
	}
	// A key the kernel does not hold.
	stranger := newAuthenticator(t)
	ad, cd, sig := stranger.get(t, b.Challenge)
	if err := r.c.Add(ctx, p, b.N, ad, cd, sig); code(err) != localapi.ErrBackupBadAssertion {
		t.Fatalf("a stranger's tap: %v", err)
	}
	// A live phone passkey's tap.
	phone := newAuthenticator(t)
	if err := r.enrol("s1", phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	ad, cd, sig = phone.get(t, b.Challenge)
	if err := r.c.Add(ctx, p, b.N, ad, cd, sig); code(err) != localapi.ErrBackupNotAnchor {
		t.Fatalf("a phone's tap: %v", err)
	}
	// An anchor's tap over another place's challenge.
	other, _ := r.c.Begin(ctx, drivePlace("b", true))
	ad, cd, sig = r.anchors[1].get(t, other.Challenge)
	if err := r.c.Add(ctx, p, b.N, ad, cd, sig); code(err) != localapi.ErrBackupBadAssertion {
		t.Fatalf("a tap over another place: %v", err)
	}
	if r.added() != 0 {
		t.Fatalf("logged %d", r.added())
	}
	// The anchor's tap logs it, and the page lists it.
	ad, cd, sig = r.anchors[1].get(t, b.Challenge)
	if err := r.c.Add(ctx, p, b.N, ad, cd, sig); err != nil {
		t.Fatal(err)
	}
	ts := r.k.k.State().BackupTargets()
	if len(ts) != 1 || ts[0].BackupTarget != (kernel.BackupTarget{Name: "a", Kind: "dir", Locator: p.Locator, AppendOnly: true}) {
		t.Fatalf("targets %+v", ts)
	}
	c, err := r.c.List(ctx)
	if err != nil || len(c.Places) != 1 || c.Places[0].Name != "a" || !c.Places[0].AppendOnly {
		t.Fatalf("list %+v, %v", c, err)
	}
	// The same tap again is stale: the count moved on.
	if err := r.c.Add(ctx, p, b.N, ad, cd, sig); code(err) != localapi.ErrBackupStale {
		t.Fatalf("replayed: %v", err)
	}
}

// The page's other refusals: a name used before, a place the kernel cannot
// carry, a count the kernel has passed, and a setup-only kernel.
func TestBackupAddRefusalsAreThePagesCodes(t *testing.T) {
	r := newChoiceRig(t)
	ctx := context.Background()
	if err := r.add(drivePlace("a", true), r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Remove(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.Begin(ctx, drivePlace("a", true)); code(err) != localapi.ErrBackupNameTaken {
		t.Fatalf("a removed name again: %v", err)
	}
	for _, p := range []localapi.BackupPlace{
		{Name: "b", Kind: "dir", Locator: "media/b"},
		{Name: "b", Kind: "dir", Locator: "/media/../b"},
		{Name: ".b", Kind: "dir", Locator: "/media/b"},
		{Name: "b c", Kind: "dir", Locator: "/media/b"},
		{Name: "b", Kind: "dir", Locator: "/media/b​"},
	} {
		if _, err := r.c.Begin(ctx, p); code(err) != localapi.ErrBackupPlace {
			t.Errorf("%+v: %v", p, err)
		}
	}
	if _, err := r.c.Begin(ctx, localapi.BackupPlace{Name: "b", Kind: "s3", Locator: "/b"}); code(err) != localapi.ErrBadArgs {
		t.Fatalf("another kind: %v", err)
	}
	p := drivePlace("b", true)
	b, _ := r.c.Begin(ctx, p)
	ad, cd, sig := r.anchors[0].get(t, b.Challenge)
	if err := r.c.Add(ctx, p, b.N+1, ad, cd, sig); code(err) != localapi.ErrBackupStale {
		t.Fatalf("another count: %v", err)
	}
	// A kernel refusal's words never pass; one of the place is ErrBackupPlace.
	for text, want := range map[string]string{
		kernel.ErrTargetExists.Error():                                    localapi.ErrBackupNameTaken,
		kernel.ErrTargetSig.Error():                                       localapi.ErrBackupStale,
		kernel.ErrNoTarget.Error():                                        localapi.ErrBackupStale,
		kernel.ErrTarget.Error():                                          localapi.ErrBackupPlace,
		"run: I keep no backups here":                                     localapi.ErrBackupPlace,
		"run: that backup destination is not a directory I can reach: /x": localapi.ErrBackupPlace,
	} {
		r.k.err = kernelsock.Refused{Text: text}
		if err := r.c.Remove(ctx, "a"); code(err) != localapi.ErrBackupUnavailable {
			t.Errorf("a read refused with %q: %v", text, err)
		}
		if got := code(backupCode(targetTyped(r.k.err))); got != want {
			t.Errorf("%q: %s", text, got)
		}
	}
	if got := code(backupCode(errors.New("kernel: some other words"))); got != localapi.ErrBackupUnavailable {
		t.Errorf("an error not the kernel's refusal: %s", got)
	}
	r.k.err = kernelsock.ErrUnreachable
	if _, err := r.c.List(ctx); code(err) != localapi.ErrBackupUnavailable {
		t.Fatalf("unreachable: %v", err)
	}
	r.k.err = nil
	s := newChoiceRig(t)
	s.k = bootKernel(t, &kernel.MemStore{}, nil)
	s.c = &backupChoice{K: s.k, S: newBackupSchedule(s.k)}
	if _, err := s.c.List(ctx); code(err) != localapi.ErrBackupSetup {
		t.Fatalf("setup-only: %v", err)
	}
}

// Removing a place needs no tap; one removed already is done, one never
// listed is stale, and its name stays taken.
func TestBackupRemoveNeedsNoTap(t *testing.T) {
	r := newChoiceRig(t)
	ctx := context.Background()
	if err := r.add(drivePlace("a", false), r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Remove(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if ts := r.k.k.State().BackupTargets(); len(ts) != 1 || !ts[0].Removed {
		t.Fatalf("targets %+v", ts)
	}
	if err := r.c.Remove(ctx, "a"); err != nil {
		t.Fatalf("again: %v", err)
	}
	if err := r.c.Remove(ctx, "never"); code(err) != localapi.ErrBackupStale {
		t.Fatalf("unknown: %v", err)
	}
	c, _ := r.c.List(ctx)
	if len(c.Places) != 0 {
		t.Fatalf("a removed place listed: %+v", c.Places)
	}
}

// The notice shows on the choice page and the status page with no
// destination, names each place that keeps no old copies on the choice
// page, and goes after verified backups on two append-only places.
func TestBackupNoticeOnTheChoiceAndStatusPages(t *testing.T) {
	r := newChoiceRig(t)
	ctx := context.Background()
	c, err := r.c.List(ctx)
	if err != nil || !slices.Equal(c.Lines, []string{backupNoTarget}) || !slices.Equal(r.c.S.pageLines(), []string{backupNoTarget}) {
		t.Fatalf("no destination: %+v %q, %v", c, r.c.S.pageLines(), err)
	}
	for _, p := range []localapi.BackupPlace{drivePlace("a", false), drivePlace("b", true), drivePlace("c", false)} {
		if err := r.add(p, r.anchors[0]); err != nil {
			t.Fatal(err)
		}
	}
	r.c.S.tick(ctx) // the schedule takes each place's first backup
	c, _ = r.c.List(ctx)
	if !slices.Equal(c.Wipeable, []string{"a", "c"}) || !slices.Equal(c.Lines, []string{backupWipeable(2)}) {
		t.Fatalf("wipeable: %+v", c)
	}
	if got := r.c.S.pageLines(); !slices.Equal(got, []string{backupPageWipeable}) {
		t.Fatalf("status page: %q", got)
	}
	for _, p := range c.Places {
		if p.Newest == 0 {
			t.Fatalf("%s: no newest", p.Name)
		}
	}
	for _, n := range []string{"a", "c"} {
		if err := r.c.Remove(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	c, _ = r.c.List(ctx)
	if !slices.Equal(c.Lines, []string{backupOnePlace}) || len(c.Wipeable) != 0 {
		t.Fatalf("one append-only place: %+v", c)
	}
	if err := r.add(drivePlace("d", true), r.anchors[1]); err != nil {
		t.Fatal(err)
	}
	r.c.S.tick(ctx)
	c, _ = r.c.List(ctx)
	if len(c.Lines) != 0 || len(c.Wipeable) != 0 || len(r.c.S.pageLines()) != 0 {
		t.Fatalf("two append-only places verified: %+v %q", c, r.c.S.pageLines())
	}
}
