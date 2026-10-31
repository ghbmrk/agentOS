package main

// REQ: REC-4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// cardKernel is rotKernel holding a card the unlock step made, named id;
// it shows the card on the real kernel's tap check.
type cardKernel struct {
	*rotKernel
	card []byte
	id   string
	err  error
}

func (k *cardKernel) RecoveryCardID(context.Context) (string, error) {
	*k.log = append(*k.log, "recoverycardid")
	if k.err != nil {
		return "", k.err
	}
	if k.card == nil {
		return "", kernelsock.ErrNoRecoveryCard
	}
	return k.id, nil
}

func (k *cardKernel) RecoveryCard(_ context.Context, c key.Cosign) ([]byte, error) {
	*k.log = append(*k.log, "recoverycard")
	if k.err != nil {
		return nil, k.err
	}
	if k.card == nil {
		return nil, kernelsock.ErrNoRecoveryCard
	}
	if err := k.k.RecoveryCardTap(k.id, c); err != nil {
		return nil, fmt.Errorf("%w (%v)", kernelsock.ErrRotateSig, err)
	}
	return bytes.Clone(k.card), nil
}

func (k *cardKernel) RecoveryCardDone(context.Context) error {
	*k.log = append(*k.log, "recoverycarddone")
	k.card = nil
	return k.err
}

type lostRig struct {
	*rotRig
	ck      *cardKernel
	l       *lostCard
	reboots int
	booted  time.Time
}

func newLostRig(t *testing.T, recipient string) *lostRig {
	r := &lostRig{rotRig: newRotRig(t, recipient)}
	r.ck = &cardKernel{rotKernel: r.rk}
	r.booted = time.Now().Add(-time.Hour)
	dir := t.TempDir()
	r.l = &lostCard{K: r.ck, S: newBackupSchedule(r.ck), Request: filepath.Join(dir, "recovery-request"), Shown: filepath.Join(dir, "recovery-card-shown"),
		Reboot: func(context.Context) error { r.reboots++; return nil }, Booted: func() time.Time { return r.booted }}
	return r
}

func (r *lostRig) filed() []byte {
	r.t.Helper()
	b, err := os.ReadFile(r.l.Request)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

// No request without a hardware key's tap over this change: a phone
// passkey's, a tap over another change or none gets no approval and files
// nothing. An anchor's tap files exactly the kernel's route-B approval
// (next ""), whole, root's alone, after one read; a box enrolled before e1
// asks from "". Begin only reads.
func TestLostCardFilesOnlyOnAHardwareKeysTap(t *testing.T) {
	old := strings.Repeat("ab", 16)
	r := newLostRig(t, old)
	ctx := context.Background()
	b, err := r.l.LostBegin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ch := key.Challenge(kernelsock.RotateMsg(old, "")); b.Old != old || !bytes.Equal(b.Challenge, ch[:]) {
		t.Fatalf("begun %+v", b)
	}
	if fmt.Sprint(r.log) != "[read]" {
		t.Fatalf("begin's calls %v", r.log)
	}
	phone := newAuthenticator(t)
	if err := r.enrol("s", phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := phone.get(t, b.Challenge)
	if err := r.l.Lost(ctx, ad, cd, sig); code(err) != localapi.ErrRecoveryNotAnchor {
		t.Fatalf("phone tap: %v", err)
	}
	card := key.Challenge(kernelsock.RotateMsg(old, strings.Repeat("cd", 16)))
	ad, cd, sig = r.anchors[0].get(t, card[:])
	if err := r.l.Lost(ctx, ad, cd, sig); code(err) != localapi.ErrRecoveryBadAssertion {
		t.Fatalf("a tap over a card-route change: %v", err)
	}
	if err := r.l.Lost(ctx, []byte{1}, []byte{2}, []byte{3}); code(err) != localapi.ErrRecoveryBadAssertion {
		t.Fatalf("no tap: %v", err)
	}
	if r.count("recoveryrotate") != 0 || r.filed() != nil {
		t.Fatalf("filed without a hardware key's tap: %v", r.log)
	}
	ad, cd, sig = r.anchors[1].get(t, b.Challenge)
	if err := r.l.Lost(ctx, ad, cd, sig); err != nil {
		t.Fatal(err)
	}
	if len(r.rk.approvals) != 1 || string(r.rk.approvals[0]) != "approval:"+old+">" || !bytes.Equal(r.filed(), r.rk.approvals[0]) {
		t.Fatalf("filed %q, approvals %q", r.filed(), r.rk.approvals)
	}
	if fi, err := os.Stat(r.l.Request); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("request file: %v %v", fi.Mode(), err)
	}

	pre := newLostRig(t, "")
	b, _ = pre.l.LostBegin(ctx)
	ad, cd, sig = pre.anchors[0].get(t, b.Challenge)
	if err := pre.l.Lost(ctx, ad, cd, sig); err != nil || string(pre.filed()) != "approval:>" {
		t.Fatalf("pre-e1 box: %v, filed %q", err, pre.filed())
	}
}

// The restart is offered only for a request filed at this boot; one the
// last restart left (the unlock step ignored it) reads as ignored and
// is withdrawn, not restarted for. Withdraw removes it.
func TestLostCardStateRestartAndWithdraw(t *testing.T) {
	r := newLostRig(t, "")
	ctx := context.Background()
	if st, err := r.l.LostState(ctx); err != nil || st != (localapi.RecoveryLostState{}) {
		t.Fatalf("nothing filed: %+v %v", st, err)
	}
	if err := r.l.Restart(ctx); code(err) != localapi.ErrRecoveryStale || r.reboots != 0 {
		t.Fatalf("restart with nothing filed: %v, %d", err, r.reboots)
	}
	b, _ := r.l.LostBegin(ctx)
	ad, cd, sig := r.anchors[0].get(t, b.Challenge)
	if err := r.l.Lost(ctx, ad, cd, sig); err != nil {
		t.Fatal(err)
	}
	if st, err := r.l.LostState(ctx); err != nil || !st.Filed || st.Ignored || st.Ready {
		t.Fatalf("filed: %+v %v", st, err)
	}
	if err := r.l.Restart(ctx); err != nil || r.reboots != 1 {
		t.Fatalf("restart: %v, %d", err, r.reboots)
	}
	// After a boot that did not carry it out, it is older than the boot.
	r.booted = time.Now().Add(time.Minute)
	if st, err := r.l.LostState(ctx); err != nil || !st.Filed || !st.Ignored {
		t.Fatalf("left by the last restart: %+v %v", st, err)
	}
	if err := r.l.Restart(ctx); code(err) != localapi.ErrRecoveryStale || r.reboots != 1 {
		t.Fatalf("restart for an ignored request: %v, %d", err, r.reboots)
	}
	if err := r.l.LostWithdraw(ctx); err != nil || r.filed() != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if err := r.l.LostWithdraw(ctx); err != nil {
		t.Fatalf("withdraw twice: %v", err)
	}
	r.l.Reboot = func(context.Context) error { return errors.New("systemctl: no bus") }
	r.booted = time.Now().Add(-time.Hour)
	b, _ = r.l.LostBegin(ctx)
	ad, cd, sig = r.anchors[0].get(t, b.Challenge)
	must(t, r.l.Lost(ctx, ad, cd, sig))
	if err := r.l.Restart(ctx); code(err) != localapi.ErrRecoveryUnavailable {
		t.Fatalf("a restart that failed: %v", err)
	}
}

// hold has the kernel hold a new card named id, the store's recipient now
// (the unlock step changed both), and returns its bits.
func (r *lostRig) hold(id string, b byte) []byte {
	bits := bytes.Repeat([]byte{b}, localapi.RecoveryCardLen)
	r.ck.card, r.ck.id, r.rk.recipient = bytes.Clone(bits), id, id
	return bits
}

// show taps anchor over the card's challenge and returns the card.
func (r *lostRig) show(anchor int) (localapi.RecoveryLostCard, error) {
	r.t.Helper()
	ctx := context.Background()
	b, err := r.l.LostCardBegin(ctx)
	if err != nil {
		return localapi.RecoveryLostCard{}, err
	}
	ad, cd, sig := r.anchors[anchor].get(r.t, b.Challenge)
	return r.l.LostCard(ctx, ad, cd, sig)
}

// MIG-4-recovery-r4c (#4128): the card the kernel holds reaches the page
// only on a hardware key's tap over its own ID. Begin names the card and
// reads no bits; a phone passkey's tap is refused before the kernel is
// asked for the bits, a tap over another card's challenge or none is a bad
// assertion; an anchor's tap answers the bits and the ID, and the shown
// file names that card, root's alone. Revert mutant: LostCard skipping
// tapper (the phone's tap answers bits).
func TestLostCardShowsOnlyOnAHardwareKeysTap(t *testing.T) {
	id := strings.Repeat("ab", 16)
	r := newLostRig(t, "")
	ctx := context.Background()
	bits := r.hold(id, 0x3c)
	b, err := r.l.LostCardBegin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ch := key.Challenge(kernelsock.CardMsg(id)); b.ID != id || !bytes.Equal(b.Challenge, ch[:]) {
		t.Fatalf("begun %+v", b)
	}
	phone := newAuthenticator(t)
	if err := r.enrol("s", phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := phone.get(t, b.Challenge)
	if got, err := r.l.LostCard(ctx, ad, cd, sig); code(err) != localapi.ErrRecoveryNotAnchor || got.Card != nil {
		t.Fatalf("phone tap: %x, %v", got.Card, err)
	}
	other := key.Challenge(kernelsock.CardMsg(strings.Repeat("cd", 16)))
	ad, cd, sig = r.anchors[0].get(t, other[:])
	if _, err := r.l.LostCard(ctx, ad, cd, sig); code(err) != localapi.ErrRecoveryBadAssertion {
		t.Fatalf("a tap over another card: %v", err)
	}
	if _, err := r.l.LostCard(ctx, []byte{1}, []byte{2}, []byte{3}); code(err) != localapi.ErrRecoveryBadAssertion {
		t.Fatalf("no tap: %v", err)
	}
	if r.count("recoverycard") != 0 || r.l.readShown() != (shown{}) {
		t.Fatalf("asked for the bits without a hardware key's tap: %v", r.log)
	}
	got, err := r.show(1)
	if err != nil || !bytes.Equal(got.Card, bits) || got.ID != id {
		t.Fatalf("card %+v %v", got, err)
	}
	if fi, err := os.Stat(r.l.Shown); err != nil || fi.Mode().Perm() != 0o600 || r.l.readShown() != (shown{ID: id}) {
		t.Fatalf("shown file: %v %v %+v", fi.Mode(), err, r.l.readShown())
	}
}

// After the restart the card the kernel holds reaches the page and its
// confirm wipes it and records the confirm; a kernel that restarted
// before (it holds none) is ErrRecoveryNoCard.
func TestLostCardShownThenWiped(t *testing.T) {
	id := strings.Repeat("ab", 16)
	r := newLostRig(t, "")
	ctx := context.Background()
	bits := r.hold(id, 0x3c)
	if st, err := r.l.LostState(ctx); err != nil || st != (localapi.RecoveryLostState{Ready: true}) {
		t.Fatalf("ready: %+v %v", st, err)
	}
	if r.count("recoverycard") != 0 {
		t.Fatalf("the state read the bits: %v", r.log)
	}
	if got, err := r.show(0); err != nil || !bytes.Equal(got.Card, bits) {
		t.Fatalf("card %x %v", got.Card, err)
	}
	must(t, r.l.LostDone(ctx))
	if r.count("recoverycarddone") != 1 {
		t.Fatalf("calls %v", r.log)
	}
	if _, err := r.l.LostCardBegin(ctx); code(err) != localapi.ErrRecoveryNoCard {
		t.Fatalf("after the confirm: %v", err)
	}
	if st, err := r.l.LostState(ctx); err != nil || st != (localapi.RecoveryLostState{Shown: id, Confirmed: true, InEffect: true}) {
		t.Fatalf("after the confirm: %+v %v", st, err)
	}
	r.ck.err = kernelsock.ErrSetupOnly
	if _, err := r.l.LostCardBegin(ctx); code(err) != localapi.ErrRecoverySetup {
		t.Fatalf("setup-only kernel: %v", err)
	}
}

// MIG-4-recovery-r4e (#4160): once the kernel holds no card, the state
// names the last card a page showed and says whether it is in effect and
// confirmed. A restart before the confirm leaves it in effect,
// unconfirmed; a second round's card, made but never shown, supersedes it,
// which then reads as not in effect; nothing shown reads as nothing. A
// shown file that does not read as a record is none.
func TestLostCardStateNamesTheCardInEffect(t *testing.T) {
	first, second := strings.Repeat("ab", 16), strings.Repeat("cd", 16)
	r := newLostRig(t, "")
	ctx := context.Background()
	r.hold(first, 0x3c)
	if _, err := r.show(0); err != nil {
		t.Fatal(err)
	}
	r.ck.card = nil // the box restarted before the confirm
	if st, err := r.l.LostState(ctx); err != nil || st != (localapi.RecoveryLostState{Shown: first, InEffect: true}) {
		t.Fatalf("restarted before the confirm: %+v %v", st, err)
	}
	r.hold(second, 0x5a) // asked again; the next restart made another
	r.ck.card = nil      // and a restart lost it before it was shown
	if st, err := r.l.LostState(ctx); err != nil || st != (localapi.RecoveryLostState{Shown: first}) {
		t.Fatalf("superseded: %+v %v", st, err)
	}
	if err := os.WriteFile(r.l.Shown, []byte(`{"id":"../x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := r.l.LostState(ctx); err != nil || st != (localapi.RecoveryLostState{}) {
		t.Fatalf("a shown file out of shape: %+v %v", st, err)
	}
}

// No log line carries the approval or the card.
func TestLostCardLogsNoSecret(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	r := newLostRig(t, "")
	ctx := context.Background()
	b, _ := r.l.LostBegin(ctx)
	ad, cd, sig := r.anchors[0].get(t, b.Challenge)
	must(t, r.l.Lost(ctx, ad, cd, sig))
	must(t, r.l.Restart(ctx))
	r.hold(strings.Repeat("ab", 16), 0x3c)
	if _, err := r.show(0); err != nil {
		t.Fatal(err)
	}
	must(t, r.l.LostDone(ctx))
	out := buf.String()
	for _, line := range []string{LogLostFiled, LogLostRestart, LogLostShown, LogLostDone} {
		if !strings.Contains(out, line) {
			t.Errorf("no %q", line)
		}
	}
	if strings.Contains(out, "approval:") || strings.Contains(out, "3c3c") || strings.Contains(out, "<<<<") {
		t.Fatalf("a secret in the log: %q", out)
	}
}
