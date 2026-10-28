package main

// REQ: REC-4, BAK-1, STO-2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// recoveryKernel over the real kernel's anchors and its rotation check
// (kernel.Kernel.RecoveryRotate, which checks the hardware key's cosign);
// the approval is a fake token, as the head key's signature is the
// kernel process's (kernel/proc). Every call is recorded in order.
type rotKernel struct {
	*testKernel
	recipient string
	log       *[]string
	switchErr []error // answered by SwitchRecipient in turn, then nil
	switched  [][]byte
	approvals [][]byte
	seen      []string // every argument the kernel was handed, as text
}

func (k *rotKernel) Backups(context.Context) (kernelsock.BackupsView, error) {
	if err := k.answer(nil); err != nil {
		return kernelsock.BackupsView{}, err
	}
	*k.log = append(*k.log, "read")
	return kernelsock.BackupsView{Recipient: k.recipient}, nil
}

func (k *rotKernel) RecoveryRotate(_ context.Context, next string, c key.Cosign) ([]byte, error) {
	*k.log = append(*k.log, "recoveryrotate")
	k.seen = append(k.seen, next, fmt.Sprintf("%x", c.Sig))
	if err := k.k.RecoveryRotate(time.Now().UnixMilli(), k.recipient, next, c); err != nil {
		return nil, fmt.Errorf("%w (%v)", kernelsock.ErrRotateSig, err)
	}
	a := []byte("approval:" + k.recipient + ">" + next)
	k.approvals = append(k.approvals, a)
	return a, nil
}

func (k *rotKernel) SwitchRecipient(_ context.Context, recipient, approval []byte) error {
	*k.log = append(*k.log, "recipient")
	k.seen = append(k.seen, fmt.Sprintf("%x %x", recipient, approval))
	if len(k.switchErr) > 0 {
		err := k.switchErr[0]
		k.switchErr = k.switchErr[1:]
		return err
	}
	k.switched = append(k.switched, append(append([]byte{}, recipient...), approval...))
	return nil
}

// fakeKeeper is the keeper's one-shot: it answers word and records what
// it was handed.
type fakeKeeper struct {
	log      *[]string
	word     string
	err      error
	factor   string
	secret   []byte
	next     []byte
	approval []byte
}

func (f *fakeKeeper) Rotate(_ context.Context, factor string, secret, next, approval []byte) (string, error) {
	*f.log = append(*f.log, "keeper")
	f.factor, f.secret, f.next, f.approval = factor, bytes.Clone(secret), bytes.Clone(next), bytes.Clone(approval)
	return f.word, f.err
}

type rotRig struct {
	*passkeyRig
	log    []string
	rk     *rotKernel
	keeper *fakeKeeper
	f      *recoveryFlow
	now    time.Time
}

func newRotRig(t *testing.T, recipient string) *rotRig {
	r := &rotRig{passkeyRig: newPasskeyRig(t), now: time.Unix(1_800_000_000, 0)}
	r.rk = &rotKernel{testKernel: r.k, recipient: recipient, log: &r.log}
	r.keeper = &fakeKeeper{log: &r.log, word: "ok"}
	r.f = &recoveryFlow{K: r.rk, S: newBackupSchedule(r.rk), Keeper: r.keeper, Now: func() time.Time { return r.now }}
	return r
}

// testNewKey is a synthetic new recovery key, never a real one.
var testNewKey = bytes.Repeat([]byte{0x5a}, localapi.RecoveryKeyLen)

// rotate runs the page's two steps: Begin, then by's tap over its
// challenge with the factor.
func (r *rotRig) rotate(by *authenticator, factor string, secret []byte) (localapi.RecoveryDone, error) {
	r.t.Helper()
	ctx := context.Background()
	b, err := r.f.Begin(ctx, testNewKey)
	if err != nil {
		return localapi.RecoveryDone{}, err
	}
	ad, cd, sig := by.get(r.t, b.Challenge)
	return r.f.Rotate(ctx, factor, secret, testNewKey, ad, cd, sig)
}

func (r *rotRig) count(call string) int {
	n := 0
	for _, c := range r.log {
		if c == call {
			n++
		}
	}
	return n
}

// Begin reads the kernel and asks nothing else: no approval and no
// keeper call before the owner taps (the page asks only after the card's
// confirm). Its challenge is over the kernel's recipient and the new
// key's, which it names for the page to show.
func TestRecoveryBeginOnlyReads(t *testing.T) {
	old := strings.Repeat("ab", 16)
	r := newRotRig(t, old)
	b, err := r.f.Begin(context.Background(), testNewKey)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := backup.RecipientFor(testNewKey)
	if b.Old != old || b.Next != want.ID() {
		t.Fatalf("begun %+v", b)
	}
	if ch := key.Challenge(kernelsock.RotateMsg(old, want.ID())); !bytes.Equal(b.Challenge, ch[:]) {
		t.Fatal("the challenge is not over this change")
	}
	if fmt.Sprint(r.log) != "[read]" {
		t.Fatalf("calls %v", r.log)
	}
	if _, err := r.f.Begin(context.Background(), testNewKey[:20]); code(err) != localapi.ErrBadArgs {
		t.Fatalf("a short key: %v", err)
	}
}

// Brief decision 6's order with a fake kernel and keeper: the tap is
// checked, the kernel approves, the keeper writes, the kernel switches,
// each on the same approval and the new key's recipient. A box enrolled
// before e1 (no recipient) rotates from "".
func TestRecoveryRotateRunsInDecisionSixOrder(t *testing.T) {
	r := newRotRig(t, "")
	d, err := r.rotate(r.anchors[1], localapi.RecoveryFactorPassphrase, []byte("synthetic words only"))
	if err != nil || !d.Switched {
		t.Fatalf("rotate: %+v %v", d, err)
	}
	if got := strings.Join(r.log, " "); got != "read read recoveryrotate keeper recipient read" {
		t.Fatalf("order %q", got)
	}
	rc, _ := backup.RecipientFor(testNewKey)
	a := r.rk.approvals[0]
	if string(a) != "approval:>"+rc.ID() {
		t.Fatalf("approval %q", a)
	}
	if !bytes.Equal(r.keeper.approval, a) || !bytes.Equal(r.keeper.next, testNewKey) || r.keeper.factor != "passphrase" {
		t.Fatalf("keeper got %q %x %q", r.keeper.approval, r.keeper.next, r.keeper.factor)
	}
	wire := append(append(append([]byte{}, rc.X...), rc.EK...), a...)
	if len(r.rk.switched) != 1 || !bytes.Equal(r.rk.switched[0], wire) {
		t.Fatal("the kernel was not switched to the new key's recipient on that approval")
	}
}

// A phone passkey's tap, a tap over another change, or a tap that is not
// one gets no approval and reaches no keeper.
func TestRecoveryNeedsAHardwareKeysTap(t *testing.T) {
	r := newRotRig(t, "")
	phone := newAuthenticator(t)
	if err := r.enrol("s", phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	b, err := r.f.Begin(ctx, testNewKey)
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := phone.get(t, b.Challenge)
	if _, err := r.f.Rotate(ctx, "recovery", testNewKey, testNewKey, ad, cd, sig); code(err) != localapi.ErrRecoveryNotAnchor {
		t.Fatalf("phone tap: %v", err)
	}
	other := key.Challenge(kernelsock.RotateMsg("", strings.Repeat("cd", 16)))
	ad, cd, sig = r.anchors[0].get(t, other[:])
	if _, err := r.f.Rotate(ctx, "recovery", testNewKey, testNewKey, ad, cd, sig); code(err) != localapi.ErrRecoveryBadAssertion {
		t.Fatalf("tap over another change: %v", err)
	}
	if _, err := r.f.Rotate(ctx, "recovery", testNewKey, testNewKey, []byte{1}, []byte{2}, []byte{3}); code(err) != localapi.ErrRecoveryBadAssertion {
		t.Fatalf("no tap: %v", err)
	}
	if _, err := r.f.Rotate(ctx, "pin", testNewKey, testNewKey, ad, cd, sig); code(err) != localapi.ErrBadArgs {
		t.Fatalf("another factor: %v", err)
	}
	if r.count("recoveryrotate") != 0 || r.count("keeper") != 0 {
		t.Fatalf("calls %v", r.log)
	}
}

// The kernel's recipient moved between the challenge and the tap: the
// kernel refuses the approval, and the keeper is not called.
func TestRecoveryStaleTapReachesNoKeeper(t *testing.T) {
	r := newRotRig(t, "")
	ctx := context.Background()
	b, err := r.f.Begin(ctx, testNewKey)
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := r.anchors[0].get(t, b.Challenge)
	// Read old before the tap's check, kernel old after: the recipient
	// the challenge named is gone by the time the kernel checks.
	r.f.K = &movingKernel{rotKernel: r.rk, to: strings.Repeat("ef", 16)}
	if _, err := r.f.Rotate(ctx, "recovery", testNewKey, testNewKey, ad, cd, sig); code(err) != localapi.ErrRecoveryStale {
		t.Fatalf("stale: %v", err)
	}
	if r.count("keeper") != 0 {
		t.Fatalf("calls %v", r.log)
	}
}

// movingKernel answers reads with the old recipient but checks the
// rotation against to, as when another rotation finished in between.
type movingKernel struct {
	*rotKernel
	to string
}

func (k *movingKernel) RecoveryRotate(ctx context.Context, next string, c key.Cosign) ([]byte, error) {
	was := k.recipient
	k.recipient = k.to
	defer func() { k.recipient = was }()
	return k.rotKernel.RecoveryRotate(ctx, next, c)
}

// Each keeper refusal is a fixed code, and the kernel is not switched.
func TestRecoveryKeeperRefusalsSwitchNothing(t *testing.T) {
	for word, want := range map[string]string{
		"factor": localapi.ErrRecoveryFactor, "stale": localapi.ErrRecoveryStale, "approval": localapi.ErrRecoveryStale,
		"busy": localapi.ErrRecoveryBusy, "request": localapi.ErrRecoveryUnavailable, "store": localapi.ErrRecoveryUnavailable,
		"": localapi.ErrRecoveryUnavailable, "ok please": localapi.ErrRecoveryUnavailable,
	} {
		r := newRotRig(t, "")
		r.keeper.word = word
		if _, err := r.rotate(r.anchors[0], "recovery", testNewKey); code(err) != want {
			t.Errorf("%q: %v", word, err)
		}
		if r.count("recipient") != 0 {
			t.Errorf("%q switched the kernel", word)
		}
	}
	r := newRotRig(t, "")
	r.keeper.err = errors.New("dial unix: no such file")
	if _, err := r.rotate(r.anchors[0], "recovery", testNewKey); code(err) != localapi.ErrRecoveryUnavailable || r.count("recipient") != 0 {
		t.Fatalf("no keeper: %v %v", err, r.log)
	}
}

// A switch the kernel did not take after the keeper's write (a crash, a
// kernel restarting) is retried with the same approval until it takes; one
// past the approval's time is dropped without asking (the kernel's next
// start reads the recipient from the store).
func TestRecoverySwitchIsRetriedAfterTheKeepersWrite(t *testing.T) {
	r := newRotRig(t, "")
	r.rk.switchErr = []error{kernelsock.ErrUnreachable, kernelsock.ErrLost}
	d, err := r.rotate(r.anchors[0], "recovery", testNewKey)
	if err != nil || d.Switched {
		t.Fatalf("rotate: %+v %v", d, err)
	}
	ctx := context.Background()
	if r.f.retry(ctx) || len(r.rk.switched) != 0 {
		t.Fatal("the second failure switched")
	}
	if !r.f.retry(ctx) || len(r.rk.switched) != 1 {
		t.Fatal("the retry did not switch")
	}
	rc, _ := backup.RecipientFor(testNewKey)
	if want := append(append(append([]byte{}, rc.X...), rc.EK...), r.rk.approvals[0]...); !bytes.Equal(r.rk.switched[0], want) {
		t.Fatal("the retry used another recipient or approval")
	}
	if n := r.count("recipient"); !r.f.retry(ctx) || r.count("recipient") != n {
		t.Fatal("a switch done is asked again")
	}

	r = newRotRig(t, "")
	r.rk.switchErr = []error{kernelsock.ErrUnreachable}
	if _, err := r.rotate(r.anchors[0], "recovery", testNewKey); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(recoveryApprovalFor)
	n := r.count("recipient")
	if r.f.retry(ctx) || r.count("recipient") != n || r.f.pending != nil {
		t.Fatal("a lapsed approval was retried or kept")
	}

	r = newRotRig(t, "")
	r.rk.switchErr = []error{kernelsock.ErrApprovalStale}
	if _, err := r.rotate(r.anchors[0], "recovery", testNewKey); err != nil {
		t.Fatal(err)
	}
	if r.f.pending != nil {
		t.Fatal("an approval the kernel calls stale is kept")
	}
}

// The factor and the new key reach the keeper alone: never a log line,
// the kernel, or a refusal, on success and on every failure path.
func TestRecoveryFactorReachesOnlyTheKeeper(t *testing.T) {
	canary := []byte("CANARY-FACTOR-r4a-synthetic")
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	forms := func(b []byte) []string {
		return []string{string(b), hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), fmt.Sprint(b)}
	}
	var seen, errs []string
	for _, setup := range []func(*rotRig){
		func(*rotRig) {},
		func(r *rotRig) { r.keeper.word = "factor" },
		func(r *rotRig) { r.keeper.err = errors.New("keeper gone") },
		func(r *rotRig) { r.rk.switchErr = []error{kernelsock.ErrLost} },
	} {
		r := newRotRig(t, "")
		setup(r)
		_, err := r.rotate(r.anchors[0], "passphrase", canary)
		r.f.retry(context.Background())
		if err != nil {
			errs = append(errs, err.Error())
		}
		seen = append(seen, r.rk.seen...)
		if !bytes.Equal(r.keeper.secret, canary) {
			t.Fatal("the keeper did not get the factor")
		}
	}
	all := logs.String() + strings.Join(seen, " ") + strings.Join(errs, " ")
	for _, f := range append(forms(canary), forms(testNewKey)...) {
		if strings.Contains(all, f) {
			t.Fatalf("a secret leaked: %q in %q", f, all)
		}
	}
}

// STATUS for a box with no recipient (enrolled before e1) names the
// Recovery key page, within STATUS's 100 characters.
func TestNoRecipientLineNamesTheRecoveryKeyPage(t *testing.T) {
	if !strings.Contains(backupNoKey, "Recovery key page") || len(backupNoKey) > 100 {
		t.Fatalf("%q", backupNoKey)
	}
}
