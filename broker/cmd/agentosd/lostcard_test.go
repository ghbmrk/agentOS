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

// cardKernel is rotKernel holding a card the unlock step made.
type cardKernel struct {
	*rotKernel
	card []byte
	err  error
}

func (k *cardKernel) RecoveryCard(context.Context) ([]byte, error) {
	*k.log = append(*k.log, "recoverycard")
	if k.err != nil {
		return nil, k.err
	}
	if k.card == nil {
		return nil, kernelsock.ErrNoRecoveryCard
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
	r.l = &lostCard{K: r.ck, S: newBackupSchedule(r.ck), Request: filepath.Join(t.TempDir(), "recovery-request"),
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

// After the restart the card the kernel holds reaches the page and its
// confirm wipes it; a kernel that restarted before (it holds none) is
// ErrRecoveryNoCard, so the page tells the owner to ask again.
func TestLostCardShownThenWiped(t *testing.T) {
	r := newLostRig(t, "")
	ctx := context.Background()
	bits := bytes.Repeat([]byte{0x3c}, localapi.RecoveryCardLen)
	r.ck.card = bytes.Clone(bits)
	if st, err := r.l.LostState(ctx); err != nil || !st.Ready || st.Filed {
		t.Fatalf("ready: %+v %v", st, err)
	}
	if got, err := r.l.LostCard(ctx); err != nil || !bytes.Equal(got, bits) {
		t.Fatalf("card %x %v", got, err)
	}
	must(t, r.l.LostDone(ctx))
	if r.count("recoverycarddone") != 1 {
		t.Fatalf("calls %v", r.log)
	}
	if _, err := r.l.LostCard(ctx); code(err) != localapi.ErrRecoveryNoCard {
		t.Fatalf("after the confirm: %v", err)
	}
	if st, err := r.l.LostState(ctx); err != nil || st.Ready {
		t.Fatalf("after the confirm: %+v %v", st, err)
	}
	r.ck.err = kernelsock.ErrSetupOnly
	if _, err := r.l.LostCard(ctx); code(err) != localapi.ErrRecoverySetup {
		t.Fatalf("setup-only kernel: %v", err)
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
	r.ck.card = bytes.Repeat([]byte{0x3c}, localapi.RecoveryCardLen)
	if _, err := r.l.LostCard(ctx); err != nil {
		t.Fatal(err)
	}
	must(t, r.l.LostDone(ctx))
	out := buf.String()
	for _, line := range []string{LogLostFiled, LogLostRestart, LogLostDone} {
		if !strings.Contains(out, line) {
			t.Errorf("no %q", line)
		}
	}
	if strings.Contains(out, "approval:") || strings.Contains(out, "3c3c") || strings.Contains(out, "<<<<") {
		t.Fatalf("a secret in the log: %q", out)
	}
}
