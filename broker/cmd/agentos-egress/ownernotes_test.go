package main

// REQ: CRED-8, CRED-9

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
)

// egress K6: each notice the vault process already logs for the owner
// maps to one kind of a closed set (agentosd words it), or to none and
// stays in the log only.
func TestOwnerNoticesClassify(t *testing.T) {
	for s, want := range map[string]modelroute.OwnerNote{
		"wrong vault passphrase tried on the box's Wi-Fi":                                    {Kind: modelroute.NoteWrongPassphrase, N: 1},
		"wrong vault passphrase tried on the box's Wi-Fi (4 more since the last notice)":     {Kind: modelroute.NoteWrongPassphrase, N: 5},
		"7 more wrong vault passphrases were tried on the box's Wi-Fi since the last notice": {Kind: modelroute.NoteWrongPassphrase, N: 7},
		"vault passphrase accepted; waiting for a code-generator code":                       {Kind: modelroute.NoteUnlockPending},
		"The box unlock was started over with your card; the earlier one was cancelled.":     {Kind: modelroute.NoteUnlockRestarted},
		"The box unlock was started over twice more before it was unlocked.":                 {Kind: modelroute.NoteUnlockRestarted},
		"wrong code for a vault unlock":                                                      {Kind: modelroute.NoteWrongCode},
		"too many wrong codes for a vault unlock; key discarded":                             {Kind: modelroute.NoteCodeLockout},
		"vault unlock expired without a code; key discarded":                                 {Kind: modelroute.NoteUnlockExpired},
		"vault unlocked": {Kind: modelroute.NoteUnlocked},
		noteRolledBack:   {Kind: modelroute.NoteRolledBack},
		"This PC started the box in a way it hasn't before. If you didn't change anything, the drive may have been tampered with. Unlock only if you're sure.": {Kind: modelroute.NoteChangedBoot},
		"vault unlocked on this trusted host":                   {Kind: modelroute.NoteUnlockedTrusted},
		"vault unlocked on this trusted host with its boot PIN": {Kind: modelroute.NoteUnlockedTrusted},
		"wrong boot PIN on this trusted host":                   {Kind: modelroute.NoteWrongBootPIN},
		"this PC's TPM locked out after wrong boot PINs":        {Kind: modelroute.NoteBootPINLockout},
		noteTPMSilent:    {Kind: modelroute.NoteChipSilent},
		noteCounterReset: {Kind: modelroute.NoteCounterReset},
		noteSMSMissed:    {Kind: modelroute.NoteTextsMissed},
		"The box unlock was started over with your card; the earlier one was cancelled. It was started over twice more since the last notice.": {Kind: modelroute.NoteUnlockRestarted},
		"this PC is now a trusted host: Air12 Lite":                  {Kind: modelroute.NoteTrustedAdded},
		"this PC is now a trusted host, with a boot PIN: Air12 Lite": {Kind: modelroute.NoteTrustedAdded},
		"a trusted host was removed":                                 {Kind: modelroute.NoteTrustedRemoved},
		noteSIPReplaced:                                              {Kind: modelroute.NoteLineReplaced},
		noteSMSReplaced:                                              {Kind: modelroute.NoteLineReplaced},
		noteSIPRemoved:                                               {Kind: modelroute.NoteLineRemoved},
		noteSMSRemoved:                                               {Kind: modelroute.NoteLineRemoved},
	} {
		got, ok := classifyNote(s)
		if !ok || got != want {
			t.Errorf("%q: %+v %v, want %+v", s, got, ok, want)
		}
	}
	for _, s := range []string{"", "vault unlocked!", "vault opened on this trusted host but the model route failed to start", "wrong vault passphrase tried on the box's Wi-Fi (lots more since the last notice)", "x more wrong vault passphrases were tried on the box's Wi-Fi since the last notice"} {
		if got, ok := classifyNote(s); ok {
			t.Errorf("%q classified as %+v", s, got)
		}
	}
}

// The notices of a real unlock reach agentosd over the verify socket, in
// order, once each, while the vault is still locked too; the notes the
// custody makes in its unlock flow all classify, so a reworded notice
// fails here rather than going silent.
func TestUnlockNoticesReachAgentosd(t *testing.T) {
	r := newFastRig(t, true)
	notes := newOwnerNotes()
	r.c.notify = func(s string) { r.notes = append(r.notes, s); notes.add(s) }
	r.c.ownerNotes = notes
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock("not the passphrase"); err == nil {
		t.Fatal("wrong passphrase unlocked")
	}
	tk := r.unlock(t)
	got, dropped, err := v.OwnerNotes(context.Background())
	if err != nil || dropped != 0 || len(got) != 2 || got[0].Kind != modelroute.NoteWrongPassphrase || got[1].Kind != modelroute.NoteUnlockPending {
		t.Fatalf("while locked: %+v %d %v (notes %q)", got, dropped, err, r.notes)
	}
	if err := r.c.confirm(tk, "000000"); err == nil {
		t.Fatal("wrong code unlocked")
	}
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	got, _, err = v.OwnerNotes(context.Background())
	if err != nil || len(got) != 2 || got[0].Kind != modelroute.NoteWrongCode || got[1].Kind != modelroute.NoteUnlocked {
		t.Fatalf("after the unlock: %+v %v (notes %q)", got, err, r.notes)
	}
	if got, _, _ = v.OwnerNotes(context.Background()); len(got) != 0 {
		t.Fatalf("given twice: %+v", got)
	}
	for _, s := range r.notes {
		if _, ok := classifyNote(s); !ok {
			t.Errorf("unlock notice %q has no kind", s)
		}
	}
}

// The queue keeps the newest MaxOwnerNotes and counts what it dropped;
// a notice with no kind is not queued.
func TestOwnerNotesQueueIsBounded(t *testing.T) {
	q := newOwnerNotes()
	q.add("not a notice for the owner")
	for i := 0; i < modelroute.MaxOwnerNotes+5; i++ {
		q.add("wrong code for a vault unlock")
	}
	q.add("vault unlocked")
	got, dropped := q.take()
	if len(got) != modelroute.MaxOwnerNotes || dropped != 6 || got[len(got)-1].Kind != modelroute.NoteUnlocked {
		t.Fatalf("%d notes, %d dropped, last %+v", len(got), dropped, got[len(got)-1])
	}
	if got, dropped = q.take(); len(got) != 0 || dropped != 0 {
		t.Fatalf("not cleared: %d %d", len(got), dropped)
	}
	var none *ownerNotes
	none.add("vault unlocked")
	if got, _ := none.take(); got != nil {
		t.Fatal("nil queue gave notes")
	}
}
