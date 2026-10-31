package run

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// The clerk's saves stopped after each privfile.WriteAtomic step, as a crash
// would (REV-CHK-save, #4191). A write stopped before its rename leaves the
// form before; one stopped at or after it leaves the new form. Either loads
// whole, and the next save goes through.
const (
	writeSteps = 6 // privfile.WriteAtomic's steps
	renamed    = 4 // the rename's step
)

func stopAt(i int) func(int) bool { return func(j int) bool { return j == i } }

// REQ: TN-gmail-registration-c, CLK-1
func TestARegistrationSaveStoppedAtEveryStepKeepsOneWhole(t *testing.T) {
	old := clerk.Registration{ID: "canary-old-client", Secret: "canary-old-secret"}
	next := clerk.Registration{ID: "canary-new-client", Secret: "canary-new-secret"}
	for i := 0; i < writeSteps; i++ {
		dir := shortDir(t)
		if err := saveReg(dir, testSealer(), old, nil); err != nil {
			t.Fatal(err)
		}
		if err := saveReg(dir, testSealer(), next, stopAt(i)); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: %v, want stopped", i, err)
		}
		want := old
		if i >= renamed {
			want = next
		}
		if r, ok := loadReg(dir, testSealer()); !ok || r != want {
			t.Fatalf("stopped after step %d: kept %q, %v; want %q", i, r.ID, ok, want.ID)
		}
		if err := saveReg(dir, testSealer(), next, nil); err != nil {
			t.Fatalf("save after a stop at step %d: %v", i, err)
		}
		if r, ok := loadReg(dir, testSealer()); !ok || r != next {
			t.Fatalf("after the next save: kept %q, %v", r.ID, ok)
		}
	}
}

// REQ: VRB-2, STO-2
func TestASeenSaveStoppedAtEveryStepKeepsOneWhole(t *testing.T) {
	const slot = "mail/canary-account"
	old := sealedSeen{Log: inbox.SeenLog{Since: "2026-07-01"}}
	next := sealedSeen{Log: inbox.SeenLog{Since: "2026-07-01", Seen: []inbox.Seen{{From: "shop@example.test", ID: "ab", Date: "2026-10-20"}}}, Told: true}
	for i := 0; i < writeSteps; i++ {
		dir := shortDir(t)
		if err := saveSeen(dir, testSealer(), slot, old, nil); err != nil {
			t.Fatal(err)
		}
		if err := saveSeen(dir, testSealer(), slot, next, stopAt(i)); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: %v, want stopped", i, err)
		}
		r, st := loadSeen(dir, testSealer(), slot)
		if st != seenLoaded || r.Told != (i >= renamed) || len(r.Log.Seen) != map[bool]int{false: 0, true: 1}[i >= renamed] {
			t.Fatalf("stopped after step %d: %+v (state %d); want the record %s the rename", i, r, st, map[bool]string{false: "before", true: "after"}[i >= renamed])
		}
		if err := saveSeen(dir, testSealer(), slot, next, nil); err != nil {
			t.Fatalf("save after a stop at step %d: %v", i, err)
		}
		if r, st := loadSeen(dir, testSealer(), slot); st != seenLoaded || !r.Told {
			t.Fatalf("after the next save: %+v (state %d)", r, st)
		}
	}
}

// REQ: VRB-2, D-141
func TestASendersSaveStoppedAtEveryStepKeepsOneWhole(t *testing.T) {
	const slot = "mail/canary-account"
	old := sealedSenders{Over: true}
	next := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"shop@example.test": 1}}}
	for i := 0; i < writeSteps; i++ {
		dir := shortDir(t)
		if err := saveSenders(dir, testSealer(), slot, old, nil); err != nil {
			t.Fatal(err)
		}
		if err := saveSenders(dir, testSealer(), slot, next, stopAt(i)); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: %v, want stopped", i, err)
		}
		r := loadSenders(dir, testSealer(), slot)
		if after := i >= renamed; r.Over == after || (r.Rec.Senders["shop@example.test"] == 1) != after {
			t.Fatalf("stopped after step %d: %+v; want the record %s the rename", i, r, map[bool]string{false: "before", true: "after"}[after])
		}
		if err := saveSenders(dir, testSealer(), slot, next, nil); err != nil {
			t.Fatalf("save after a stop at step %d: %v", i, err)
		}
		if r := loadSenders(dir, testSealer(), slot); r.Over || r.Rec.Senders["shop@example.test"] != 1 {
			t.Fatalf("after the next save: %+v", r)
		}
	}
}

// A Put whose write stopped leaves the running store as it was, and the
// restarted clerk's store holds the slot only if the write got to its rename.
//
// REQ: CLK-1, STO-2
func TestASecretsWriteStoppedAtEveryStepLeavesTheStoreWhole(t *testing.T) {
	for i := 0; i < writeSteps; i++ {
		dir := clerkDir(t)
		at := -1
		sec, err := openSecrets(dir, testSealer(), func(j int) bool { return j == at })
		if err != nil {
			t.Fatal(err)
		}
		if err := sec.Put("web", clerk.KindStatic, []byte("canary-old-secret")); err != nil {
			t.Fatal(err)
		}
		at = i
		if err := sec.Put("api", clerk.KindStatic, []byte("canary-new-secret")); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: %v, want stopped", i, err)
		}
		if sec.Has("api") || !sec.Has("web") {
			t.Fatalf("stopped after step %d: the running store changed", i)
		}
		re, err := OpenSecrets(dir, testSealer()) // the restarted clerk process
		if err != nil {
			t.Fatalf("stopped after step %d: %v", i, err)
		}
		if !re.Has("web") || re.Has("api") != (i >= renamed) {
			t.Fatalf("stopped after step %d: restarted store holds %d slots, api %v", i, re.Len(), re.Has("api"))
		}
		at = -1
		if err := sec.Put("api", clerk.KindStatic, []byte("canary-new-secret")); err != nil {
			t.Fatalf("put after a stop at step %d: %v", i, err)
		}
		if re, err := OpenSecrets(dir, testSealer()); err != nil || re.Len() != 2 {
			t.Fatalf("after the next put: %v", err)
		}
	}
}

// A setup whose settings write stopped after any step, as a crash would,
// leaves settings whose own slot opens to their own password (#2704): the
// account before until the rename, the new one after. A secret is rolled
// back only when the settings on disk do not name its account.
//
// REQ: CLK-1, CLK-2, STO-2
func TestMailSettingsWriteStoppedAtEveryStepSignsInWithItsOwnPassword(t *testing.T) {
	a := MailSettings{Address: "you@example.com", IMAP: "imap.a.test:993", SMTP: "smtp.a.test:465"}
	b := MailSettings{Address: "you@example.com", IMAP: "imap.b.test:993", SMTP: "smtp.b.test:465"}
	pass := map[MailSettings]string{a: "canary-account-A-pass", b: "canary-account-B-pass"}
	for i := 0; i < writeSteps; i++ {
		dir := shortDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := SetMail(dir, sec, a, pass[a]); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		mailMu.Lock()
		err = switchMail(dir, sec, b, raw, func() error { return sec.Put(slotOf(b), clerk.KindStatic, []byte(pass[b])) }, nil, stopAt(i))
		mailMu.Unlock()
		if !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: %v, want stopped", i, err)
		}
		want := a
		if i >= renamed {
			want = b
		}
		for _, run := range []string{"running", "restarted"} {
			if run == "restarted" {
				if sec, err = OpenSecrets(dir, testSealer()); err != nil {
					t.Fatal(err)
				}
			}
			s, err := readMail(dir)
			if err != nil || s != want {
				t.Fatalf("stopped after step %d (%s): settings for %s, %v; want %s", i, run, s.IMAP, err, want.IMAP)
			}
			l, err := sec.Login(slotOf(s), s.login())(context.Background())
			if err != nil || l.Secret != pass[s] {
				t.Fatalf("stopped after step %d (%s): settings for %s sign in with %q, %v; want their own password", i, run, s.IMAP, l.Secret, err)
			}
		}
		if err := SetMail(dir, sec, b, pass[b]); err != nil {
			t.Fatalf("setup after a stop at step %d: %v", i, err)
		}
		if s, err := readMail(dir); err != nil || s != b || sec.Len() != 1 {
			t.Fatalf("setup run again: %+v, %v, %d slots", s, err, sec.Len())
		}
	}
}
