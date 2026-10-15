package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
	"github.com/google/go-tpm/tpm2/transport"
)

// REQ: CRED-9, A1

// inSetup puts the open vault in setup's state: enrollment opened by
// `init -setup`, and confirmed by the owner's code unless confirmed is
// false (confirmEnroll leaves the confirmed mark; sealEnroll removes it).
func (r *pcRig) inSetup(t *testing.T, confirmed bool) {
	t.Helper()
	if err := r.c.v.Put(SetupOpenName, KindSetupOpen, []byte(synthetic(t, "open-"))); err != nil {
		t.Fatal(err)
	}
	if confirmed {
		if err := r.c.putMark(ConfirmedName, KindConfirmed); err != nil {
			t.Fatal(err)
		}
	}
}

// §8.1: setup's default makes this PC trusted without a further code,
// because the owner confirmed the code generator on the box's own Wi-Fi
// page (CH-3's approval code plus local confirmation). The default holds
// only in that window: not before the confirmation, not while a newer
// seed waits, and never once finish has sealed enrollment (CRED-9: from
// then on trust needs a code).
func TestSetupHostTrustsThisPCOnlyAfterConfirmedEnrollment(t *testing.T) {
	r := newPCRig(t)
	if _, err := r.c.setupHost(true); err != errLocked {
		t.Fatalf("locked: %v", err)
	}
	r.unknownHostUnlock(t)
	if _, err := r.c.setupHost(true); err != errNotOpen {
		t.Fatalf("a vault not in setup: %v", err)
	}
	r.inSetup(t, false)
	if _, err := r.c.setupHost(true); err != errNotConfirmed {
		t.Fatalf("before the code generator is confirmed: %v", err)
	}
	if err := r.c.putMark(ConfirmedName, KindConfirmed); err != nil {
		t.Fatal(err)
	}
	if err := r.c.v.Put(PendingSeedName, vault.KindTOTPSeed, []byte(synthetic(t, "seed-"))); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.setupHost(true); err != errNotConfirmed {
		t.Fatalf("with a newer seed waiting: %v", err)
	}
	if r.tpmSlots(t) != 0 {
		t.Fatal("a slot was added outside the window")
	}
	if err := r.c.v.Delete(PendingSeedName); err != nil {
		t.Fatal(err)
	}

	name, err := r.c.setupHost(true)
	if err != nil || name != "Test PC" {
		t.Fatalf("setup's default: %q, %v", name, err)
	}
	if _, err := r.c.setupHost(true); err != nil || r.tpmSlots(t) != 1 {
		t.Fatalf("a second save: %v, %d slots", err, r.tpmSlots(t))
	}
	if !r.noted("this PC is now a trusted host") {
		t.Fatalf("owner not told: %q", r.notes)
	}

	ensureCard(t, r.c)
	if err := r.c.sealEnroll(); err != nil {
		t.Fatal(err)
	}
	for _, trusted := range []bool{true, false} {
		if _, err := r.c.setupHost(trusted); err != errEnrolled {
			t.Fatalf("after finish, setupHost(%v): %v", trusted, err)
		}
	}
	if r.tpmSlots(t) != 1 {
		t.Fatal("the slot changed after finish")
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("setup's trusted PC did not restart unattended: %v %q", r.phase(), r.notes)
	}
}

// "This is not my PC" leaves the PC untrusted, and takes back a slot an
// earlier answer in the same setup saved for it.
func TestSetupHostNotMineRemovesThisPC(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	r.inSetup(t, true)
	if _, err := r.c.setupHost(false); err != nil || r.tpmSlots(t) != 0 {
		t.Fatalf("not mine with no slot: %v, %d", err, r.tpmSlots(t))
	}
	if r.noted("a trusted host was removed") {
		t.Fatal("the owner is told of a removal that did not happen")
	}
	if _, err := r.c.setupHost(true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.setupHost(false); err != nil || r.tpmSlots(t) != 0 {
		t.Fatalf("not mine after trust: %v, %d slots", err, r.tpmSlots(t))
	}
	if !r.noted("a trusted host was removed") {
		t.Fatal("the owner is not told this PC's trust was taken back")
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("a PC the owner said is not theirs restarts unattended")
	}
}

// "Not mine" fails closed: when this PC's TPM cannot say which slot is
// its own, the answer is not saved, rather than reported saved while the
// slot an earlier answer made still opens the vault unattended (L3 B2).
func TestSetupHostNotMineFailsClosedWhenTheTPMIsSilent(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	r.inSetup(t, true)
	if _, err := r.c.setupHost(true); err != nil {
		t.Fatal(err)
	}
	r.c.host.(*tpmHost).openTPM = func() (transport.TPMCloser, error) { return nil, errors.New("tpm: device busy") }
	if _, err := r.c.setupHost(false); err == nil {
		t.Fatal("not mine saved while the slot stays")
	}
	if r.tpmSlots(t) != 1 {
		t.Fatalf("%d slots", r.tpmSlots(t))
	}
}

// REQ: CRED-9, HW-1

// VAULT-slot-decided-2 (#1741): "not mine" whose removal is decided before
// the slot change reports an error says the PC is no longer trusted, and
// tells the owner, rather than failing as if nothing changed.
func TestSetupHostNotMineAfterTheSlotIsDecided(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	r.inSetup(t, true)
	if _, err := r.c.setupHost(true); err != nil {
		t.Fatal(err)
	}
	r.notes = nil
	restore := vault.InjectSealFault(errors.New("input/output error"))
	defer restore()
	if _, err := r.c.setupHost(false); !errors.Is(err, errHostRemovedDecided) {
		t.Fatalf("not mine after the seal: %v", err)
	}
	restore()
	if !r.noted("a trusted host was removed (saving not finished)") {
		t.Fatalf("owner not told: %q", r.notes)
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("a PC the owner said is not theirs restarts unattended")
	}
}

// Without a TPM the PC cannot be trusted, which setup is told as such;
// "not my PC" has nothing to remove.
func TestSetupHostWithoutTPM(t *testing.T) {
	r := newPCRig(t)
	r.start(t, nil)
	r.unknownHostUnlock(t)
	r.inSetup(t, true)
	if _, err := r.c.setupHost(true); err != errNoTPM {
		t.Fatalf("trust without a TPM: %v", err)
	}
	if _, err := r.c.setupHost(false); err != nil {
		t.Fatalf("not mine without a TPM: %v", err)
	}
}

// The local UI saves setup's host step over the unlock socket: POST
// /setup/host answers the PC's name, a refusal its fixed reason, and a PC
// without a TPM says so in a field the page can word (CH-12).
func TestSetupHostOverTheUnlockSocket(t *testing.T) {
	r := newPCRig(t)
	call := func(method string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
		w := httptest.NewRecorder()
		unlockHandler(r.c).ServeHTTP(w, httptest.NewRequest(method, "/setup/host", rd))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := call("GET", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", code)
	}
	r.unknownHostUnlock(t)
	r.inSetup(t, false)
	if code, out := call("POST", map[string]bool{"trusted": true}); code != http.StatusConflict || out["error"] != errNotConfirmed.msg {
		t.Fatalf("before confirmation: %d %v", code, out)
	}
	r.c.putMark(ConfirmedName, KindConfirmed)
	if code, out := call("POST", map[string]bool{"trusted": true}); code != http.StatusOK || out["host"] != "Test PC" {
		t.Fatalf("trust: %d %v", code, out)
	}
	if code, out := call("POST", map[string]bool{"trusted": false}); code != http.StatusOK || r.tpmSlots(t) != 0 {
		t.Fatalf("not mine: %d %v", code, out)
	}
	r.start(t, nil)
	r.unknownHostUnlock(t)
	if code, out := call("POST", map[string]bool{"trusted": true}); code != http.StatusConflict || out["no_tpm"] != true {
		t.Fatalf("no TPM: %d %v", code, out)
	}
}
