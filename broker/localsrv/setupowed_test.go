package localsrv

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CAP-9, REV-6, ONB-3

// owed is OpSetupProviders' owed answer for provider id, if any.
func owed(t *testing.T, r *setupRig, id string) *bool {
	t.Helper()
	var l localapi.SetupProviders
	if err := r.call(localapi.OpSetupProviders, nil, &l); err != nil {
		t.Fatal(err)
	}
	for _, p := range l.Providers {
		if p.ID == id {
			return p.Owed
		}
	}
	t.Fatalf("no provider %q", id)
	return nil
}

// #1544 (#1534 Security S2): the owner's no that the vault did not take
// is owed in agentosd's setup record, which survives a restart of the
// page and of agentosd; finish waits while it is owed, so setup cannot
// finish with the vault keeping the older yes.
func TestAnOwedAnswerHoldsFinishAcrossARestart(t *testing.T) {
	r, f := providersRig(t)
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "anthropic", Key: canaryKey}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic", OK: true}, nil); err != nil {
		t.Fatal(err)
	}
	if o := owed(t, r, "anthropic"); o != nil {
		t.Fatalf("a saved yes is owed: %v", *o)
	}
	f.privErr = errors.New("vault busy")
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic"}, nil); code(err) != localapi.ErrFailed {
		t.Fatalf("failed save answered %v", err)
	}
	if o := owed(t, r, "anthropic"); o == nil || *o {
		t.Fatalf("the failed no is not owed: %v", o)
	}
	r.start() // agentosd restarts; the page's memory is gone too
	r.s.cfg.Providers = f
	if o := owed(t, r, "anthropic"); o == nil || *o {
		t.Fatalf("the owed no did not survive a restart: %v", o)
	}
	if o := owed(t, r, "openai"); o != nil {
		t.Fatal("another provider is owed")
	}
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); code(err) != localapi.ErrAnswerOwed {
		t.Fatalf("finish with an answer owed: %v", err)
	}
	if r.vault.sealed || len(r.finished) != 0 || !f.private["anthropic"] {
		t.Fatal("finish sealed or finished, or the old yes changed")
	}
	// The retry's save clears the owed answer; finish then goes through
	// with the owner's no.
	f.privErr = nil
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic"}, nil); err != nil {
		t.Fatal(err)
	}
	if o := owed(t, r, "anthropic"); o != nil || f.private["anthropic"] {
		t.Fatalf("saved no still owed, or not recorded: %v", o)
	}
	r.start()
	r.s.cfg.Providers = f
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); err != nil {
		t.Fatal(err)
	}
	if !r.vault.sealed || len(r.finished) != 1 {
		t.Fatal("finish did not go through once nothing was owed")
	}
}

// failRecord fails every Save while fail is set.
type failRecord struct {
	FileRecord
	fail bool
}

func (f *failRecord) Save(r SetupRecord) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.FileRecord.Save(r)
}

// The answer is owed on disk before the vault is asked: a record that
// cannot be written asks the vault nothing. A clear that cannot be
// written leaves the answer owed and answers failed, so the page holds.
func TestAnAnswerIsOwedOnDiskBeforeTheVaultHearsIt(t *testing.T) {
	r, f := providersRig(t)
	rec := &failRecord{FileRecord: FileRecord{Path: r.path}, fail: true}
	r.s.cfg.Record = rec
	n := len(f.private)
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai", OK: true}, nil); code(err) != localapi.ErrFailed {
		t.Fatalf("unwritable record answered %v", err)
	}
	if len(f.private) != n {
		t.Fatal("the vault heard an answer the record did not owe")
	}
	if o := owed(t, r, "openai"); o != nil {
		t.Fatal("an answer never written is owed")
	}

	// The record takes the owed answer, then fails the clear.
	rec.fail = false
	h := &failAfterVault{fakeProviders: f, rec: rec}
	r.s.cfg.Providers = h
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai", OK: true}, nil); code(err) != localapi.ErrFailed {
		t.Fatalf("unwritable clear answered %v", err)
	}
	if !f.private["openai"] {
		t.Fatal("the vault did not record the yes")
	}
	rec.fail = false
	r.start()
	r.s.cfg.Providers = f
	if o := owed(t, r, "openai"); o == nil || !*o {
		t.Fatalf("an answer whose clear failed is not owed: %v", o)
	}
}

// failAfterVault fails the record's saves once the vault took an answer.
type failAfterVault struct {
	*fakeProviders
	rec *failRecord
}

func (h *failAfterVault) SetPrivateOK(provider string, ok bool) error {
	err := h.fakeProviders.SetPrivateOK(provider, ok)
	h.rec.fail = true
	return err
}

// A provider the vault does not list owes nothing: it is refused before
// the record is written, so it cannot hold setup open for good.
func TestAnUnknownProviderOwesNothing(t *testing.T) {
	r, f := providersRig(t)
	for _, id := range []string{"mistral", strings.Repeat("a", 4096)} {
		if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: id, OK: true}, nil); code(err) != localapi.ErrBadArgs {
			t.Fatalf("unknown provider answered %v", err)
		}
	}
	if b, err := os.ReadFile(r.path); err == nil && strings.Contains(string(b), "owed") {
		t.Fatalf("record owes an unknown provider: %s", b)
	}
	// A vault that refuses a listed provider leaves nothing owed either.
	f.privErr = ProviderRefused
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai", OK: true}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("refused provider answered %v", err)
	}
	if o := owed(t, r, "openai"); o != nil {
		t.Fatal("a refused answer is owed")
	}
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); err != nil {
		t.Fatalf("finish after refusals: %v", err)
	}
}

// A vault list that cannot be read owes nothing and asks the vault
// nothing more: the page keeps its own hold.
func TestAnUnreadableProviderListOwesNothing(t *testing.T) {
	r, f := providersRig(t)
	f.err = errors.New("vault down")
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai"}, nil); code(err) != localapi.ErrFailed {
		t.Fatalf("answered %v", err)
	}
	if _, err := os.Stat(r.path); err == nil {
		b, _ := os.ReadFile(r.path)
		if strings.Contains(string(b), "owed") {
			t.Fatalf("record owes with no vault list: %s", b)
		}
	}
}
