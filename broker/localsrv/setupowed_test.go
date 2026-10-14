package localsrv

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

// recordOwed is the owed answers agentosd holds, read without the vault.
func recordOwed(r *setupRig) map[string]bool {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.rec.Owed
}

// #1554 Security B1: a no posted while the vault is down or locked is
// owed before the vault is asked even its list, stays owed when the list
// fails, and holds finish across a restart, with the vault down or up.
func TestANoPostedWhileTheVaultIsDownHoldsFinish(t *testing.T) {
	r, f := providersRig(t)
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic", OK: true}, nil); err != nil {
		t.Fatal(err)
	}
	f.err = errors.New("connection refused")
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic"}, nil); code(err) != localapi.ErrFailed {
		t.Fatalf("no with the vault down answered %v", err)
	}
	if o, ok := recordOwed(r)["anthropic"]; !ok || o {
		t.Fatalf("the no is not owed: %v", recordOwed(r))
	}
	f.err = EnrollNotOpen
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic"}, nil); code(err) != localapi.ErrEnrollUnavailable {
		t.Fatalf("no with the vault locked answered %v", err)
	}
	if o, ok := recordOwed(r)["anthropic"]; !ok || o {
		t.Fatalf("the no is not owed: %v", recordOwed(r))
	}
	r.start()
	r.s.cfg.Providers = f
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); code(err) != localapi.ErrAnswerOwed {
		t.Fatalf("finish with the vault down answered %v", err)
	}
	f.err = nil
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); code(err) != localapi.ErrAnswerOwed {
		t.Fatalf("finish with the vault up answered %v", err)
	}
	if r.vault.sealed || len(r.finished) != 0 || !f.private["anthropic"] {
		t.Fatal("finish sealed or finished, or the old yes changed")
	}
}

// An id the vault does not list, owed while the vault was down, does not
// hold finish once the vault lists its providers; and the record owes at
// most maxOwed ids.
func TestStrayOwedIdsDoNotHoldFinish(t *testing.T) {
	r, f := providersRig(t)
	r.enrollAndConfirm()
	f.err = errors.New("connection refused")
	for _, id := range []string{strings.Repeat("a", 65), "Mistral", "a b", "x\n"} {
		if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: id}, nil); code(err) != localapi.ErrBadArgs {
			t.Fatalf("%q answered %v", id, err)
		}
	}
	if len(recordOwed(r)) != 0 {
		t.Fatalf("an id not shaped like a provider is owed: %v", recordOwed(r))
	}
	for i := 0; i < maxOwed; i++ {
		id := fmt.Sprintf("stray-%d", i)
		if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: id}, nil); code(err) != localapi.ErrFailed {
			t.Fatalf("%s answered %v", id, err)
		}
	}
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "stray-x"}, nil); code(err) != localapi.ErrLimited {
		t.Fatalf("an id past the cap answered %v", err)
	}
	if n := len(recordOwed(r)); n != maxOwed {
		t.Fatalf("record owes %d ids", n)
	}
	// An id already owed can still be answered again at the cap.
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "stray-0", OK: true}, nil); code(err) != localapi.ErrFailed {
		t.Fatalf("an owed id at the cap answered %v", err)
	}
	f.err = nil
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); err != nil {
		t.Fatalf("stray ids held finish: %v", err)
	}
}

// Potency R2 (M7): an id the vault does not list never reaches the vault
// and is owed nothing, even when the vault would fail it otherwise than
// by refusing.
func TestAnUnlistedIdNeverReachesTheVault(t *testing.T) {
	r, f := providersRig(t)
	f.privErr = errors.New("vault busy")
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "mistral"}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("unlisted id answered %v", err)
	}
	if f.sets != 0 || len(recordOwed(r)) != 0 {
		t.Fatalf("vault asked %d times, owed %v", f.sets, recordOwed(r))
	}
}

// Potency R3 (M6): a refused retry puts back the answer owed before it.
func TestARefusedRetryKeepsTheEarlierOwedAnswer(t *testing.T) {
	r, f := providersRig(t)
	f.privErr = errors.New("vault busy")
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai"}, nil); code(err) != localapi.ErrFailed {
		t.Fatal(err)
	}
	f.privErr = ProviderRefused
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai", OK: true}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatal(err)
	}
	if o := owed(t, r, "openai"); o == nil || *o {
		t.Fatalf("the earlier no is not owed: %v", o)
	}
}

// Security R2 and Potency R4 (M8): two answers for one provider are taken
// one at a time, so a yes the vault takes cannot clear a later no that
// the vault failed.
func TestConcurrentAnswersCannotClearAnOwedNo(t *testing.T) {
	r, f := providersRig(t)
	r.enrollAndConfirm()
	entered, release := make(chan struct{}), make(chan struct{})
	f.setHook = func(_ string, ok bool) error {
		if ok {
			close(entered)
			<-release
			return nil
		}
		return errors.New("vault busy")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic", OK: true}, nil)
	}()
	<-entered
	go func() {
		defer wg.Done()
		r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "anthropic"}, nil)
	}()
	time.Sleep(100 * time.Millisecond) // the no reaches the vault unless serialized
	close(release)
	wg.Wait()
	if o := owed(t, r, "anthropic"); o == nil || *o {
		t.Fatalf("the failed no is not owed: %v", o)
	}
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); code(err) != localapi.ErrAnswerOwed {
		t.Fatalf("finish answered %v", err)
	}
}

// Security R2: once setup is closed, nothing more is owed or written.
func TestAClosedSetupOwesNothingMore(t *testing.T) {
	r, _ := providersRig(t)
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: ownerNumber}, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(r.path)
	no := false
	r.s.mu.Lock()
	err := r.s.setOwedLocked("openai", &no)
	r.s.mu.Unlock()
	if err != errSetupClosed {
		t.Fatalf("closed setup owed an answer: %v", err)
	}
	after, _ := os.ReadFile(r.path)
	if string(before) != string(after) || len(recordOwed(r)) != 0 {
		t.Fatal("closed setup changed its record")
	}
}

// Security R2: the providers list says what agentosd owes, not what the
// vault claims.
func TestTheProvidersListOwesOnlyWhatTheRecordOwes(t *testing.T) {
	r, f := providersRig(t)
	f.owedLie = true
	if o := owed(t, r, "openai"); o != nil {
		t.Fatalf("the vault's claim is owed: %v", *o)
	}
}
