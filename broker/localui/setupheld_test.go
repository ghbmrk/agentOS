package localui

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CAP-9, ONB-3

// ONB-private-save-fail s3 (#1554 Security R1): a plan sign-in records
// yes, then the owner's no is posted while agentosd's socket is down, so
// agentosd owes nothing. A reboot loses the page's memory; the hold in
// HeldStore's file still holds setup open with the owner's unticked box,
// and setup finishes only once a retry saves the no.
func TestAHeldNoOutlivesAReboot(t *testing.T) {
	r := newRig(t)
	held := filepath.Join(t.TempDir(), "unsaved.json")
	st := &MemStore{}
	r.srv = r.open(HeldStore{Inner: st, Path: held})
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	r.hooks.mu.Lock()
	r.hooks.down = true      // agentosd unreachable: no owed record either
	r.hooks.connected = true // the owner finishes signing in on the provider's site
	r.hooks.mu.Unlock()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	if len(r.hooks.owed) != 0 || !r.hooks.private["anthropic"] {
		t.Fatal("the rig recorded the no somewhere other than the page")
	}
	kept, _ := st.Load()
	kept.Unsaved = nil // the box rebooted: the page's memory is gone
	r.srv = r.open(HeldStore{Inner: &MemStore{s: kept}, Path: held})
	page := r.get("/setup")
	if r.srv.setup.done() || r.hooks.finishes != 0 {
		t.Fatal("setup finished on the old yes after a reboot")
	}
	f, ok := setupForms(t, page)["ai-private anthropic"]
	if !ok || strings.Contains(f, "checked") {
		t.Fatalf("no retry after the reboot, or the owner's no came back ticked:\n%s", page)
	}
	r.hooks.mu.Lock()
	r.hooks.down = false
	r.hooks.mu.Unlock()
	r.post("/setup/ai-private", url.Values{"provider": {"anthropic"}})
	if !r.srv.setup.done() || r.hooks.finishes != 1 || r.hooks.private["anthropic"] {
		t.Fatal("setup did not finish with the owner's no")
	}
}

// HeldStore keeps only the hold on disk: the owner's number and phone stay
// in memory (L18), a cleared hold stays cleared, and an unreadable hold
// fails the load rather than passing as none.
func TestHeldStoreKeepsOnlyTheHold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsaved.json")
	st := HeldStore{Inner: &MemStore{}, Path: path}
	if err := st.Save(SetupState{Owner: "+15550100", Device: "d", Host: true, Unsaved: map[string]bool{"openai": false}}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(b), "15550100") || strings.Contains(string(b), `"d"`) {
		t.Fatalf("file %q, %v", b, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	s, err := HeldStore{Inner: &MemStore{}, Path: path}.Load()
	if err != nil || s.Owner != "" || len(s.Unsaved) != 1 || s.Unsaved["openai"] {
		t.Fatalf("after reboot %+v, %v", s, err)
	}
	if err := st.Save(SetupState{Host: true}); err != nil {
		t.Fatal(err)
	}
	if s, err := (HeldStore{Inner: &MemStore{}, Path: path}).Load(); err != nil || s.Unsaved != nil {
		t.Fatalf("cleared hold came back: %+v, %v", s.Unsaved, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil {
		t.Fatal("an unreadable hold loaded as none")
	}
}
