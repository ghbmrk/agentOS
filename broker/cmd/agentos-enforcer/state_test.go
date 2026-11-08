package main

// REQ: KEY-7, STO-4

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRevokeUnsaved (#4751): a revocation the head store cannot save is
// in force for the run and the page says it was not saved, so the owner
// taps again; the tap after the journal recovers saves it.
func TestRevokeUnsaved(t *testing.T) {
	x, a := enrolled(t, true)
	addr := x.serve()
	journal := filepath.Join(x.dir, fileHeads)
	os.Remove(journal)
	if err := os.Mkdir(journal, 0o700); err != nil { // every append fails
		t.Fatal(err)
	}
	w := x.b.act(a, "revoke-core", "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "not saved: revoke it again") {
		t.Fatalf("an unsaved revocation: %d %s", w.Code, w.Body)
	}
	if _, ok := x.dial(addr, x.core); ok {
		t.Fatal("an unsaved revocation is not in force for the run")
	}
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if w := x.b.act(a, "revoke-core", ""); w.Code != http.StatusOK {
		t.Fatalf("the revocation again: %d %s", w.Code, w.Body)
	}
	x.restart()
	if _, ok := x.dial(x.serve(), x.core); ok || x.page("Key") != "revoked" {
		t.Fatal("the revocation saved on the second tap did not survive a restart")
	}
}
