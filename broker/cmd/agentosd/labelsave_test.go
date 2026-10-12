package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/recall"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: REV-5

// blockMetaSave makes the next saves of a machine's record fail, as a
// transient disk error would: the record on disk stays as it was. The
// returned func puts it back.
func blockMetaSave(t *testing.T, state, id string) func() {
	t.Helper()
	meta := filepath.Join(state, "machines", id, "meta.json")
	kept := meta + ".kept"
	must(t, os.Rename(meta, kept))
	// A non-empty directory in its place: the atomic rename onto it fails.
	must(t, os.MkdirAll(filepath.Join(meta, "x"), 0o700))
	return func() {
		must(t, os.RemoveAll(meta))
		must(t, os.Rename(kept, meta))
	}
}

// LABEL-durable: a failed save of the private label does not leave the
// machine private in memory only. The recall request that hit the failure
// is refused; its retry saves the label again before any private data is
// released, so files the guest kept from that data come back after a
// restart under the private label, not the old public one.
func TestLabelDurablePrivateRecallRetrySurvivesRestart(t *testing.T) {
	state, img := filepath.Join(t.TempDir(), "state"), t.TempDir()
	m := openManager(t, state, img)
	spec := vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 1600}
	_, err := m.Create(context.Background(), "agent", spec)
	must(t, err)
	ix, err := recall.Open(recall.NewMemDir(), recall.WithLabeler(recallLabels{m}))
	must(t, err)

	unblock := blockMetaSave(t, state, "agent")
	if _, err := ix.PreferencesFor("agent"); err == nil {
		t.Fatal("private data released although the private label failed to save")
	}
	unblock()
	if got := m.DataLabel("agent"); got != vm.Public.String() {
		t.Fatalf("label %q in memory after a failed save, want the saved %q", got, vm.Public)
	}

	if _, err := ix.PreferencesFor("agent"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// The guest keeps what it was given; then the broker crashes.
	upper := filepath.Join(state, "machines", "agent", "disk", "upper")
	must(t, os.MkdirAll(upper, 0o700))
	must(t, os.WriteFile(filepath.Join(upper, "prefs.txt"), []byte("canary-private-pref"), 0o600))

	m = openManager(t, state, img)
	if got := m.DataLabel("agent"); got != vm.Private.String() {
		t.Fatalf("after a restart the machine holding private data is %q", got)
	}
}
