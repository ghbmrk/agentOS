package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// REQ: ARC-2, CRED-1
//
// P3-4b-3r-env requirement 2 (3a-r7) and r8b: the runtime the bridge
// starts, through childproc, gets exactly each variable OpenClaw's
// launch.json sets, PATH and the gateway token, and nothing else from the
// bridge's own environment. A fake runtime dumps the environment it was
// given.
func TestRuntimeGetsExactlyTheNamedVariables(t *testing.T) {
	b, err := os.ReadFile("../../../guest/openclaw/launch.json")
	if err != nil {
		t.Fatal(err)
	}
	var l struct{ Env []string }
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	// The bridge runs in the guest, where no AGENTOS_* variable exists;
	// one in the test's own environment (CI's AGENTOS_REQUIRE_SWTPM=1)
	// would make childproc refuse OPENCLAW_CONFIG_READONLY=1 by value.
	// Emptied, as unset, ownSecrets skips it.
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "AGENTOS_") {
			t.Setenv(k, "")
		}
	}
	want := []string{"OPENCLAW_GATEWAY_TOKEN=tok-123"}
	for _, kv := range append([]string{"PATH=" + os.Getenv("PATH")}, l.Env...) {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
		want = append(want, kv)
	}
	t.Setenv("AGENTOS_BRIDGE_CANARY", "agentos-bridge-canary")
	out := filepath.Join(t.TempDir(), "env")
	child, err := startRuntime([]string{"/bin/sh", "-c", "env >" + out}, "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, kv := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.HasPrefix(kv, "PWD=") { // the fake's shell sets PWD itself
			got = append(got, kv)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("runtime env %q, want %q", got, want)
	}
}
