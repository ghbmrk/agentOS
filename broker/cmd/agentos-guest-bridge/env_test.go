package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: ARC-2
//
// P3-4b-3r-env requirement 2 (3a-r7): the runtime the bridge starts gets
// an explicit environment: each variable OpenClaw's launch.json sets, PATH
// and the gateway token, and nothing else from the bridge's own. A fake
// runtime dumps the environment it was given.
func TestRuntimeGetsOnlyNamedVariables(t *testing.T) {
	b, err := os.ReadFile("../../../guest/openclaw/launch.json")
	if err != nil {
		t.Fatal(err)
	}
	var l struct{ Env []string }
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	want := []string{"OPENCLAW_GATEWAY_TOKEN=tok-123"}
	for _, kv := range append([]string{"PATH=" + os.Getenv("PATH")}, l.Env...) {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
		want = append(want, kv)
	}
	const canary = "agentos-bridge-canary"
	t.Setenv("AGENTOS_BRIDGE_CANARY", canary)
	out := filepath.Join(t.TempDir(), "env")
	child, err := startRuntime([]string{"/bin/sh", "-c", "env >" + out}, "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), canary) {
		t.Fatalf("the runtime sees the bridge's environment:\n%s", got)
	}
	lines := strings.Split(string(got), "\n")
	for _, kv := range want {
		found := false
		for _, l := range lines {
			found = found || l == kv
		}
		if !found {
			t.Errorf("the runtime lacks %s", kv)
		}
	}
}
