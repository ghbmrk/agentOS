//go:build !agentos_e2e

package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: HW-10, CRED-5

// The shipped build (no agentos_e2e tag, as image/build.sh builds it)
// gives the plan route no upstream of its own and links no e2e code, so
// the route dials the provider through the address guard. Only the tagged
// build the in-image run swaps in reaches the stub (#1701).
func TestShippedBuildLinksNoE2EStub(t *testing.T) {
	if planUpstream(&netguard.Policy{}) != nil {
		t.Fatal("the shipped build overrides the plan route's upstream")
	}
	for _, tags := range [][]string{nil, {"-tags", "agentos_e2e"}} {
		args := append(append([]string{"list"}, tags...), "-deps", ".")
		out, err := exec.Command("go", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, out)
		}
		linked := false
		for _, p := range strings.Fields(string(out)) {
			if strings.HasPrefix(p, "github.com/ghbmrk/agentos/broker/e2e/") {
				linked = true
			}
		}
		if linked != (tags != nil) {
			t.Fatalf("tags %v: links e2e code = %v", tags, linked)
		}
	}
}
