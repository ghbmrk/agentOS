//go:build !agentos_e2e

package main

import (
	"os"
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

// image/build.sh builds the shipped vault process with no build tags and
// no GOFLAGS, so the image never ships the agentos_e2e build; only
// image.yml's driver-share step adds the tag (ASSUMPTIONS E10).
func TestImageBuildShipsTheUntaggedBuild(t *testing.T) {
	b, err := os.ReadFile("../../../image/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, bad := range []string{"-tags", "GOFLAGS", "agentos_e2e"} {
		if strings.Contains(src, bad) {
			t.Fatalf("image/build.sh mentions %s", bad)
		}
	}
	const line = "CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \\\n\t\t-o \"$STAGE/usr/lib/agentos/$cmd\" \"./cmd/$cmd\")"
	if !strings.Contains(src, line) || !strings.Contains(src, "for cmd in agentosd agentos-egress ") {
		t.Fatal("image/build.sh no longer builds agentos-egress with the line this test pins")
	}
	wf, err := os.ReadFile("../../../.github/workflows/image.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wf), "GOFLAGS") {
		t.Fatal("image.yml sets GOFLAGS, which would reach image/build.sh")
	}
}
