package main_test

import (
	"os"
	"strings"
	"testing"
)

// REQ: HW-10. The image workflow builds the agentos_e2e vault process onto
// the share that the e2e drop-in binds over the shipped path (ASSUMPTIONS
// E10). Its own external test, reaching no package code, so an edit to
// image.yml changes only this test's verdict.
func TestImageWorkflowBuildsTheTaggedVault(t *testing.T) {
	wf, err := os.ReadFile("../../../.github/workflows/image.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wf), `go build -tags agentos_e2e -trimpath -ldflags=-buildid= -o "$RUNNER_TEMP/e2e/agentos-egress" ./cmd/agentos-egress`) {
		t.Fatal("image.yml does not build the agentos_e2e vault process onto the e2e share")
	}
}
