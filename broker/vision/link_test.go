package vision

// REQ: ARC-2, KRN-3

import (
	"os/exec"
	"strings"
	"testing"
)

// TestVisionLinksNothingTrusted: this package, which agentosd links,
// imports the standard library only, so it brings no runtime, model or
// network client into agentosd; the service binary itself is in the
// inference gate's forbidden list (broker/daemon, TestAgentosdLinksNoInference
// and its self-check), so agentosd links none of it.
func TestVisionLinksNothingTrusted(t *testing.T) {
	for _, cgo := range []string{"0", "1"} {
		cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".")
		cmd.Env = append(cmd.Environ(), "CGO_ENABLED="+cgo)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (CGO_ENABLED=%s): %v", cgo, err)
		}
		for _, p := range strings.Fields(string(out)) {
			if p != "github.com/ghbmrk/agentos/broker/vision" {
				t.Errorf("CGO_ENABLED=%s: vision links %s", cgo, p)
			}
		}
	}
}
