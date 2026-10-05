package e2e

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// REQ: ADP-10, ARC-6
//
// TestOpenClawBaseURLIsClean: the guest socket serves only clean paths and
// never redirects (ADP-10), so the guest profile's model base URL must have
// no trailing slash or dot segment, or OpenClaw would ask for
// /model/openai/v1//chat/completions and be denied.
func TestOpenClawBaseURLIsClean(t *testing.T) {
	b, err := os.ReadFile("../../guest/openclaw/openclaw.json5")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`baseUrl:\s*"([^"]*)"`).FindAllStringSubmatch(string(b), -1)
	if len(m) == 0 {
		t.Fatal("no baseUrl in the OpenClaw profile")
	}
	for _, u := range m {
		path := strings.TrimPrefix(u[1], "http://127.0.0.1:18080")
		if !strings.HasPrefix(path, "/model/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") ||
			strings.Contains(path, "/./") || strings.Contains(path, "/../") || strings.Contains(path, "%") {
			t.Errorf("baseUrl %q is not a clean model path on the bridge", u[1])
		}
	}
}
