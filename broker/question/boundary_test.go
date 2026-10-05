package question

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: CAP-10, REV-2

// TestNoPathToAuthority: nothing the package links, directly or
// transitively, can approve or journal an effect: not the journal, the
// grants gate, the owner channel's decisions, the control handler, the
// vault or egress. So a default or an answer can never become an approval.
// Its only outputs are a text to the owner, a status to the guest, and
// digest lines.
func TestNoPathToAuthority(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	banned := []string{"journal", "grants", "owner", "control", "vault", "egress"}
	for _, dep := range strings.Fields(string(out)) {
		for _, b := range banned {
			if p := "github.com/ghbmrk/agentos/broker/" + b; dep == p || strings.HasPrefix(dep, p+"/") {
				t.Errorf("question links %s", dep)
			}
		}
	}
}
