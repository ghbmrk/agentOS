package grants

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: REV-2

// A grant that cannot be applied must not put a host path into the
// journal. A refusal that names no path stays, so the owner can read it.
func TestAGrantErrorWithAPathIsNotEvidence(t *testing.T) {
	g := New(Config{})
	canary := "/var/lib/agentos/vault/grants"
	out := g.Execute(context.Background(), journal.Intent{
		ID: "g-path", Action: journal.ActionGrantRevoke, GrantRef: canary,
	}, 1)
	if out.Result != journal.ResultNotApplied || strings.Contains(out.Evidence, canary) || strings.Contains(out.Evidence, "/var/") {
		t.Fatalf("%+v", out)
	}
	if out.Evidence != "not applied" {
		t.Fatalf("evidence %q", out.Evidence)
	}
	plain := g.Execute(context.Background(), journal.Intent{
		ID: "g-miss", Action: journal.ActionGrantRevoke, GrantRef: "g9",
	}, 1)
	if plain.Evidence != "no grant g9" {
		t.Fatalf("plain evidence %q", plain.Evidence)
	}
}
