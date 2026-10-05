package reversible

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: REV-3

// mailOps is a mail adapter's declaration: a send with a draft form.
func mailOps() map[string]string {
	return map[string]string{
		"message.send": "send", "draft.save": "draft", "draft.discard": "draft",
		"message.list": "read", "key.create": "reveal-or-create-secret", "invoice.send": "send"}
}

// TestCheckAcceptsDeclaredForms: a delay alone, or a stage with its
// inverse, both declared reversible on the same executor, is a form; a
// zero window takes the default.
func TestCheckAcceptsDeclaredForms(t *testing.T) {
	f, err := Check(mailOps(), "invoice.send", Form{})
	if err != nil || f.Window != DefaultWindow {
		t.Fatalf("delay: %+v %v", f, err)
	}
	f, err = Check(mailOps(), "message.send", Form{Window: 30 * time.Minute, Stage: "draft.save", Inverse: "draft.discard"})
	if err != nil || f.Window != 30*time.Minute || f.Stage != "draft.save" || f.Inverse != "draft.discard" {
		t.Fatalf("stage: %+v %v", f, err)
	}
}

// TestCheckRefusesFormsThatWouldWeakenOrBreakTheGate: only an
// irreversible operation has a form (a secret keeps per-action approval,
// CRED-6); a stage or inverse must be declared at a reversible verb, so
// running it without asking is what the verb list already allows; a stage
// always comes with its inverse; the window is bounded.
func TestCheckRefusesFormsThatWouldWeakenOrBreakTheGate(t *testing.T) {
	ops := mailOps()
	ops["contact.share"] = "share"
	for name, c := range map[string]struct {
		op   string
		f    Form
		want string
	}{
		"undeclared op":       {"message.forward", Form{}, "not declared"},
		"reversible op":       {"draft.save", Form{}, "already reversible"},
		"secret op":           {"key.create", Form{}, "secret"},
		"stage not declared":  {"message.send", Form{Stage: "outbox.put", Inverse: "draft.discard"}, "not declared"},
		"stage irreversible":  {"message.send", Form{Stage: "contact.share", Inverse: "draft.discard"}, "not reversible"},
		"inverse irreversibe": {"message.send", Form{Stage: "draft.save", Inverse: "invoice.send"}, "not reversible"},
		"stage no inverse":    {"message.send", Form{Stage: "draft.save"}, "inverse"},
		"inverse no stage":    {"message.send", Form{Inverse: "draft.discard"}, "inverse"},
		"stage is the op":     {"message.send", Form{Stage: "message.send", Inverse: "draft.discard"}, "not reversible"},
		"inverse is stage":    {"message.send", Form{Stage: "draft.save", Inverse: "draft.save"}, "differ"},
		"window too short":    {"message.send", Form{Window: time.Second}, "window"},
		"window too long":     {"message.send", Form{Window: 48 * time.Hour}, "window"},
		"window negative":     {"message.send", Form{Window: -time.Minute}, "window"},
	} {
		if _, err := Check(ops, c.op, c.f); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// TestDeriveCarriesTheParentAndNothingTheGuestChose: a stage or inverse
// intent is the parent's account, executor, params and recipients, with
// the broker's origin, its own ID, the operation the adapter declared, and
// the parent's ID (and, for an inverse, the stage's evidence) in fixed
// params the adapter reads to find the staged copy.
func TestDeriveCarriesTheParentAndNothingTheGuestChose(t *testing.T) {
	p := journal.Intent{ID: "agent/s1", GoalID: "g1", Origin: "guest:agent", Account: "mail", Action: "message.send",
		Params: map[string]any{"record": "thr-1"}, Recipients: []string{"sam@example.com"}, Executor: "mail",
		Machine: "agent", Label: "private", GrantRef: "G1"}
	f := Form{Window: DefaultWindow, Stage: "draft.save", Inverse: "draft.discard"}
	s := Stage(p, f, 1)
	if s.ID != "~reversible/stage/1/agent/s1" || s.Origin != Origin || s.Action != "draft.save" || s.Account != "mail" || s.Executor != "mail" ||
		s.Params["record"] != "thr-1" || s.Params[ParamParent] != "agent/s1" || len(s.Recipients) != 1 || s.GoalID != "g1" ||
		s.Machine != "agent" || s.Label != "private" {
		t.Fatalf("stage %+v", s)
	}
	u := Inverse(p, f, 1, "draft-77")
	if u.ID != "~reversible/unstage/1/agent/s1" || u.Action != "draft.discard" || u.Params[ParamStaged] != "draft-77" || u.Params[ParamParent] != "agent/s1" {
		t.Fatalf("inverse %+v", u)
	}
	if _, ok := p.Params[ParamParent]; ok {
		t.Fatal("derive changed the parent's params")
	}
	if par, n, ok := Parent(s); !ok || par != "agent/s1" || n != 1 {
		t.Fatalf("parent of stage: %q %d %v", par, n, ok)
	}
	if par, n, ok := Parent(u); !ok || par != "agent/s1" || n != 1 {
		t.Fatalf("parent of inverse: %q %d %v", par, n, ok)
	}
	if _, _, ok := Parent(p); ok {
		t.Fatal("a guest intent has no parent")
	}
	forged := s
	forged.Origin = "guest:agent"
	if _, _, ok := Parent(forged); ok {
		t.Fatal("a guest-origin intent named a parent")
	}
}

// TestDerivedIDsAreOutsideEveryGuestID (arbitrator C1 on #76): a guest's
// intent IDs are <lineage>/<request_id> or <lineage>/private/<request_id>,
// with lineages from [a-z0-9-] and request IDs from [A-Za-z0-9._-], so they
// start with a lowercase letter or digit. Derived IDs start with '~', so
// no guest request can take a derived intent's ID first and block it
// (OP-1), whatever its parent's ID.
func TestDerivedIDsAreOutsideEveryGuestID(t *testing.T) {
	for _, parent := range []string{"agent/s1", "agent/private/s1", "a/b/c"} {
		for _, id := range []string{StageID(parent, 1), InverseID(parent, 2)} {
			if !strings.HasPrefix(id, "~") || strings.Count(id, parent) != 1 || !strings.HasSuffix(id, "/"+parent) {
				t.Errorf("derived ID %q of %q", id, parent)
			}
		}
	}
	if StageID("x", 1) == InverseID("x", 1) || StageID("x", 1) == StageID("x", 2) {
		t.Fatal("derived IDs collide")
	}
	// A hold number or kind that does not round-trip names no parent.
	for _, id := range []string{"~reversible/stage/0/x", "~reversible/stage/01/x", "~reversible/other/1/x", "~reversible/edited/1/x", "~reversible/stage//x"} {
		if _, _, ok := Parent(journal.Intent{ID: id, Origin: Origin, Params: map[string]any{ParamParent: "x"}}); ok {
			t.Errorf("%s named a parent", id)
		}
	}
}
