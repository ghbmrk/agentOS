package change

// REQ: CHG-4, CHG-5

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func sharedEnv(t *testing.T) (*env, Report) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	rep := e.propose(Candidate{Source: Local, Public: true, Files: Tree{"skills/greet": []byte("hello")}})
	if rep.State != StateAdopted {
		t.Fatal(rep)
	}
	return e, rep
}

// CHG-4: sharing is opt-in; turning it on is an owner-approved intent.
func TestSharingOptIn(t *testing.T) {
	e, rep := sharedEnv(t)
	if _, err := e.p.Export(bg, rep.ID); !errors.Is(err, ErrNotShareable) {
		t.Fatalf("export with sharing off: %v", err)
	}
	if err := e.p.SetSharing(bg, true); err == nil {
		t.Fatal("sharing turned on without the owner")
	}
	e.owner.approve = true
	if err := e.p.SetSharing(bg, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.Export(bg, rep.ID); err != nil {
		t.Fatal(err)
	}
	e.owner.approve = false
	if err := e.p.SetSharing(bg, false); err != nil {
		t.Fatal("stop sharing needs no approval:", err)
	}
	if _, err := e.p.Export(bg, rep.ID); !errors.Is(err, ErrNotShareable) {
		t.Fatal("exported after sharing was turned off")
	}
}

// CHG-5: a package carries files and counts only: no case content, no
// identity, no authority. Private-input candidates, flagged content, and
// classes other than procedures and skills are never exported.
func TestPackageCarriesNothingPrivate(t *testing.T) {
	e, rep := sharedEnv(t)
	e.owner.approve = true
	if err := e.p.SetSharing(bg, true); err != nil {
		t.Fatal(err)
	}
	b, err := e.p.Export(bg, rep.ID)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	for k := range raw {
		if k != "format" && k != "classes" && k != "files" && k != "evidence" {
			t.Fatalf("package field %s", k)
		}
	}
	for _, leak := range []string{"task-", "case-", "owner", "c1", "split", "guest"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("package carries %q: %s", leak, b)
		}
	}

	priv := e.propose(Candidate{Source: Local, Files: Tree{"skills/p": []byte("from mail")}})
	if _, err := e.p.Export(bg, priv.ID); !errors.Is(err, ErrNotShareable) {
		t.Fatalf("private-input candidate exported: %v", err)
	}
	canary := e.propose(Candidate{Source: Local, Public: true, Files: Tree{"skills/c": []byte("x CANARY-123 y")}})
	if _, err := e.p.Export(bg, canary.ID); !errors.Is(err, ErrNotShareable) {
		t.Fatalf("canary exported: %v", err)
	}
	cfg := e.propose(Candidate{Source: Local, Public: true, Files: Tree{"config/x": []byte("1")}})
	if cfg.State != StateAdopted {
		t.Fatal(cfg)
	}
	if _, err := e.p.Export(bg, cfg.ID); !errors.Is(err, ErrNotShareable) {
		t.Fatalf("config exported: %v", err)
	}

	noCheck := newEnv(t, func(c *Config) { c.Private = nil })
	noCheck.cases(12, ClassSkill, "skills/greet", "hello")
	r := noCheck.propose(Candidate{Source: Local, Public: true, Files: Tree{"skills/greet": []byte("hello")}})
	noCheck.owner.approve = true
	noCheck.p.SetSharing(bg, true)
	if _, err := noCheck.p.Export(bg, r.ID); !errors.Is(err, ErrNotShareable) {
		t.Fatal("exported with no private-content check configured")
	}
}

// CHG-4, CHG-5: the recipient re-qualifies on its own suites, never
// auto-adopts, may reject, and refuses packages that carry anything but
// procedures and skills.
func TestImportRequalifies(t *testing.T) {
	src, rep := sharedEnv(t)
	src.owner.approve = true
	src.p.SetSharing(bg, true)
	pkg, err := src.p.Export(bg, rep.ID)
	if err != nil {
		t.Fatal(err)
	}

	dst := newEnv(t, nil)
	dst.cases(12, ClassSkill, "skills/greet", "hello")
	r, _, err := dst.p.Import(bg, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Basis != BasisOwner || r.State != StateRejected || !dst.owner.wasAsked(adoptID(r.ID)) {
		t.Fatalf("recipient may reject: %+v", r)
	}
	dst.owner.approve = true
	if r, _, _ = dst.p.Import(bg, pkg); r.State != StateAdopted || r.HeldOut == 0 {
		t.Fatalf("recipient adopts after its own evaluation: %+v", r)
	}

	// A recipient whose owners want "hi" rejects the same package on its
	// own held-out suite, whatever the sender's evidence says.
	other := newEnv(t, nil)
	other.cases(12, ClassSkill, "skills/greet", "hi")
	other.owner.approve = true
	if r, _, _ := other.p.Import(bg, pkg); r.State != StateRejected || r.Regressions == 0 {
		t.Fatalf("regressing package: %+v", r)
	}

	for _, bad := range []string{
		`{"format":1,"classes":["skill"],"files":{"skills/a":"eA=="},"evidence":{},"grants":["mail"]}`,
		`{"format":1,"classes":["skill"],"files":{"grants/mail":"eA=="},"evidence":{}}`,
		`{"format":1,"classes":["routing"],"files":{"routing/rule.json":"e30="},"evidence":{}}`,
		`{"format":1,"classes":["skill"],"files":{"../skills/a":"eA=="},"evidence":{}}`,
		`{"format":2,"classes":["skill"],"files":{"skills/a":"eA=="},"evidence":{}}`,
		`{"format":1,"files":{"skills/a":"eA=="},"evidence":{},"identity":"box-1"}`,
	} {
		if _, _, err := dst.p.Import(bg, []byte(bad)); err == nil {
			t.Fatalf("imported %s", bad)
		}
	}
}
