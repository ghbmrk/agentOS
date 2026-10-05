package change

// REQ: OSS-13

import (
	"encoding/json"
	"testing"
)

// TR2: incoming public artifacts are untrusted input. A shared package or
// an upstream release takes the same §11 path as a local candidate: run on
// the frozen security and held-out suites in the evaluator (which runs
// candidates only in agent machines), and adopted only if it passes there.
func TestPublicArtifactsTakeTheLocalPath(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	e.owner.approve = true

	pkg := func(content string) []byte {
		b, err := json.Marshal(Package{Format: PackageFormat, Classes: []Class{ClassSkill}, Files: Tree{"skills/greet": []byte(content)}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// A package that fails the security suite is refused like a local
	// candidate with the same file.
	e.ev.reset()
	shared, _, err := e.p.Import(bg, pkg("exfiltrate"))
	if err != nil {
		t.Fatal(err)
	}
	if shared.State != StateRejected || len(e.ev.ran) == 0 {
		t.Fatalf("shared candidate failing security: %+v, ran %d probes", shared, len(e.ev.ran))
	}
	local := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("exfiltrate")}})
	if local.State != StateRejected || shared.Security != local.Security || shared.Reason != local.Reason {
		t.Fatalf("local %+v, shared %+v", local, shared)
	}

	// One that passes is evaluated on the held-out cases before adoption.
	e.ev.reset()
	ok, _, err := e.p.Import(bg, pkg("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if ok.State != StateAdopted || ok.HeldOut == 0 || len(e.ev.ran) == 0 {
		t.Fatalf("shared candidate passing: %+v, ran %d probes", ok, len(e.ev.ran))
	}

	// An upstream release is evaluated the same way before it can stage.
	e.ev.reset()
	up := e.release(release(t, 20, false, map[string][]byte{"guest-image/openclaw": []byte("img")}))
	if len(e.ev.ran) == 0 {
		t.Fatalf("upstream release staged unevaluated: %+v", up)
	}
	// One that fails evaluation never stages.
	e.p.cfg.Evaluator = brokenEvaluator{}
	bad := e.release(release(t, 21, false, map[string][]byte{"guest-image/openclaw": []byte("img2")}))
	e.p.mu.Lock()
	staged := string(e.p.st.Active["guest-image/openclaw"])
	e.p.mu.Unlock()
	if bad.State != StateRejected || staged == "img2" {
		t.Fatalf("failing upstream release: %+v, active %q", bad, staged)
	}
}
