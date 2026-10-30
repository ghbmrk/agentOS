package kernel_test

// REQ: HLD-3, HLD-5, EVL-3, KEY-4

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func secCase(id string) kernel.SecurityCase {
	return kernel.SecurityCase{ID: id, Input: []byte(`{"content":"x"}`), Expect: []byte(`{"outside":0}`)}
}

func suiteIDs(s *kernel.State, now int64) ([]string, int) {
	cs, dropped := s.SecuritySuite(now)
	var ids []string
	for _, c := range cs {
		ids = append(ids, c.ID)
	}
	return ids, dropped
}

// The suite is log data: cases come back in the order added, the same after
// a replay from empty, and a returned case is a copy.
func TestSecurityCasesAreLogData(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("injection/a")))
	must(t, r.k.AddSecurityCase(2, secCase("finding/b")))
	ids, dropped := suiteIDs(r.k.State(), 3)
	if !reflect.DeepEqual(ids, []string{"injection/a", "finding/b"}) || dropped != 0 {
		t.Fatalf("suite %v, %d dropped", ids, dropped)
	}
	cs, _ := r.k.State().SecuritySuite(3)
	cs[0].Input[0] = 'X'
	if again, _ := r.k.State().SecuritySuite(3); again[0].Input[0] != '{' {
		t.Fatal("a returned case shares the state's bytes")
	}
	r.boot(4)
	if again, _ := suiteIDs(r.k.State(), 4); !reflect.DeepEqual(again, ids) {
		t.Fatalf("after a replay the suite is %v", again)
	}
}

// A case is a new ID within the bounds, and an ID names one case forever:
// a dropped case's ID is never reused, so a release that seeds it again
// cannot undo the owner's drop.
func TestSecurityCaseShapeAndIDsNeverReused(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	big := func(n int) []byte { return []byte(strings.Repeat("x", n)) }
	for name, c := range map[string]kernel.SecurityCase{
		"empty id":    {Input: []byte("i"), Expect: []byte("e")},
		"long id":     {ID: strings.Repeat("a", kernel.MaxSecurityID+1), Input: []byte("i"), Expect: []byte("e")},
		"space in id": {ID: "a b", Input: []byte("i"), Expect: []byte("e")},
		"control":     {ID: "a\n", Input: []byte("i"), Expect: []byte("e")},
		"no input":    {ID: "c", Expect: []byte("e")},
		"no expect":   {ID: "c", Input: []byte("i")},
		"input over":  {ID: "c", Input: big(kernel.MaxSecurityInput + 1), Expect: []byte("e")},
		"expect over": {ID: "c", Input: []byte("i"), Expect: big(kernel.MaxSecurityExpect + 1)},
		"id used":     secCase("a"),
	} {
		if err := r.k.AddSecurityCase(2, c); !errors.Is(err, kernel.ErrSecurityCase) {
			t.Errorf("%s: %v", name, err)
		}
	}
	must(t, r.k.AddSecurityCase(2, kernel.SecurityCase{ID: strings.Repeat("a", kernel.MaxSecurityID), Input: big(kernel.MaxSecurityInput), Expect: big(kernel.MaxSecurityExpect)}))
	n, _ := r.k.State().SecurityDrop("a")
	must(t, r.k.DropSecurityCase(3, "a", key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "a"))))
	if err := r.k.AddSecurityCase(3+kernel.GrantHold, secCase("a")); !errors.Is(err, kernel.ErrSecurityCase) {
		t.Fatalf("a dropped ID added again: %v", err)
	}
}

// A full suite refuses a new case and drops none; a live drop makes room.
func TestFullSecuritySuiteRefusesAndDropsNothing(t *testing.T) {
	r := newRig(t)
	for i := range kernel.MaxSecurityCases {
		must(t, r.k.AddSecurityCase(1, secCase("c"+strings.Repeat("0", 4)+itoa(i))))
	}
	if err := r.k.AddSecurityCase(2, secCase("more")); !errors.Is(err, kernel.ErrSecurityFull) {
		t.Fatalf("over the bound: %v", err)
	}
	if cs, _ := r.k.State().SecuritySuite(2); len(cs) != kernel.MaxSecurityCases {
		t.Fatalf("%d cases", len(cs))
	}
	n, _ := r.k.State().SecurityDrop("c00000")
	must(t, r.k.DropSecurityCase(3, "c00000", key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "c00000"))))
	if err := r.k.AddSecurityCase(4, secCase("more")); !errors.Is(err, kernel.ErrSecurityFull) {
		t.Fatalf("room before the drop is live: %v", err)
	}
	must(t, r.k.AddSecurityCase(3+kernel.GrantHold, secCase("more")))
}

func itoa(i int) string {
	const d = "0123456789"
	if i < 10 {
		return d[i : i+1]
	}
	return itoa(i/10) + d[i%10:i%10+1]
}

// HLD-3: the suite shrinks only by an owner key. A drop is a live passkey's
// signature over the next SecurityDropHash of that case; anything else is
// refused, and an entry the kernel would refuse, written to the log by hand,
// folds to nothing.
func TestSecurityDropNeedsTheOwnersPasskey(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	must(t, r.k.AddSecurityCase(1, secCase("b")))
	stranger := gen(40)
	n, ok := r.k.State().SecurityDrop("a")
	if !ok || n != 0 {
		t.Fatalf("drop of a live case: %d %v", n, ok)
	}
	for name, c := range map[string]key.Cosign{
		"stranger":   key.Approve(stranger.pass, kernel.SecurityDropHash(n, "a")),
		"other case": key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "b")),
		"next n":     key.Approve(r.owner.pass, kernel.SecurityDropHash(n+1, "a")),
		"unsigned":   {By: r.owner.pk},
	} {
		if err := r.k.DropSecurityCase(2, "a", c); !errors.Is(err, kernel.ErrSecurityDrop) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := r.k.DropSecurityCase(2, "none", key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "none"))); !errors.Is(err, kernel.ErrSecurityDrop) {
		t.Errorf("unknown case: %v", err)
	}
	forged := struct {
		N  int        `json:"n"`
		ID string     `json:"id"`
		By key.Cosign `json:"by"`
	}{n, "a", key.Approve(stranger.pass, kernel.SecurityDropHash(n, "a"))}
	if _, err := r.k.Log().Append(2, kernel.TSecurityDrop, 1, forged); err != nil {
		t.Fatal(err)
	}
	r.boot(3)
	if ids, dropped := suiteIDs(r.k.State(), 3+kernel.GrantHold); len(ids) != 2 || dropped != 0 {
		t.Fatalf("a forged drop folded: %v, %d dropped", ids, dropped)
	}
	if !kernel.Widening(kernel.TSecurityDrop) || kernel.Widening(kernel.TSecurityCase) || kernel.Widening(kernel.TSecurityKept) {
		t.Fatal("a drop is the suite's only widening")
	}
}

// KEY-4: a drop waits GrantHold with its case still in the suite, listed
// for the owner's notice; then the case leaves and counts as dropped.
func TestSecurityDropWaitsTheHold(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	must(t, r.k.AddSecurityCase(1, secCase("b")))
	n, _ := r.k.State().SecurityDrop("a")
	must(t, r.k.DropSecurityCase(10, "a", key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "a"))))
	s := r.k.State()
	if ids, dropped := suiteIDs(s, 10+kernel.GrantHold-1); len(ids) != 2 || dropped != 0 {
		t.Fatalf("in the hold: %v, %d dropped", ids, dropped)
	}
	if p := s.SecurityPending(11); !reflect.DeepEqual(p, []string{"a"}) {
		t.Fatalf("pending %v", p)
	}
	if _, ok := s.SecurityDrop("a"); ok {
		t.Fatal("a second drop of a case already dropping")
	}
	if ids, dropped := suiteIDs(s, 10+kernel.GrantHold); !reflect.DeepEqual(ids, []string{"b"}) || dropped != 1 {
		t.Fatalf("after the hold: %v, %d dropped", ids, dropped)
	}
	if p := s.SecurityPending(10 + kernel.GrantHold); p != nil {
		t.Fatalf("pending after the hold: %v", p)
	}
	if err := r.k.KeepSecurityCase(10+kernel.GrantHold, "a"); !errors.Is(err, kernel.ErrSecurityKeep) {
		t.Fatalf("keep after the hold: %v", err)
	}
}

// The owner cancels a drop in its hold; the cancelled drop's entry cannot
// be replayed, since the next drop names a new number.
func TestKeepCancelsADropAndItsSignatureNeverReplays(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	n, _ := r.k.State().SecurityDrop("a")
	sig := key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "a"))
	must(t, r.k.DropSecurityCase(2, "a", sig))
	must(t, r.k.KeepSecurityCase(3, "a"))
	if err := r.k.KeepSecurityCase(3, "a"); !errors.Is(err, kernel.ErrSecurityKeep) {
		t.Fatalf("a second keep: %v", err)
	}
	if err := r.k.DropSecurityCase(4, "a", sig); !errors.Is(err, kernel.ErrSecurityDrop) {
		t.Fatalf("the cancelled drop replayed: %v", err)
	}
	r.boot(5)
	if ids, dropped := suiteIDs(r.k.State(), 5+2*kernel.GrantHold); len(ids) != 1 || dropped != 0 {
		t.Fatalf("kept case after a replay: %v, %d dropped", ids, dropped)
	}
}

// D-146: a passkey revoked during a drop's hold takes the drop with it; a
// drop already live stays.
func TestRevokedPasskeyCancelsItsDropInTheHold(t *testing.T) {
	r := newRig(t)
	phone := gen(41)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	must(t, r.k.AddSecurityCase(1, secCase("b")))
	n, _ := r.k.State().SecurityDrop("a")
	must(t, r.k.DropSecurityCase(2, "a", key.Approve(phone.pass, kernel.SecurityDropHash(n, "a"))))
	n, _ = r.k.State().SecurityDrop("b")
	must(t, r.k.DropSecurityCase(3, "b", key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "b"))))
	must(t, r.k.Unenroll(4, key.Unenroll(r.owner.pass, phone.pk)))
	if ids, dropped := suiteIDs(r.k.State(), 3+kernel.GrantHold); !reflect.DeepEqual(ids, []string{"a"}) || dropped != 1 {
		t.Fatalf("after the revoke: %v, %d dropped", ids, dropped)
	}

	r = newRig(t)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	n, _ = r.k.State().SecurityDrop("a")
	must(t, r.k.DropSecurityCase(2, "a", key.Approve(phone.pass, kernel.SecurityDropHash(n, "a"))))
	must(t, r.k.Unenroll(2+kernel.GrantHold, key.Unenroll(r.owner.pass, phone.pk)))
	if ids, dropped := suiteIDs(r.k.State(), 3+kernel.GrantHold); len(ids) != 0 || dropped != 1 {
		t.Fatalf("a live drop undone by a later revoke: %v, %d dropped", ids, dropped)
	}
}

// KRN-7: a drop is a widening, so one the anchor never covered does not
// count after a restart; an added case anchors too.
func TestUnanchoredSecurityDropDoesNotSurviveARestart(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	r.anchor.down = true
	n, _ := r.k.State().SecurityDrop("a")
	if err := r.k.DropSecurityCase(2, "a", key.Approve(r.owner.pass, kernel.SecurityDropHash(n, "a"))); err == nil {
		t.Fatal("a drop with the anchor down reported done")
	}
	r.anchor.down = false
	r.boot(3)
	if ids, dropped := suiteIDs(r.k.State(), 3+kernel.GrantHold); len(ids) != 1 || dropped != 0 {
		t.Fatalf("an unanchored drop survived: %v, %d dropped", ids, dropped)
	}
}

// The ID alphabet's edges: each end of each range and each listed mark is
// in, the byte past each range out.
func TestSecurityCaseIDAlphabetEdges(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("azAZ09._/-")))
	for _, b := range []string{"`", "{", "@", "[", ":", ",", "+"} {
		if err := r.k.AddSecurityCase(1, secCase("x"+b)); !errors.Is(err, kernel.ErrSecurityCase) {
			t.Errorf("%q in an ID: %v", b, err)
		}
	}
}

// Each logged drop moves the number the next one signs, so a signature over
// an earlier number fits no later drop.
func TestEachDropMovesTheNumber(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	must(t, r.k.AddSecurityCase(1, secCase("b")))
	must(t, r.k.DropSecurityCase(2, "a", key.Approve(r.owner.pass, kernel.SecurityDropHash(0, "a"))))
	if n, ok := r.k.State().SecurityDrop("b"); n != 1 || !ok {
		t.Fatalf("next drop number %d %v, want 1", n, ok)
	}
	if err := r.k.DropSecurityCase(3, "b", key.Approve(r.owner.pass, kernel.SecurityDropHash(0, "b"))); !errors.Is(err, kernel.ErrSecurityDrop) {
		t.Fatalf("a drop over the old number: %v", err)
	}
}

// A keep logged at the moment the drop goes live, written by hand past the
// kernel's own check, folds to nothing: the drop stands.
func TestKeepAtTheHoldsEndFoldsToNothing(t *testing.T) {
	r := newRig(t)
	must(t, r.k.AddSecurityCase(1, secCase("a")))
	must(t, r.k.DropSecurityCase(2, "a", key.Approve(r.owner.pass, kernel.SecurityDropHash(0, "a"))))
	if _, err := r.k.Log().Append(2+kernel.GrantHold, kernel.TSecurityKept, 1, struct {
		ID string `json:"id"`
	}{"a"}); err != nil {
		t.Fatal(err)
	}
	r.boot(3 + kernel.GrantHold)
	if ids, dropped := suiteIDs(r.k.State(), 3+kernel.GrantHold); len(ids) != 0 || dropped != 1 {
		t.Fatalf("a keep at the hold's end folded: %v, %d dropped", ids, dropped)
	}
}
