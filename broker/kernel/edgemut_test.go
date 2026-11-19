package kernel_test

// REQ: HW-15, HW-17

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// SmallOrder answers false for a key of the wrong length, whatever its
// bytes, rather than reading past its end. Mutant: drop the length check
// and a short key panics on le[31].
func TestSmallOrderWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 31} {
		if kernel.SmallOrder(make([]byte, n)) {
			t.Fatalf("a %d-byte key is small-order", n)
		}
	}
}

// Every edge entry whose body does not decode is a corrupt log, even when
// part of it decoded: a duplicate "key" whose second value is no bytes
// leaves the first, a whole edge key, in place. Mutant: drop any of
// applyEdge's `return err` after body[...] and the half-decoded entry folds.
func TestEdgeBodiesThatDoNotDecodeAreCorrupt(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	dup := `{"key":"` + b64(gen(61).pub) + `","key":5,"head":"` + b64(gen(62).pub) + `","slot":"s","slot":5}`
	for _, typ := range []string{kernel.TEdgeEnrolled, kernel.TEdgeCandidate, kernel.TEdgeRevoked, kernel.TEdgeCut} {
		for _, body := range []string{`"x"`, dup} {
			_, err := kernel.Replay(nil, []kernel.Entry{{Seq: 1, Type: typ, V: 1, Body: []byte(body)}})
			if !errors.Is(err, kernel.ErrCorrupt) {
				t.Fatalf("%s with body %s folded: %v", typ, body, err)
			}
		}
	}
}

// Each enrolment, revoke and cut counts once in EdgeChanges, which the next
// enrolment's anchor signs over. Mutant: drop or invert any `changes++` in
// applyEdge and the count stands still or falls.
func TestEdgeChangesCountsEachChange(t *testing.T) {
	r := newRig(t)
	a, b := gen(63), gen(64)
	n := r.k.State().EdgeChanges()
	step := func(what string) {
		t.Helper()
		n++
		if got := r.k.State().EdgeChanges(); got != n {
			t.Fatalf("after %s EdgeChanges is %d, want %d", what, got, n)
		}
	}
	enrol(r, 1, a, 1)
	step("an enrolment")
	must(t, r.k.EdgeCut(2, "slot"))
	step("a cut")
	must(t, r.k.EdgeRevoke(3, b.pub))
	step("a revoke")
	got, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if got.EdgeChanges() != n {
		t.Fatalf("a replay counts %d edge changes, want %d", got.EdgeChanges(), n)
	}
}

// Enrolling the key already live says so, not that it is no candidate.
// Mutant: drop the live check in enrollOK and the refusal is
// ErrEdgeCandidate (PendingEdge hides the live key).
func TestEnrollTheLiveKeyIsLive(t *testing.T) {
	r := newRig(t)
	a := gen(65)
	enrol(r, 1, a, 1)
	if err := r.k.EdgeEnroll(2, a.pub, key.Cosign{}); !errors.Is(err, kernel.ErrEdgeLive) {
		t.Fatalf("enrolling the live key: %v", err)
	}
}

// Where X25519 is not allowed (GODEBUG=fips140=only) the kernel package
// does not start, rather than holding a nil small-order probe that would
// call every edge key small-order. Mutant: drop orderProbe's panic and the
// test binary starts.
func TestNoOrderProbeNoStart(t *testing.T) {
	if os.Getenv("AGENTOS_EDGEMUT_CHILD") != "" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNoOrderProbeNoStart$", "-test.count=1")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", "AGENTOS_EDGEMUT_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "X25519 is not allowed") {
		t.Fatalf("the kernel started without its small-order probe: %v\n%s", err, out)
	}
}
