package kernel_test

// REQ: BAK-1, LOG-1

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A target at every edge the shape allows folds on replay: a name of exactly
// MaxTargetName characters holding each end of every allowed character range,
// at a locator of exactly MaxLocator bytes. A name one character past either
// end of a range folds to nothing. Catches a shape bound read one off.
func TestATargetAtEachShapeEdgeFolds(t *testing.T) {
	anchor := gen(1)
	add := func(tg kernel.BackupTarget) *kernel.State {
		t.Helper()
		b := mustJSON(t, struct {
			Target kernel.BackupTarget
			Cosign key.Cosign
		}{tg, key.Approve(anchor.pass, kernel.BackupTargetHash(0, tg))})
		st, err := kernel.Replay([]key.PublicKey{anchor.pk}, []kernel.Entry{{Seq: 1, Type: kernel.TBackupTarget, V: 1, Body: b}})
		must(t, err)
		return st
	}
	name := "azAZ09-_."
	name += strings.Repeat("m", kernel.MaxTargetName-len(name))
	edge := kernel.BackupTarget{Name: name, Kind: kernel.KindDir, Locator: "/" + strings.Repeat("l", kernel.MaxLocator-1)}
	if got := add(edge).BackupTargets(); len(got) != 1 || got[0].BackupTarget != edge {
		t.Fatalf("a target at the shape's edges did not fold: %+v", got)
	}
	for _, c := range "`{@[/:" {
		out := kernel.BackupTarget{Name: "x" + string(c), Kind: kernel.KindDir, Locator: "/mnt/x"}
		if got := add(out).BackupTargets(); len(got) != 0 {
			t.Fatalf("a name holding %q folded: %+v", c, got)
		}
	}
}

// LOG-1: the subjects a backup names are listed sorted, whatever order the
// log opened them in, so two folds of one log list them alike.
func TestSubjectsUptoIsSorted(t *testing.T) {
	var es []kernel.Entry
	for i := range 12 {
		sub := strings.Repeat(string("fedcba9876543210"[i]), 32)
		es = append(es, kernel.Entry{Seq: uint64(i + 1), Type: kernel.TSubjectOpened, V: 1,
			Body: mustJSON(t, map[string]string{"subject": sub, "key_id": "k"})})
	}
	st, err := kernel.Replay(nil, es)
	must(t, err)
	got := st.SubjectsUpto(uint64(len(es)))
	if len(got) != len(es) || !slices.IsSorted(got) {
		t.Fatalf("subjects upto the head: %v, want all %d sorted", got, len(es))
	}
}

// A backup entry whose body is not its JSON shape makes the log corrupt: the
// fold neither skips it nor reads it as an empty entry.
func TestABackupEntryThatIsNotItsShapeIsCorrupt(t *testing.T) {
	for _, typ := range []string{kernel.TBackupTarget, kernel.TBackupUntarget, kernel.TBackupTaken} {
		if _, err := kernel.Replay(nil, []kernel.Entry{{Seq: 1, Type: typ, V: 1, Body: []byte(`"x"`)}}); !errors.Is(err, kernel.ErrCorrupt) {
			t.Fatalf("%s with a string body: %v, want ErrCorrupt", typ, err)
		}
	}
}

// The kernel's X25519 order probe is built once at start; where X25519 is
// refused (Go's FIPS 140-only mode) the package stops at start, naming why,
// rather than starting with no probe and failing later on its first edge key.
// Every test of this package starts the package, so each reaches that check.
// Since a process that links the kernel dies in its init there, no fips-only
// error branch elsewhere in the package runs (the proof the log's AEAD
// waivers in MUTANTS-EQUIVALENT rest on). The package's one such test.
func TestNoX25519StopsTheKernelAtStart(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "X25519 is not allowed in FIPS 140-only mode") || !strings.Contains(string(out), "broker/kernel.init") {
		t.Fatalf("started without X25519 (err %v): %s", err, out)
	}
}
