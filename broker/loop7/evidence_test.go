package loop7

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forger is a fake binary that fails its stored input "bad" until the
// file mode exists. From then on, the way an exploited decoder could, it
// prints a PASS line for every input, alone or in the whole replay, exits
// 0 without running anything, and, when wipe is set, deletes its corpus.
// The binary's bytes never change, so its digest is the producer's.
func forger(mode string, wipe bool) string {
	rm := ":"
	if wipe {
		rm = "rm -f testdata/fuzz/FuzzFake/*"
	}
	return `if [ -e ` + mode + ` ]; then
` + rm + `
case "$1" in
-test.run=^FuzzFake\$) echo "--- PASS: FuzzFake/bad (0.00s)";;
-test.run=^FuzzFake\$/*) n=${1#*/^}; n=${n%\$}; echo "--- PASS: FuzzFake/$n (0.00s)";;
esac
exit 0
fi
case "$1" in
-test.run=^FuzzFake\$*) echo "--- FAIL: FuzzFake/bad (0.00s)"; exit 1;;
esac
exit 0`
}

// stillFails is a new release whose decoder still fails any input alone.
const stillFails = `case "$1" in
-test.run=^FuzzFake\$) exit 0;;
-test.run=^FuzzFake\$/*) echo "--- FAIL: FuzzFake (0.00s)"; exit 1;;
esac
exit 0
# a new build`

// LOOP-9, LOOP-7 (P3-4b-3r-evidence, requirements 1-3): a target that
// crashed and then, on the same binary, prints PASS for every input and
// exits 0 without running the regression is not cleared, whether or not
// it also deletes its crash input. Root kept the input; a new release
// that still fails it keeps the finding open and becomes its producer,
// and a fixed one, replayed on root's copy, clears it.
// REQ: LOOP-9, LOOP-7
func TestAForgedPassOnTheCrashingBinaryClearsNothing(t *testing.T) {
	for _, wipe := range []bool{false, true} {
		t.Run(map[bool]string{false: "input kept", true: "input deleted"}[wipe], func(t *testing.T) {
			release, mode := t.TempDir(), filepath.Join(t.TempDir(), "mode")
			g := newFake()
			tg := fakeTarget(t, release, forger(mode, wipe))
			details := corpus(t, tg, map[string]string{"bad": "synthetic crash"})
			data, err := os.ReadFile(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzFake", "bad"))
			if err != nil {
				t.Fatal(err)
			}
			evidence := t.TempDir()
			s := newSource(t, g, Config{Targets: []Target{tg}, Release: release, Evidence: evidence})
			crashed := fileDigest(t, tg.Binary)
			if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 || len(g.open) != 1 {
				t.Fatalf("n=%d err=%v open %v", n, err, g.open)
			}
			id := g.reported[0].ID
			if g.reported[0].Detail != details["bad"] || g.producer[id] != crashed {
				t.Fatalf("reported %+v producer %q, want %q", g.reported[0], g.producer[id], crashed)
			}
			sum := strings.TrimPrefix(details["bad"], crashPrefix)
			stored := filepath.Join(evidence, "fake", "FuzzFake", sum)
			if b, err := os.ReadFile(stored); err != nil || string(b) != string(data) {
				t.Fatalf("store holds %q %v", b, err)
			}
			if fi, err := os.Stat(stored); err != nil || fi.Mode().Perm() != 0o400 {
				t.Fatalf("stored input mode %v %v", fi, err)
			}

			// The same binary turns forger: nothing it prints clears.
			if err := os.WriteFile(mode, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if _, err := s.Fuzz(context.Background(), tg); err != nil || len(g.open) != 1 || len(g.resolved) != 0 {
					t.Fatalf("forged round %d: err=%v open %v resolved %v", i, err, g.open, g.resolved)
				}
			}
			if b, err := os.ReadFile(stored); err != nil || string(b) != string(data) {
				t.Fatalf("store after the forger holds %q %v", b, err)
			}

			// A new release that still fails the kept input alone keeps it
			// open and becomes its producer.
			fakeBin(t, release, "fake.test", stillFails)
			still := fileDigest(t, tg.Binary)
			if _, err := s.Fuzz(context.Background(), tg); err != nil || len(g.open) != 1 || len(g.resolved) != 0 || g.producer[id] != still {
				t.Fatalf("still failing: err=%v open %v resolved %v producer %q want %q", err, g.open, g.resolved, g.producer[id], still)
			}

			// A fixed release passes root's copy alone and clears it.
			fakeBin(t, release, "fake.test", passAlone(":"))
			fixed := fileDigest(t, tg.Binary)
			if _, err := s.Fuzz(context.Background(), tg); err != nil || len(g.open) != 0 || len(g.resolved) != 1 {
				t.Fatalf("fixed: err=%v open %v resolved %v", err, g.open, g.resolved)
			}
			if r := g.replays[0]; r.Binary != fixed || r.Produced != still || r.Evidence != details["bad"] {
				t.Fatalf("replay %+v, want binary %q produced %q", r, fixed, still)
			}
			// The replay directory is gone once judged.
			if left, _ := filepath.Glob(filepath.Join(s.cfg.CacheDir, "replay-*")); len(left) != 0 {
				t.Fatalf("replay directories left: %v", left)
			}
		})
	}
}

// LOOP-9 (requirement 2): a kept input whose bytes no longer match its
// name is not replayed in its place, and a fixed release clears nothing
// on it.
// REQ: LOOP-9
func TestAKeptInputThatDoesNotMatchItsDigestIsNotReplayed(t *testing.T) {
	release := t.TempDir()
	g := newFake()
	tg := fakeTarget(t, release, `case "$1" in -test.run=^FuzzFake\$*) echo "--- FAIL: FuzzFake/bad (0.00s)"; exit 1;; esac; exit 0`)
	details := corpus(t, tg, map[string]string{"bad": "synthetic crash"})
	evidence := t.TempDir()
	s := newSource(t, g, Config{Targets: []Target{tg}, Release: release, Evidence: evidence})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if err := os.RemoveAll(filepath.Join(tg.Dir, "testdata")); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(evidence, "fake", "FuzzFake", strings.TrimPrefix(details["bad"], crashPrefix))
	if err := os.Chmod(stored, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored, []byte("go test fuzz v1\n[]byte(\"ab\")\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeBin(t, release, "fake.test", passAlone(":"))
	if _, err := s.Fuzz(context.Background(), tg); err == nil || len(g.open) != 1 || len(g.resolved) != 0 {
		t.Fatalf("err=%v open %v resolved %v", err, g.open, g.resolved)
	}
}

// LOOP-7 (requirement 2): New refuses an evidence store the children
// could reach, or one that is not an absolute clean path.
// REQ: LOOP-7
func TestAnEvidenceStoreTheChildrenWriteIsRefused(t *testing.T) {
	release := t.TempDir()
	tg := fakeTarget(t, release, "exit 0")
	cache := t.TempDir()
	for name, ev := range map[string]string{
		"empty":           "",
		"relative":        "evidence",
		"unclean":         tg.Dir + "/../x",
		"in the target":   filepath.Join(tg.Dir, "evidence"),
		"over the target": filepath.Dir(tg.Dir),
		"in the cache":    filepath.Join(cache, "evidence"),
	} {
		if _, err := New(Config{Inner: newFake(), Report: newFake(), Targets: []Target{tg}, Release: release, CacheDir: cache, Evidence: ev}); err == nil {
			t.Errorf("%s: evidence store %q accepted", name, ev)
		}
	}
}

// LOOP-7, LOOP-9 (requirements 2 and 3, the threat check): jailed, the
// child judged on a kept input can write neither root's store nor the
// directory it is replayed from, nor the input itself. The new binary
// tries each; any write that lands fails the run, and none may land.
// REQ: LOOP-7, LOOP-9
func TestAJailedChildCannotWriteTheStoreOrItsReplay(t *testing.T) {
	needRoot(t)
	base := jailDir(t)
	release, evidence := filepath.Join(base, "release"), filepath.Join(base, "evidence")
	if err := os.Mkdir(release, 0o755); err != nil {
		t.Fatal(err)
	}
	// Traversable, unlike agentosd's, so only the store's own modes stop
	// the child.
	if err := os.Mkdir(evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	tg := Target{Pkg: "fake", Name: "FuzzFake", Binary: fakeBin(t, release, "fake.test", `case "$1" in -test.run=^FuzzFake\$*) echo "--- FAIL: FuzzFake/0crash (0.00s)"; exit 1;; esac; exit 0`), Dir: filepath.Join(base, "state", "targets", "fake")}
	if err := os.MkdirAll(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzFake"), 0o700); err != nil {
		t.Fatal(err)
	}
	in := cacheFile(t, tg.Dir, "testdata/fuzz/FuzzFake/0crash", 10, 0)
	data, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	j := &Jail{UID: nobody, GID: nobody, State: filepath.Join(base, "state")}
	if err := j.Own(); err != nil {
		t.Fatal(err)
	}
	g := newFake()
	s := newSource(t, g, Config{Targets: []Target{tg}, CacheDir: filepath.Join(base, "state", "cache"), Jail: j, Evidence: evidence})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 || len(g.open) != 1 {
		t.Fatalf("n=%d err=%v open %v", n, err, g.open)
	}
	sum := strings.TrimPrefix(g.reported[0].Detail, crashPrefix)
	stored := filepath.Join(evidence, "fake", "FuzzFake", sum)

	fakeBin(t, release, "fake.test", `case "$1" in
-test.run=^FuzzFake\$/*)
  n=${1#*/^}; n=${n%\$}
  for p in testdata/fuzz/FuzzFake/$n testdata/fuzz/FuzzFake/new testdata/new new `+evidence+`/new `+filepath.Dir(stored)+`/new `+stored+`; do
    if (echo x >> "$p") 2>/dev/null; then echo "wrote $p"; exit 1; fi
  done
  if mv testdata/fuzz/FuzzFake/$n x 2>/dev/null || rm -f testdata/fuzz/FuzzFake/$n 2>/dev/null && [ ! -e testdata/fuzz/FuzzFake/$n ]; then echo "moved $n"; exit 1; fi
  echo "--- PASS: FuzzFake/$n (0.00s)";;
esac
exit 0`)
	if _, err := s.Fuzz(context.Background(), tg); err != nil || len(g.open) != 0 || len(g.resolved) != 1 {
		t.Fatalf("err=%v open %v resolved %v reported %+v", err, g.open, g.resolved, g.reported)
	}
	if b, err := os.ReadFile(stored); err != nil || string(b) != string(data) {
		t.Fatalf("store holds %q %v", b, err)
	}
}
