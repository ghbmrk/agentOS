package change

import (
	"bytes"
	"testing"
)

// REQ: CHG-1
// The test env pins its split key (testSplitKey), so a fixture's dev and
// held-out sides are the same every run. Fixtures need both: split tests
// need a non-empty dev side, and auto-adoption needs at least MinHeldOut
// held-out cases or the mock owner refuses. Under a random key a 12-case
// fixture missed the first about 1 env in 70 and the second about 1 in
// 5000 (#491). This test fails loudly if the key, DevPercent or MinHeldOut
// changes so that the pinned split no longer meets both. Draft: #273.
func TestFixtureSplitIsPinnedAndAdoptable(t *testing.T) {
	a, b := newEnv(t, nil), newEnv(t, nil)
	if !bytes.Equal(a.p.key, testSplitKey) || !bytes.Equal(b.p.key, testSplitKey) {
		t.Fatal("test env split key is not the pinned testSplitKey")
	}
	const n = 12
	a.cases(n, ClassSkill, "skills/greet", "hello")
	b.cases(n, ClassSkill, "skills/greet", "hello")
	devA, devB := len(a.p.Dev(ClassSkill)), len(b.p.Dev(ClassSkill))
	if devA != devB {
		t.Fatalf("same fixture split differently across envs: dev=%d vs %d", devA, devB)
	}
	if held := n - devA; devA == 0 || held < a.p.cfg.MinHeldOut {
		t.Fatalf("pinned split lacks a side: dev=%d held-out=%d, need dev>0 and held-out>=%d", devA, held, a.p.cfg.MinHeldOut)
	}
}

// REQ: CHG-1
// A test that needs another split key sets Rand through newEnv's mod; the
// pinned default must not override it.
func TestFixtureEntropyOverride(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	e := newEnv(t, func(c *Config) { c.Rand = bytes.NewReader(key) })
	if !bytes.Equal(e.p.key, key) {
		t.Fatal("test's entropy override ignored")
	}
}
