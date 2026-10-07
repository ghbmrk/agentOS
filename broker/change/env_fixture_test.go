package change

import (
	"bytes"
	"testing"
)

// REQ: CHG-1
// Forget/cascade fixtures require auto-adoption before testing their own
// assertions. A random fixture split can fall below MinHeldOut and instead
// ask the mock owner, which refuses. Keep both sides reproducible in tests.
func TestFixtureSplitIsReproducibleAndHasAdoptionPrerequisites(t *testing.T) {
	a, b := newEnv(t, nil), newEnv(t, nil)
	if !bytes.Equal(a.p.key, b.p.key) {
		t.Fatal("fixture splits differ across fresh environments")
	}
	a.cases(12, ClassSkill, "skills/greet", "hello")
	devCount := len(a.p.Dev(ClassSkill))
	held := 12 - devCount
	if devCount == 0 || held < a.p.cfg.MinHeldOut {
		t.Fatalf("fixture lacks both sides and minimum held-out: dev=%d held=%d", devCount, held)
	}
}
func TestFixtureAllowsExplicitEntropyOverride(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	e := newEnv(t, func(c *Config) { c.Rand = bytes.NewReader(key) })
	if !bytes.Equal(e.p.key, key) {
		t.Fatal("test's entropy override ignored")
	}
}
