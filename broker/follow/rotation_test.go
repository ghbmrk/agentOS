package follow

// REQ: OSS-10, UPD-8, OSS-9

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// rotated is prev's next version with its root keys replaced by two fresh
// ones, signed by prev's keys (old) and the new: a TUF root rotation.
func rotated(t *testing.T, prev []byte, old []ed25519.PrivateKey) ([]byte, []ed25519.PrivateKey) {
	t.Helper()
	m, err := metadata.Root().FromBytes(prev)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range append([]string(nil), m.Signed.Roles[metadata.ROOT].KeyIDs...) {
		if err := m.Signed.RevokeKey(id, metadata.ROOT); err != nil {
			t.Fatal(err)
		}
	}
	keys := []ed25519.PrivateKey{newKey(t), newKey(t)}
	for _, k := range keys {
		key, err := metadata.KeyFromPublicKey(k.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Signed.AddKey(key, metadata.ROOT); err != nil {
			t.Fatal(err)
		}
	}
	m.Signed.Version++
	m.ClearSignatures()
	for _, k := range append(append([]ed25519.PrivateKey(nil), old...), keys...) {
		if _, err := m.Sign(signerOf(k)); err != nil {
			t.Fatal(err)
		}
	}
	b, err := m.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return b, keys
}

func (r *rig) describeChain(root []byte, chain ...[]byte) string {
	r.t.Helper()
	sum, err := r.x.Describe(context.Background(), root, chain...)
	if err != nil {
		r.t.Fatal(err)
	}
	return sum.Digest
}

// OSS-10w-r: after the project rotates its root keys twice, its current
// root alone is not the project's; with the rotation between, it is, at
// describe time and at the switch.
func TestOSS10wrSwitchBackAfterARotation(t *testing.T) {
	r := newRig(t)
	if out := r.run(grants.FollowIntent("a1", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	v2, k2 := rotated(t, r.shipped, r.pk)
	v3, _ := rotated(t, v2, k2)
	alone := r.describe(v3)
	if r.x.Project(context.Background(), alone) {
		t.Fatal("a twice-rotated root with no chain read as the project's")
	}
	if out := r.run(grants.FollowIntent("a2", "", alone)); out.Result != journal.ResultNotApplied ||
		!strings.Contains(out.Evidence, "project's own root") || !r.trusts(r.fork) {
		t.Fatalf("switched back with no chain: %+v", out)
	}
	d := r.describeChain(v3, v2)
	if d != alone || !r.x.Project(context.Background(), d) {
		t.Fatal("the chained root is not the project's, or its digest moved")
	}
	if out := r.run(grants.FollowIntent("a3", "", d)); out.Result != journal.ResultSucceeded || !r.trusts(v3) {
		t.Fatalf("switching back through the rotation: %+v", out)
	}
	if src, _ := r.store.Following(); src != (update.Followed{}) {
		t.Fatalf("still following %+v", src)
	}
}

// Threat: a fork that rotates its own keys is never the project's, chain
// or not, but can still be followed under a name.
func TestOSS10wrForkRotationIsNotTheProject(t *testing.T) {
	r := newRig(t)
	fk := []ed25519.PrivateKey{newKey(t), newKey(t)}
	f1 := rootOf(t, fk[0], fk[1])
	f2, _ := rotated(t, f1, fk)
	d := r.describeChain(f2, f1)
	if r.x.Project(context.Background(), d) {
		t.Fatal("a fork's own rotation read as the project's")
	}
	if out := r.run(grants.FollowIntent("a1", "", d)); out.Result != journal.ResultNotApplied || !r.trusts(r.shipped) {
		t.Fatalf("%+v", out)
	}
	if out := r.run(grants.FollowIntent("a2", "Acme", d)); out.Result != journal.ResultSucceeded || !r.trusts(f2) {
		t.Fatalf("following the fork by name: %+v", out)
	}
}

// Threat: a forged link, signed by its new keys alone, does not carry the
// shipped root to the project's next.
func TestOSS10wrForgedLinkIsRefused(t *testing.T) {
	r := newRig(t)
	v2, k2 := rotated(t, r.shipped, nil) // not signed by the shipped keys
	v3, _ := rotated(t, v2, k2)
	if d := r.describeChain(v3, v2); r.x.Project(context.Background(), d) {
		t.Fatal("a chain through a forged link read as the project's")
	}
	if d := r.describeChain(v2); r.x.Project(context.Background(), d) {
		t.Fatal("a forged next root read as the project's")
	}
}

// Threat: rollback. A box that trusted the project at v3 before leaving
// for a fork walks from v3: v2 (chained from the shipped root) and the
// shipped root are refused, v3 and v4 admitted.
func TestOSS10wrSwitchBackNeverRollsBack(t *testing.T) {
	r := newRig(t)
	v2, k2 := rotated(t, r.shipped, r.pk)
	v3, k3 := rotated(t, v2, k2)
	v4, _ := rotated(t, v3, k3)
	if out := r.run(grants.FollowIntent("a1", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	if out := r.run(grants.FollowIntent("a2", "", r.describeChain(v3, v2))); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	if out := r.run(grants.FollowIntent("a3", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	for name, d := range map[string]string{"v2": r.describeChain(v2), "shipped": r.describe(r.shipped)} {
		if r.x.Project(context.Background(), d) {
			t.Fatalf("%s read as the project's after the box trusted v3", name)
		}
		if out := r.run(grants.FollowIntent("b-"+name, "", d)); out.Result != journal.ResultNotApplied || !r.trusts(r.fork) {
			t.Fatalf("switched back to %s: %+v", name, out)
		}
	}
	if !r.x.Project(context.Background(), r.describe(v3)) || !r.x.Project(context.Background(), r.describeChain(v4)) {
		t.Fatal("v3, or v4 chained from it, is not the project's")
	}
}

// Security F1 on #476 (rollback): a box back on the project chain walks
// from the root it trusts now, not from the one it trusted when it left.
// After switching back to v3 through v2, v2 and the shipped root are
// refused, and v3's next is admitted.
func TestOSS10wrBackOnTheProjectNeverRollsBack(t *testing.T) {
	r := newRig(t)
	v2, k2 := rotated(t, r.shipped, r.pk)
	v3, k3 := rotated(t, v2, k2)
	v4, _ := rotated(t, v3, k3)
	if out := r.run(grants.FollowIntent("a1", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	if out := r.run(grants.FollowIntent("a2", "", r.describeChain(v3, v2))); out.Result != journal.ResultSucceeded || !r.trusts(v3) {
		t.Fatalf("%+v", out)
	}
	r.refusesRollback(map[string]string{"v2": r.describeChain(v2), "shipped": r.describe(r.shipped)}, v3)
	if !r.x.Project(context.Background(), r.describeChain(v4)) {
		t.Fatal("v4, chained from the trusted v3, is not the project's")
	}
}

// Security F1 on #476 (rollback): a box that never left the project and
// rotated to v3 through Check walks from v3, not from the shipped root.
func TestOSS10wrCheckRotatedBoxNeverRollsBack(t *testing.T) {
	r := newRig(t)
	v2, k2 := rotated(t, r.shipped, r.pk)
	v3, k3 := rotated(t, v2, k2)
	v4, _ := rotated(t, v3, k3)
	// What Check leaves after verifying v2 and v3 from the project's
	// repository: root.json is v3, and the box never followed anything.
	if err := os.WriteFile(filepath.Join(r.store.Dir, "root.json"), v3, 0o600); err != nil {
		t.Fatal(err)
	}
	r.refusesRollback(map[string]string{"v2": r.describeChain(v2), "shipped": r.describe(r.shipped)}, v3)
	if !r.x.Project(context.Background(), r.describe(v3)) || !r.x.Project(context.Background(), r.describeChain(v4)) {
		t.Fatal("v3, or v4 chained from it, is not the project's")
	}
}

// refusesRollback checks each digest is not the project's and a switch to
// it is not applied, leaving the box on trusted.
func (r *rig) refusesRollback(older map[string]string, trusted []byte) {
	r.t.Helper()
	for name, d := range older {
		if r.x.Project(context.Background(), d) {
			r.t.Fatalf("%s read as the project's after the box trusted a newer root", name)
		}
		if out := r.run(grants.FollowIntent("b-"+name, "", d)); out.Result != journal.ResultNotApplied || !r.trusts(trusted) {
			r.t.Fatalf("switched back to %s: %+v", name, out)
		}
	}
}

// racingStore runs race once, when the executor first reads the anchor or
// asks for the switch: a rotation landing between the page's check and
// the switch.
type racingStore struct {
	*update.Store
	race *func()
}

func (s racingStore) ProjectRoot() ([]byte, error) {
	b, err := s.Store.ProjectRoot()
	s.fire()
	return b, err
}

func (s racingStore) FollowProject(root []byte, links [][]byte, shipped []byte, approved string, o update.Options) error {
	s.fire()
	return s.Store.FollowProject(root, links, shipped, approved, o)
}

func (s racingStore) fire() {
	if f := *s.race; f != nil {
		*s.race = nil
		f()
	}
}

// Security 4a on #667: a rotation between the switch-back check and the
// switch never lets the box trust the older root. The check runs under
// the store's lock, against the anchor at the moment of the write.
func TestOSS10wrRotationDuringASwitchBackIsRefused(t *testing.T) {
	t.Run("Check rotates the project chain", func(t *testing.T) {
		r := newRig(t)
		v2, _ := rotated(t, r.shipped, r.pk)
		race := func() {
			if err := os.WriteFile(filepath.Join(r.store.Dir, "root.json"), v2, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		x := r.with(racingStore{r.store, &race})
		sum, err := x.Describe(context.Background(), r.shipped)
		if err != nil {
			t.Fatal(err)
		}
		if out := x.Execute(context.Background(), grants.FollowIntent("a1", "", sum.Digest), 1); out.Result != journal.ResultNotApplied || !r.trusts(v2) {
			t.Fatalf("switched back past a rotation: %+v", out)
		}
	})
	t.Run("another switch back lands first", func(t *testing.T) {
		r := newRig(t)
		v2, _ := rotated(t, r.shipped, r.pk)
		if out := r.run(grants.FollowIntent("a1", "Acme", r.describe(r.fork))); out.Result != journal.ResultSucceeded {
			t.Fatalf("%+v", out)
		}
		var x *Executor
		race := func() {
			sum, err := x.Describe(context.Background(), v2)
			if err != nil {
				t.Fatal(err)
			}
			if out := x.Execute(context.Background(), grants.FollowIntent("b1", "", sum.Digest), 1); out.Result != journal.ResultSucceeded {
				t.Fatalf("%+v", out)
			}
		}
		x = r.with(racingStore{r.store, &race})
		sum, err := x.Describe(context.Background(), r.shipped)
		if err != nil {
			t.Fatal(err)
		}
		if out := x.Execute(context.Background(), grants.FollowIntent("a2", "", sum.Digest), 1); out.Result != journal.ResultNotApplied || !r.trusts(v2) {
			t.Fatalf("switched back past a newer project root: %+v", out)
		}
		if b, err := r.store.ProjectRoot(); err != nil || string(b) != string(v2) {
			t.Fatalf("anchor lowered: %v", err)
		}
	})
}
