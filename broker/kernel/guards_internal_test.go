package kernel

// Guards of the code a grant's reach runs (KEY-9-reach-b2a): each test fails
// when its one check is dropped or moved by one, so mutgate's reach scope
// finds them tested.
// REQ: KEY-1, KEY-4, KRN-1, LOG-2

import (
	"crypto/ed25519"
	"errors"
	"math"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func seedKey(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return ed25519.NewKeyFromSeed(s)
}

// A holder's daily budget sums its roots' caps, capped at MaxInt64/2 in total,
// so two roots at MaxInt64 sum to MaxInt64/2, never wrapping (#2950).
func TestADayOfTwoHugeCapsStopsAtHalfMaxInt64(t *testing.T) {
	p := &power{days: map[key.ID]int64{{1}: math.MaxInt64, {2}: math.MaxInt64}}
	if got := p.day(); got != math.MaxInt64/2 {
		t.Fatalf("two MaxInt64 caps: %d, want %d", got, int64(math.MaxInt64/2))
	}
	p = &power{days: map[key.ID]int64{{1}: 100, {2}: 50, {3}: -7}}
	if got := p.day(); got != 150 {
		t.Fatalf("caps 100, 50 and a negative: %d, want 150", got)
	}
}

// Power is per holder: two holders of one clerk's keys hold apart.
func TestPowerIsPerHolder(t *testing.T) {
	owner := key.Ed25519Signer(seedKey(1))
	root := key.Issue(owner, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "h"})
	var keys []key.Key
	for _, seed := range []byte{2, 3} {
		k, err := key.ClerkKey(root, owner, seedKey(seed).Public().(ed25519.PublicKey), 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	if got := (&State{}).powers(Reading{}, true, keys); len(got) != 2 {
		t.Fatalf("two holders' keys fold into %d powers, want 2", len(got))
	}
}

// Apply folds only the next entry, and refuses a grant batch it cannot read.
func TestApplyRefusesASeqGapAndAnUnreadableBatch(t *testing.T) {
	if err := (&State{}).Apply(Entry{Seq: 2, Type: TKeyIssued, Body: []byte(`{}`)}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("entry 2 first: %v", err)
	}
	if err := (&State{}).Apply(Entry{Seq: 1, Type: TKeyIssued, Body: []byte(`1`)}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a batch that is a number: %v", err)
	}
}

// A grant is a root or a root's one link: a deeper key is none, whatever
// the passkeys.
func TestADeeperKeyIsNotAGrant(t *testing.T) {
	owner := key.Ed25519Signer(seedKey(1))
	root := key.Issue(owner, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "d"})
	holder := seedKey(2)
	ck, err := key.ClerkKey(root, owner, holder.Public().(ed25519.PublicKey), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	deep, err := key.Derive(ck, holder, seedKey(3).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&State{}).decide(deep, Reading{}, nil); !errors.Is(err, ErrNotAGrant) {
		t.Fatalf("a two-link key: %v", err)
	}
}

// A clerk key whose root was never granted is no grant.
func TestAClerkKeyUnderAnUngrantedRootIsNotAGrant(t *testing.T) {
	ownerKey := seedKey(1)
	owner := key.Ed25519Signer(ownerKey)
	root := key.Issue(owner, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "never"})
	ck, err := key.ClerkKey(root, owner, seedKey(2).Public().(ed25519.PublicKey), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	s := &State{Anchors: []key.PublicKey{key.Ed25519(ownerKey.Public().(ed25519.PublicKey))}}
	if _, err := s.decide(ck, Reading{}, nil); !errors.Is(err, ErrNotAGrant) {
		t.Fatalf("a clerk key alone: %v", err)
	}
}

type noReadStore struct{ MemStore }

type errNoRead struct{}

func (errNoRead) Error() string { return "store not readable" }

func (*noReadStore) ReadAll() ([]byte, error) { return nil, errNoRead{} }

// A store that cannot be read opens no log.
func TestALogIsNotOpenedFromAnUnreadableStore(t *testing.T) {
	if _, err := Open(Config{Store: &noReadStore{}}); !errors.Is(err, errNoRead{}) {
		t.Fatalf("open on a store that cannot be read: %v", err)
	}
}

// Only a step result answers a send: a probe's finding of "unsent" on an
// in-flight step derives no cancel.
func TestOnlyAStepResultIsARefusedSend(t *testing.T) {
	s := &State{Plans: map[string]*PlanState{"p1": {Status: SActive, Steps: []StepState{{Phase: PInflight}}}}}
	e := Entry{Type: TStepProbed, Body: []byte(`{"plan":"p1","index":0,"outcome":"unsent"}`)}
	if d := refusedSend(s, e); d != nil {
		t.Fatalf("a probe derived %+v", *d)
	}
}
