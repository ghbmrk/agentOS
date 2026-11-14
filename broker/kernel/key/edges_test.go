package key

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

// REQ: KEY-1, KEY-2, KEY-3, KEY-4, KEY-7, KRN-5

// The edges of the key check that the main tests reach without pinning:
// each test here fails when one statement of the check is deleted (mutgate,
// #5676).

// A malformed caveat is ErrMalformed and a widening one ErrLoosens, never
// the other or nothing (KEY-3).
func TestEveryCaveatRuleHoldsAlone(t *testing.T) {
	_, holder, k := root(t)
	next := gen(3)
	lo, hi := int64(1), int64(5)
	k2, err := Derive(k, holder.priv, next.pub, LimitArg(ArgBound{Name: "n", Min: &lo, Max: &hi}), LimitTask("t1"))
	if err != nil {
		t.Fatal(err)
	}
	lower := int64(0)
	for _, c := range []struct {
		name string
		from Key
		cav  Caveat
		want error
	}{
		{"unknown verb", k, Caveat{Kind: KVerbs, Set: []string{"bogus"}}, ErrMalformed},
		{"arg bound with no name", k, Caveat{Kind: KArg, Arg: &ArgBound{}}, ErrMalformed},
		{"arg min lowered", k2, LimitArg(ArgBound{Name: "n", Min: &lower, Max: &hi}), ErrLoosens},
		{"negative cap", k, Caveat{Kind: KUses, N: -1}, ErrMalformed},
		{"two tasks", k, Caveat{Kind: KTask, Set: []string{"a", "b"}}, ErrMalformed},
		{"another task", k2, LimitTask("t2"), ErrLoosens},
	} {
		from, signer := c.from, holder.priv
		if len(from.Links) == 2 {
			signer = next.priv
		}
		if _, err := Derive(from, signer, gen(4).pub, c.cav); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// A root's verbs are known and canonical, and a link's holder is a whole key,
// whoever signed them (KEY-1).
func TestARootAndLinkAreWellFormed(t *testing.T) {
	owner := gen(1)
	owners := []PublicKey{owner.pk}
	for name, vs := range map[string][]Verb{"unknown": {Organize, "bogus"}, "unsorted": {Trash, Organize}} {
		r := Root{Owner: owner.pk, Clerk: "mail", Verbs: vs, Serial: "r1"}
		if _, err := Chain(AttachRoot(r, owner.pass.Sign(RootMsg(r))), owners); !errors.Is(err, ErrMalformed) {
			t.Errorf("root verbs %s: %v", name, err)
		}
	}
	if _, err := ClerkKey(bare(owner), owner.pass, gen(2).pub[:31], 0, 1); !errors.Is(err, ErrMalformed) {
		t.Errorf("short holder: %v", err)
	}
	_, _, k := root(t)
	if _, err := ClerkKey(k, owner.pass, gen(3).pub, 0, 1); !errors.Is(err, ErrNotHolder) {
		t.Errorf("ClerkKey off a derived key: %v", err)
	}
}

// IDs are SHA-256 over the domain and every signed byte, signature included,
// so two spellings of a key are two IDs (KEY-7).
func TestIDsHashTheDomainAndEveryByte(t *testing.T) {
	owner, holder, k := root(t)
	sum := func(parts ...[]byte) ID {
		h := sha256.New()
		for _, p := range parts {
			h.Write(p)
		}
		var id ID
		h.Sum(id[:0])
		return id
	}
	r := k.Root
	rid := sum([]byte(domainID), rootBody(r), r.Sig)
	if rootID(r) != rid {
		t.Error("rootID")
	}
	l := k.Links[0]
	if linkID(rid, l) != sum([]byte(domainID), rid[:], linkBody(l), l.Sig) {
		t.Error("linkID")
	}
	acct := sum([]byte(domainID), []byte("account\x00"), rid[:], holder.pub)
	if account(rid, holder.pub) != acct {
		t.Error("account")
	}
	// A first link's caps are charged to the clerk's account under the root,
	// the last of its scopes; a bare root has only its own.
	v := verified(t, k, owner, holder)
	if s := v.Scopes(); len(s) != 3 || s[2] != acct {
		t.Errorf("scopes %v, account %v", s, acct)
	}
	for _, cp := range v.Limits.Caps {
		if cp.Scope != acct {
			t.Errorf("cap %s charged to %v, not the account", cp.Kind, cp.Scope)
		}
	}
	bv, err := Chain(bare(owner), []PublicKey{owner.pk})
	if err != nil {
		t.Fatal(err)
	}
	if s := bv.Scopes(); len(s) != 1 || s[0] != rootID(bv.Key.Root) {
		t.Errorf("bare root scopes %v", s)
	}
}

// A step carries exactly its verb's arguments, each with a value, and no
// negative amount (KEY-2).
func TestAStepCarriesExactlyItsArgs(t *testing.T) {
	owner, holder, k := root(t)
	v := verified(t, k, owner, holder)
	c := ctx(0, ledger{})
	if r := v.Authorize(step(Unsubscribe), c); r != nil {
		t.Fatal(r)
	}
	if len(ArgNames(Unsubscribe)) == 0 {
		t.Fatal("unsubscribe takes no args")
	}
	missing := step(Unsubscribe)
	missing.Args = map[string]Arg{}
	extra := step(Unsubscribe)
	extra.Args["extra"] = Arg{Value: "x"}
	renamed := step(Unsubscribe)
	empty := step(Unsubscribe)
	for _, n := range ArgNames(Unsubscribe) {
		delete(renamed.Args, n)
		renamed.Args[n+"?"] = Arg{Value: "x"}
		empty.Args[n] = Arg{}
	}
	for name, s := range map[string]Step{"missing": missing, "extra": extra, "renamed": renamed, "empty": empty} {
		if ArgsDeclared(s) {
			t.Errorf("ArgsDeclared(%s)", name)
		}
		if r := v.Authorize(s, c); r == nil || r.Code != RArg {
			t.Errorf("%s: %v", name, r)
		}
	}
	neg := step(Organize)
	neg.Amount = -1
	if r := v.Authorize(neg, c); r == nil || r.Code != RMalformed {
		t.Errorf("negative amount: %v", r)
	}
}

// A rate cap counts the day's steps and no older one (KEY-3).
func TestARateCapCountsTheDay(t *testing.T) {
	owner, holder, k := root(t)
	now := 10 * DayMS
	d, err := Derive(k, holder.priv, gen(3).pub, LimitRate(1))
	if err != nil {
		t.Fatal(err)
	}
	v := verified(t, d, owner, gen(3))
	id := v.ID()
	if r := v.Authorize(step(Organize), ctx(now, ledger{id: {{At: now - DayMS}}})); r != nil {
		t.Errorf("a day-old step counted: %v", r)
	}
	if r := v.Authorize(step(Organize), ctx(now, ledger{id: {{At: now - 1}}})); r == nil || r.Code != RRate {
		t.Errorf("today's step not counted: %v", r)
	}
}

// Spend checks only a live key, for its task, with a spend cap and a
// non-negative amount, and counts no step cap (LOG-7, KRN-5).
func TestSpendChecksItsOwnRules(t *testing.T) {
	_, holder, k := root(t)
	d, err := Derive(k, holder.priv, gen(3).pub, LimitUses(1), LimitTask("t"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Chain(d, []PublicKey{gen(1).pk})
	if err != nil {
		t.Fatal(err)
	}
	used := ledger{v.ID(): {{At: 1, Task: "t"}}}
	if r := v.Spend("t", 1, ctx(2, used)); r != nil {
		t.Errorf("a spent use cap refused a spend: %v", r)
	}
	if r := v.Spend("t", -1, ctx(2, used)); r == nil || r.Code != RMalformed {
		t.Errorf("negative spend: %v", r)
	}
	if r := v.Spend("u", 1, ctx(2, used)); r == nil || r.Code != RTask {
		t.Errorf("another task: %v", r)
	}
	c := ctx(2, used)
	c.Changes.Revoked[v.ID()] = true
	if r := v.Spend("t", 1, c); r == nil || r.Code != RRevoked {
		t.Errorf("revoked: %v", r)
	}
	nocap := &Verified{Key: d, IDs: v.IDs, Limits: Limits{Clerk: "mail"}}
	if r := nocap.Spend("", 1, ctx(2, ledger{})); r == nil || r.Code != RMalformed {
		t.Errorf("no spend cap: %v", r)
	}
}

// A use is a bare root's alone, a signer counts as one approver, and the
// zero passkey signs nothing (KEY-4).
func TestSignersAndApprovers(t *testing.T) {
	owner, _, k := root(t)
	other := gen(5)
	owners := []PublicKey{owner.pk, other.pk}
	use := []byte("use")
	if p := UseSigner(k, owners, use, owner.pass.Sign(UseMsg(k, use))); p.Valid() {
		t.Errorf("UseSigner of a derived key: %v", p)
	}
	what := sha256.Sum256([]byte("change"))
	cos := []Cosign{{By: other.pk, Sig: other.pass.Sign(CosignMsg(what))}}
	if !Approved(owners, []PublicKey{other.pk}, what, []PublicKey{owner.pk}, cos) {
		t.Error("a signer and a co-signer are not two approvers")
	}
	if SignedBy(Key{}, PublicKey{}) {
		t.Error("the zero passkey signed the zero key")
	}
}

// A passkey is whole, and decoding resets it (KEY-4).
func TestAPasskeyIsWhole(t *testing.T) {
	if Ed25519(make([]byte, ed25519.PublicKeySize-1)).Valid() {
		t.Error("a short Ed25519 key is valid")
	}
	pk := gen(1).pk
	if err := pk.UnmarshalJSON([]byte(" null ")); err != nil || pk.Valid() {
		t.Errorf("null: %v %v", err, pk)
	}
	pk = gen(1).pk
	if err := json.Unmarshal([]byte("null"), &pk); err != nil || pk.Valid() {
		t.Errorf("json null: %v %v", err, pk)
	}
	// An ES256 key whose point does not parse verifies nothing, and does not
	// panic. No constructor makes one; this pins the check that stands
	// behind them.
	a := newAuthenticator(t, "example.com")
	msg := []byte("m")
	var as Assertion
	if err := json.Unmarshal(a.Sign(msg), &as); err != nil {
		t.Fatal(err)
	}
	bad := PublicKey{alg: AlgES256, rpID: "example.com", raw: string(bytes.Repeat([]byte{4}, 65))}
	if bad.VerifyAssertion(msg, as) {
		t.Error("an off-curve point verified")
	}
}
