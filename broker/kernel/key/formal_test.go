package key_test

// REQ: KEY-1, KEY-2, KEY-3, KEY-4, KEY-6, KEY-7, KEY-8

// The model-checked vectors (FRM-key, #2936). kernel/formal/KeyVerdict.tla
// models the key check; TLC checks its invariants (no link widens authority, holds never
// shorten, labels only accumulate, a stop, revocation, pause or expiry admits
// nothing) over every state it reaches, and kernel/formal/vectors.py writes each
// state's key, context and verdicts here. This test builds each key for real,
// signs it, and requires Verify, Authorize and Window to give the model's
// answer for every step. testdata/formal/key.json is a fixed sample; CI's
// formal job sets FORMAL_VECTORS to a directory holding every state.

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const fHour = int64(3_600_000) // one model time unit

type fStep struct {
	Verb   string   `json:"verb"`
	Labels []string `json:"labels"`
}

type fState struct {
	Root    bool              `json:"root"`
	Chain   []json.RawMessage `json:"chain"` // [signer, kind, set, n, m]
	Now     int64             `json:"now"`
	Used    int               `json:"used"`
	Cut     [2]any            `json:"cut"` // [kind, prefix index]
	Verdict []string          `json:"verdict"`
	Window  [2]int64          `json:"window"`
}

type fLink struct {
	signer, kind string
	set          []string
	n, m         int64
}

func (l *fLink) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &[]any{&l.signer, &l.kind, &l.set, &l.n, &l.m})
}

func fParty(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

// fLedger charges the same n uses, an hour old, to every scope.
type fLedger struct {
	n  int
	at int64
}

func (f fLedger) Uses(key.ID) []key.Use {
	out := make([]key.Use, f.n)
	for i := range out {
		out[i] = key.Use{At: f.at - fHour, Recipient: "x", Task: "t"}
	}
	return out
}

func formalVectors(t *testing.T) (steps []fStep, states []fState) {
	t.Helper()
	path := filepath.Join("testdata", "formal", "key.json")
	if d := os.Getenv("FORMAL_VECTORS"); d != "" {
		path = filepath.Join(d, "key.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Steps  []fStep  `json:"steps"`
		States []fState `json:"states"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.States) == 0 || len(f.Steps) == 0 {
		t.Fatalf("%s holds no vectors", path)
	}
	return f.Steps, f.States
}

func TestFormalKeyVerdict(t *testing.T) {
	steps, states := formalVectors(t)
	owner, ownerPriv := fParty(1)
	holder, holderPriv := fParty(2)
	_, strangerPriv := fParty(3)
	owners := []key.PublicKey{key.Ed25519(owner)}
	signers := map[string]ed25519.PrivateKey{"holder": holderPriv, "passkey": ownerPriv, "stranger": strangerPriv}

	type built struct {
		k   key.Key
		ver *key.Verified
		err error
	}
	cache := map[string]built{}
	build := func(s fState) built {
		id, _ := json.Marshal([]any{s.Root, s.Chain})
		if b, ok := cache[string(id)]; ok {
			return b
		}
		issuer := ownerPriv
		if !s.Root {
			issuer = strangerPriv
		}
		root := key.Issue(key.Ed25519Signer(issuer), key.Root{Clerk: "mail", Verbs: []key.Verb{key.Organize, key.Unsubscribe}, Serial: "formal"})
		k, err := key.ClerkKey(root, key.Ed25519Signer(ownerPriv), holder, 0, 1<<40)
		if err != nil {
			t.Fatalf("the grant: %v", err)
		}
		for _, raw := range s.Chain {
			var l fLink
			if err := json.Unmarshal(raw, &l); err != nil {
				t.Fatal(err)
			}
			var c key.Caveat
			switch l.kind {
			case "verbs":
				vs := make([]key.Verb, len(l.set))
				for i, v := range l.set {
					vs[i] = key.Verb(v)
				}
				c = key.LimitVerbs(vs...)
			case "labels":
				c = key.LimitLabels(l.set...)
			case "hold":
				c = key.LimitHold(l.n*fHour, l.m*fHour)
			case "expires":
				c = key.LimitExpires(l.n * fHour)
			case "uses":
				c = key.LimitUses(l.n)
			default:
				t.Fatalf("caveat kind %q", l.kind)
			}
			k = key.Extend(k, signers[l.signer], key.Link{Caveats: []key.Caveat{c}, Holder: holder})
		}
		use := []byte("formal")
		ver, err := key.Verify(k, owners, use, key.Sign(k, holderPriv, use))
		b := built{k, ver, err}
		cache[string(id)] = b
		return b
	}

	for n, s := range states {
		b := build(s)
		if (b.err != nil) != (s.Verdict[0] == "invalid") {
			t.Fatalf("state %d: Verify gave %v, the model %q (KEY-1, KEY-3)\n%s", n, b.err, s.Verdict[0], show(s))
		}
		if b.err != nil {
			continue
		}
		if got := [2]int64{b.ver.Limits.Window(false) / fHour, b.ver.Limits.Window(true) / fHour}; got != s.Window {
			t.Fatalf("state %d: windows %v, the model %v (KEY-8)\n%s", n, got, s.Window, show(s))
		}
		ch := &key.Changes{Revoked: map[key.ID]bool{}, Paused: map[key.ID]bool{}}
		switch kind, i := s.Cut[0].(string), int(s.Cut[1].(float64)); kind {
		case "stop":
			ch.Stopped = true
		case "revoke":
			ch.Revoked[b.ver.IDs[i]] = true
		case "pause":
			ch.Paused[b.ver.IDs[i]] = true
		}
		now := s.Now * fHour
		ctx := key.Context{Now: now, Changes: ch, Ledger: fLedger{s.Used, now}}
		for i, st := range steps {
			step := key.Step{Verb: key.Verb(st.Verb), Clerk: "mail", Args: map[string]key.Arg{},
				Labels: st.Labels, Recipient: "x", Task: "t"}
			for _, a := range key.ArgNames(step.Verb) {
				step.Args[a] = key.Arg{Value: "x", Source: key.SrcClerk}
			}
			got := "ok"
			if r := b.ver.Authorize(step, ctx); r != nil {
				got = r.Code
			}
			if got != s.Verdict[i] {
				t.Fatalf("state %d, step %v: Authorize %q, the model %q (KEY-2, KEY-6, KEY-7)\n%s", n, st, got, s.Verdict[i], show(s))
			}
		}
	}
	t.Logf("%d model states, %d keys, %d steps each", len(states), len(cache), len(steps))
}

func show(s fState) string {
	b, _ := json.Marshal(s)
	return string(b)
}
