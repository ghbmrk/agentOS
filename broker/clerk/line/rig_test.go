package line

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"

	"github.com/icholy/digest"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/sipsign"
)

// Synthetic numbers and a canary password; none is real.
const (
	t0       = int64(1_792_400_000_000)
	dayMS    = int64(86_400_000)
	domain   = "voip.test"
	user     = "acct1001"
	realm    = "voip.test"
	password = "canary-line-password-7f3a" // synthetic canary
	lineNum  = "+15550000300"
	boxNum   = "+15550000100" // the owner channel (CH-1)
	ownerNum = "+15550000001"
	shopNum  = "+15550000777" // an owner-created contact
	dentist  = "+15550000888" // a number the owner fixed
	stranger = "+15550000999" // neither
)

func seed(b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

func anchors() []key.PublicKey {
	o, _ := seed(1)
	b, _ := seed(12)
	return []key.PublicKey{key.Ed25519(o), key.Ed25519(b)}
}

// fakeLine is the line process: it records each text and, like sipline,
// asks the signer to answer the provider's MESSAGE challenge first.
type fakeLine struct {
	mu     sync.Mutex
	signer *Signer
	sent   []string // "to: words"
	// answer, when set, decides Send's answer after the text went out;
	// before, when set, answers instead of sending.
	answer func() error
	before func(ctx context.Context) error
}

func (f *fakeLine) Send(ctx context.Context, to, words string) error {
	if f.before != nil {
		if err := f.before(ctx); err != nil {
			return err
		}
	}
	if f.signer != nil {
		if _, err := f.signer.Sign(ctx, challenge("MESSAGE", "sip:"+to+"@"+domain)); err != nil {
			return fmt.Errorf("%w: %w", ErrNotTaken, err)
		}
	}
	f.mu.Lock()
	f.sent = append(f.sent, to+": "+words)
	f.mu.Unlock()
	if f.answer != nil {
		return f.answer()
	}
	return nil
}

func (f *fakeLine) texts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

// challenge is the provider's qop=auth digest challenge for one request.
func challenge(method, uri string) sipsign.Challenge {
	return sipsign.Challenge{Header: `Digest realm="` + realm + `", nonce="n0nce", qop="auth", algorithm=MD5`, Method: method, URI: uri}
}

// verifies reports whether auth answers c with the account's password, as
// the provider would check it.
func verifies(t *testing.T, c sipsign.Challenge, auth string) bool {
	t.Helper()
	cred, err := digest.ParseCredentials(auth)
	if err != nil {
		t.Fatalf("unparsable answer: %v", err)
	}
	ch, _ := digest.ParseChallenge(c.Header)
	want, err := digest.Digest(ch, digest.Options{Method: c.Method, URI: c.URI, Username: user, Password: password, Cnonce: cred.Cnonce, Count: cred.Nc})
	return err == nil && want.Response == cred.Response && cred.URI == c.URI
}

// rig is a real kernel with the line clerk, an owner key for it and a
// planner key derived from it.
type rig struct {
	c       *Clerk
	signer  *Signer
	line    *fakeLine
	k       *kernel.Kernel
	planner key.Key
	priv    ed25519.PrivateKey
	now     int64
	logged  []Entry
	results map[string]kernel.Result
	// ctx, when set, is the context the kernel's Do runs the clerk under.
	ctx context.Context

	mu sync.Mutex
}

// recorder keeps each result the kernel got from the clerk.
type recorder struct{ r *rig }

func (w recorder) Do(q kernel.Request, v kernel.View) kernel.Result {
	ctx := w.r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	res := w.r.c.DoContext(ctx, q, v)
	w.r.mu.Lock()
	w.r.results[q.Plan.ID] = res
	w.r.mu.Unlock()
	return res
}
func (w recorder) Probe(q kernel.Request, v kernel.View) kernel.Result { return w.r.c.Probe(q, v) }

// newClerk is a clerk with a set, confirmed account and its signer.
func newClerk(t *testing.T, now *int64, l *fakeLine, logged *[]Entry) (*Clerk, *Signer) {
	t.Helper()
	sealer, err := clerk.NewAESSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Anchors: anchors(), Secrets: clerk.NewSecrets(sealer, nil), Line: l,
		Numbers: Numbers{Owner: ownerNum, Channel: boxNum}, Clock: func() int64 { return *now },
		Log: func(e Entry) { *logged = append(*logged, e) }})
	if err != nil {
		t.Fatal(err)
	}
	s := NewSigner(c)
	l.signer = s
	c.SetContacts([]Contact{{Name: "Shop", Number: shopNum}, {Name: "Pharmacy", Number: "72345"}, {Name: "Hotline", Number: "+19005550123"}})
	c.SetFixed([]string{dentist, "+19005550199"})
	return c, s
}

// setUp sets the account, registers once to learn the realm and confirms it.
func setUp(t *testing.T, c *Clerk, s *Signer) {
	t.Helper()
	if err := c.Account().Set(sipsign.Settings{Server: "sip.voip.test:5061", Domain: domain, User: user, Number: lineNum}, password); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), challenge("REGISTER", "sip:"+domain)); err != nil {
		t.Fatal(err)
	}
	if err := c.Account().ConfirmRealm(realm); err != nil {
		t.Fatal(err)
	}
}

func newRig(t *testing.T, account bool, caveats ...key.Caveat) *rig {
	t.Helper()
	r := &rig{line: &fakeLine{}, now: t0, results: map[string]kernel.Result{}}
	r.c, r.signer = newClerk(t, &r.now, r.line, &r.logged)
	if account {
		setUp(t, r.c, r.signer)
	}
	_, ownerPriv := seed(1)
	holderPub, holderPriv := seed(2)
	headPub, headPriv := seed(3)
	plannerPub, plannerPriv := seed(4)
	r.priv = plannerPriv
	log, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: headPub, Sign: headPriv,
		Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	r.k, err = kernel.Boot(log, anchors(), map[string]kernel.Clerk{Name: recorder{r}}, t0-dayMS)
	if err != nil {
		t.Fatal(err)
	}
	root, err := key.ClerkKey(key.Issue(key.Ed25519Signer(ownerPriv), key.Root{Clerk: Name, Verbs: []key.Verb{key.Send}, Serial: "line-1"}),
		key.Ed25519Signer(ownerPriv), holderPub, t0-dayMS-kernel.GrantHold, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, backup := seed(12)
	batch := []key.Key{{Root: root.Root}, root}
	if err := r.k.Issue(t0-dayMS-kernel.GrantHold, []key.Cosign{key.Approve(key.Ed25519Signer(ownerPriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(backup), kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	if err := log.Anchor(); err != nil {
		t.Fatal(err)
	}
	r.planner, err = key.Derive(root, holderPriv, plannerPub, caveats...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// text submits one send and runs the kernel; it returns the clerk's result.
func (r *rig) text(t *testing.T, id, to, words string) kernel.Result {
	t.Helper()
	p := kernel.SignPlan(kernel.Plan{ID: id, Key: r.planner, Steps: []kernel.PlanStep{{Verb: key.Send, Clerk: Name, Args: map[string]string{"to": to, "msg": words}}}}, r.priv)
	if err := r.k.Submit(r.now, p); err != nil {
		return kernel.Result{Outcome: "failed", Detail: "submit: " + err.Error()}
	}
	if err := r.k.Tick(r.now); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	res, ok := r.results[id]
	if !ok {
		return kernel.Result{Outcome: "failed", Detail: "kernel: not dispatched"}
	}
	return res
}

func contains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
