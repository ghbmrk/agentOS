// Package keydiff checks broker/kernel/key against keycheck, the second key
// check written in Rust from SPEC KEY-1..KEY-8 (SPEC §19 risk 32). Each case
// is a key, a step or metered call and a log view built from one seed with
// the Go library; both sides judge it and the test fails on any disagreement:
// whether the chain verifies, the scopes a use is charged to, the hold window,
// and whether the step or call is admitted. The Go library returns its first
// refusal and keycheck every refusal it finds, so the Go code must be one of
// them. Set KEYCHECK to the keycheck binary; without it the test skips.
package keydiff

// REQ: KEY-1, KEY-2, KEY-3, KEY-4, KEY-6, KEY-7, KEY-8, KRN-5

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// checker is one running keycheck process.
type checker struct {
	mu  sync.Mutex
	in  *json.Encoder
	out *bufio.Scanner
}

var (
	once   sync.Once
	shared *checker
	failed error
)

func start(t testing.TB) *checker {
	bin := os.Getenv("KEYCHECK")
	if bin == "" {
		t.Skip("KEYCHECK is not set to the keycheck binary")
	}
	once.Do(func() {
		cmd := exec.Command(bin)
		cmd.Stderr = os.Stderr
		w, err := cmd.StdinPipe()
		if err != nil {
			failed = err
			return
		}
		r, err := cmd.StdoutPipe()
		if err != nil {
			failed = err
			return
		}
		if failed = cmd.Start(); failed != nil {
			return
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		shared = &checker{in: json.NewEncoder(w), out: sc}
	})
	if failed != nil {
		t.Fatal(failed)
	}
	return shared
}

type wireArg struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

type wireStep struct {
	Verb      string             `json:"verb"`
	Clerk     string             `json:"clerk"`
	Args      map[string]wireArg `json:"args"`
	Content   string             `json:"content"`
	Labels    []string           `json:"labels"`
	Amount    int64              `json:"amount"`
	Recipient string             `json:"recipient"`
	Task      string             `json:"task"`
}

type wireUse struct {
	At        int64  `json:"at"`
	Amount    int64  `json:"amount"`
	Recipient string `json:"recipient"`
	Task      string `json:"task"`
}

type wireCtx struct {
	Now     int64                `json:"now"`
	Revoked []string             `json:"revoked"`
	Paused  []string             `json:"paused"`
	Stopped bool                 `json:"stopped"`
	Uses    map[string][]wireUse `json:"uses"`
}

type wireCase struct {
	Op     string              `json:"op"`
	Key    key.Key             `json:"key"`
	Owners []ed25519.PublicKey `json:"owners"`
	Use    []byte              `json:"use"`
	Sig    []byte              `json:"sig"`
	Step   wireStep            `json:"step"`
	Task   string              `json:"task"`
	Amount int64               `json:"amount"`
	Ctx    wireCtx             `json:"ctx"`
}

type verdict struct {
	Valid  bool     `json:"valid"`
	Bad    string   `json:"bad"`
	Codes  []string `json:"codes"`
	Hold   []int64  `json:"hold"`
	Scopes []string `json:"scopes"`
}

func (c *checker) judge(w wireCase) (verdict, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.in.Encode(w); err != nil {
		return verdict{}, err
	}
	if !c.out.Scan() {
		return verdict{}, fmt.Errorf("keycheck exited: %v", c.out.Err())
	}
	var v verdict
	return v, json.Unmarshal(c.out.Bytes(), &v)
}

type ledger map[key.ID][]key.Use

func (l ledger) Uses(id key.ID) []key.Use { return l[id] }

// party is a deterministic signer.
type party struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newParty(i byte) party {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = i
	priv := ed25519.NewKeyFromSeed(seed)
	return party{priv.Public().(ed25519.PublicKey), priv}
}

var (
	pass1, pass2 = newParty(1), newParty(2) // the owner's passkeys
	clerkA       = newParty(3)
	clerkB       = newParty(4)
	stranger     = newParty(5)
	everyone     = []party{pass1, pass2, clerkA, clerkB, stranger}
)

const t0 int64 = 1_800_000_000_000

var (
	clerks   = []string{"mail", "bank", "web"}
	contents = []string{"none", "template", "thread", "free"}
	labelSet = []string{"private", "public", "secret", "bank"}
	values   = []string{"a@x", "b@x", "c@x", "5", "50", "500", "-3", "x"}
	tasks    = []string{"t1", "t2", ""}
	sources  = []key.Source{key.SrcOwner, key.SrcClerk, key.SrcPlanner, ""}
	verbs    = []key.Verb{key.Read, key.Fetch, key.Draft, key.Organize, key.Trash, key.Present, key.Unsubscribe,
		key.Send, key.Post, key.Actuate, key.Buy, key.Share, key.DeleteRemote, key.ChangeAccount,
		key.RevealOrCreateSecret, key.ActuatePhysical}
	codes = []string{key.RMalformed, key.RStopped, key.RRevoked, key.RPaused, key.RExpired, key.RClerk,
		key.RVerb, key.RArg, key.RContent, key.RLabels, key.RSpendTask, key.RSpendDay, key.RRate, key.RUses}
	chainErrs = []error{key.ErrMalformed, key.ErrWrongOwner, key.ErrBadSig, key.ErrLoosens, key.ErrNotHolder,
		key.ErrUnknownKind, key.ErrUncaveated}
)

type gen struct{ r *rand.Rand }

func (g gen) p(pct int) bool { return g.r.Intn(100) < pct }

func pick[T any](g gen, s []T) T { return s[g.r.Intn(len(s))] }

// subset is a canonical subset of s, or now and then a set out of order or
// with a repeat.
func (g gen) subset(s []string) []string {
	var out []string
	for _, x := range s {
		if g.p(50) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	if out == nil {
		out = []string{}
	}
	if g.p(3) && len(out) > 0 {
		out = append(out, out[0])
	}
	if g.p(3) && len(out) > 1 {
		out[0], out[1] = out[1], out[0]
	}
	if g.p(2) {
		out = nil
	}
	return out
}

func (g gen) num(lo, hi int64) int64 { return lo + g.r.Int63n(hi-lo+1) }

func (g gen) caveat(first bool) key.Caveat {
	switch g.r.Intn(13) {
	case 0:
		vs := make([]string, len(verbs))
		for i, v := range verbs {
			vs[i] = string(v)
		}
		return key.Caveat{Kind: key.KVerbs, Set: g.subset(vs[:6+g.r.Intn(10)])}
	case 1:
		return key.Caveat{Kind: key.KContent, Set: g.subset(contents)}
	case 2:
		return key.Caveat{Kind: key.KLabels, Set: g.subset(labelSet)}
	case 3:
		b := key.ArgBound{Name: pick(g, []string{"to", "amount", "target", "msg"})}
		if g.p(50) {
			b.OneOf = g.subset(values)
		}
		if g.p(40) {
			n := g.num(-5, 600)
			b.Min = &n
		}
		if g.p(40) {
			n := g.num(-5, 600)
			b.Max = &n
		}
		c := key.Caveat{Kind: key.KArg, Arg: &b}
		if g.p(3) {
			c.Arg = nil
		}
		return c
	case 4:
		return key.Caveat{Kind: key.KSpendTask, N: g.num(-1, 60)}
	case 5:
		return key.Caveat{Kind: key.KSpendDay, N: g.num(-1, 60)}
	case 6:
		return key.Caveat{Kind: key.KRateDay, N: g.num(-1, 6)}
	case 7:
		return key.Caveat{Kind: key.KRateRecipient, N: g.num(-1, 4)}
	case 8:
		return key.Caveat{Kind: key.KExpires, N: t0 + g.num(-3, 6)*key.DayMS/2}
	case 9:
		return key.Caveat{Kind: key.KUses, N: g.num(-1, 6)}
	case 10:
		return key.Caveat{Kind: key.KHold, N: g.num(-1, 5) * 1000, M: g.num(-1, 8) * 1000}
	case 11:
		c := key.Caveat{Kind: key.KTask, Set: []string{pick(g, tasks)}}
		if g.p(5) {
			c.Set = []string{"t1", "t2"}
		}
		return c
	default:
		if g.p(10) {
			return key.Caveat{Kind: "colour", N: 1}
		}
		return key.Caveat{Kind: key.KExpires, N: t0 + g.num(1, 6)*key.DayMS}
	}
}

// world is one case: the key and the private key of whoever holds its tip.
type world struct {
	k      key.Key
	owners []ed25519.PublicKey
	holder *party // nil: any passkey holds a bare root
}

func (g gen) key() world {
	owner := pass1
	if g.p(50) {
		owner = pass2
	}
	if g.p(4) {
		owner = stranger
	}
	var vs []key.Verb
	for _, v := range verbs {
		if g.p(60) {
			vs = append(vs, v)
		}
	}
	if g.p(3) {
		vs = append(vs, "teleport")
	}
	k := key.Issue(owner.priv, key.Root{Clerk: pick(g, clerks), Verbs: vs, Serial: strconv.Itoa(g.r.Intn(100))})
	w := world{k: k, owners: []ed25519.PublicKey{pass1.pub, pass2.pub}}
	n := g.r.Intn(5)
	if g.p(2) {
		n = key.MaxLinks + g.r.Intn(2)
	}
	for i := 0; i < n; i++ {
		var cav []key.Caveat
		if i == 0 && g.p(92) {
			cav = append(cav, key.LimitExpires(t0+g.num(-1, 8)*key.DayMS/2), key.LimitSpendDay(g.num(0, 60)))
		}
		for j := g.r.Intn(4); j > 0; j-- {
			cav = append(cav, g.caveat(i == 0))
		}
		if n > 8 {
			cav = nil
		}
		next := pick(g, everyone[2:4])
		if w.holder != nil && g.p(30) {
			next = *w.holder // a narrowing for the same holder
		}
		if g.p(3) {
			next = stranger
		}
		var signer party
		switch {
		case w.holder == nil:
			signer = pick(g, []party{pass1, pass2})
		case next.pub.Equal(w.holder.pub) && g.p(30):
			signer = pick(g, []party{pass1, pass2}) // the owner narrows it
		default:
			signer = *w.holder
		}
		if g.p(3) {
			signer = pick(g, everyone)
		}
		l := key.Link{Caveats: cav, Holder: next.pub}
		if g.p(1) {
			l.Holder = next.pub[:31]
		}
		w.k = key.Extend(w.k, signer.priv, l)
		nx := next
		w.holder = &nx
	}
	switch {
	case g.p(2):
		w.k.Root.Clerk += "x" // altered after signing
	case g.p(2) && len(w.k.Links) > 0:
		l := &w.k.Links[g.r.Intn(len(w.k.Links))]
		l.Sig = append([]byte(nil), l.Sig...)
		l.Sig[g.r.Intn(len(l.Sig))] ^= 1
	case g.p(2) && len(w.k.Links) > 1:
		w.k.Links = w.k.Links[:len(w.k.Links)-1] // a parent's key, with the child's holder
	}
	return w
}

func (g gen) step(clerk string) key.Step {
	v := pick(g, verbs)
	if g.p(3) {
		v = "teleport"
	}
	s := key.Step{Verb: v, Clerk: clerk, Content: pick(g, contents), Task: pick(g, tasks), Args: map[string]key.Arg{}}
	if g.p(10) {
		s.Clerk = pick(g, clerks)
	}
	for _, n := range key.ArgNames(v) {
		if g.p(4) {
			continue
		}
		val := pick(g, values)
		if g.p(3) {
			val = ""
		}
		s.Args[n] = key.Arg{Value: val, Source: pick(g, sources)}
	}
	if g.p(4) {
		s.Args["extra"] = key.Arg{Value: "1", Source: key.SrcOwner}
	}
	for _, l := range labelSet {
		if g.p(25) {
			s.Labels = append(s.Labels, l)
		}
	}
	s.Amount = g.num(0, 30)
	if g.p(4) {
		s.Amount = -1
	}
	s.Recipient = pick(g, values[:3])
	return s
}

func (g gen) ctx(scopes []key.ID, ids []key.ID) (key.Context, wireCtx) {
	now := t0 + g.num(-2, 8)*key.DayMS/4 + g.num(-2, 2)
	ch := &key.Changes{Revoked: map[key.ID]bool{}, Paused: map[key.ID]bool{}, Stopped: g.p(4)}
	wc := wireCtx{Now: now, Stopped: ch.Stopped, Uses: map[string][]wireUse{}}
	for _, id := range ids {
		if g.p(4) {
			ch.Revoked[id] = true
			wc.Revoked = append(wc.Revoked, id.String())
		}
		if g.p(4) {
			ch.Paused[id] = true
			wc.Paused = append(wc.Paused, id.String())
		}
	}
	l := ledger{}
	for _, s := range scopes {
		for n := g.r.Intn(5); n > 0; n-- {
			u := key.Use{At: now - g.num(0, 2*key.DayMS), Amount: g.num(0, 25), Recipient: pick(g, values[:3]), Task: pick(g, tasks)}
			if g.p(10) {
				u.At = now - key.DayMS + g.num(-1, 1) // the day's edge
			}
			l[s] = append(l[s], u)
			wc.Uses[s.String()] = append(wc.Uses[s.String()], wireUse(u))
		}
	}
	return key.Context{Now: now, Changes: ch, Ledger: l}, wc
}

func toWire(s key.Step) wireStep {
	w := wireStep{Verb: string(s.Verb), Clerk: s.Clerk, Content: s.Content, Labels: s.Labels, Amount: s.Amount,
		Recipient: s.Recipient, Task: s.Task, Args: map[string]wireArg{}}
	for n, a := range s.Args {
		w.Args[n] = wireArg{a.Value, string(a.Source)}
	}
	return w
}

// tally counts what the cases reached, so a generator that stops reaching a
// rule fails the test instead of passing quietly.
type tally struct {
	mu        sync.Mutex
	codes     map[string]int
	errs      map[error]int
	admitted  int
	spendOK   int
	kindDiffs map[string]int
}

func (t *tally) add(code string, err error, admitted, spendOK bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if code != "" {
		t.codes[code]++
	}
	for _, e := range chainErrs {
		if errors.Is(err, e) {
			t.errs[e]++
		}
	}
	if admitted {
		t.admitted++
	}
	if spendOK {
		t.spendOK++
	}
}

// one builds and judges case seed; it returns a description of any
// disagreement.
func one(c *checker, seed int64, t *tally) string {
	g := gen{rand.New(rand.NewSource(seed))}
	w := g.key()
	use := []byte(fmt.Sprintf("plan-%d", g.r.Intn(1000)))
	signer := pick(g, []party{pass1, pass2})
	if w.holder != nil {
		signer = *w.holder
	}
	if g.p(5) {
		signer = pick(g, everyone)
	}
	sig := key.Sign(w.k, signer.priv, use)
	if g.p(2) {
		use = append(use, '!')
	}
	op := pick(g, []string{"chain", "verify", "authorize", "authorize", "authorize", "spend", "spend"})
	wc := wireCase{Op: op, Key: w.k, Owners: w.owners, Use: use, Sig: sig}
	var v *key.Verified
	var err error
	if op == "chain" || op == "spend" {
		v, err = key.Chain(w.k, w.owners)
	} else {
		v, err = key.Verify(w.k, w.owners, use, sig)
	}
	var scopes, ids []key.ID
	if err == nil {
		scopes, ids = v.Scopes(), v.IDs
	}
	ctx, wctx := g.ctx(scopes, ids)
	wc.Ctx = wctx
	st := g.step(w.k.Root.Clerk)
	wc.Step = toWire(st)
	wc.Task, wc.Amount = pick(g, tasks), g.num(-1, 30)
	got, jerr := c.judge(wc)
	if jerr != nil {
		return "keycheck: " + jerr.Error()
	}
	if (err == nil) != got.Valid {
		return fmt.Sprintf("op %s: library chain err %v, keycheck valid %v (%s)", op, err, got.Valid, got.Bad)
	}
	if err != nil {
		t.add("", err, false, false)
		bad, _, _ := strings.Cut(got.Bad, "(")
		if k := kindOf(err); k != bad {
			t.mu.Lock()
			t.kindDiffs[k+" / "+bad]++
			t.mu.Unlock()
		}
		return ""
	}
	var hex []string
	for _, s := range scopes {
		hex = append(hex, s.String())
	}
	if !slices.Equal(hex, got.Scopes) {
		return fmt.Sprintf("scopes: library %v, keycheck %v", hex, got.Scopes)
	}
	if hold := []int64{v.Limits.Window(false), v.Limits.Window(true)}; !slices.Equal(hold, got.Hold) {
		return fmt.Sprintf("hold: library %v, keycheck %v", hold, got.Hold)
	}
	var r *key.Refusal
	switch op {
	case "authorize":
		r = v.Authorize(st, ctx)
	case "spend":
		r = v.Spend(wc.Task, wc.Amount, ctx)
	default:
		t.add("", nil, false, false)
		return ""
	}
	code := ""
	if r != nil {
		code = r.Code
	}
	t.add(code, nil, op == "authorize" && r == nil, op == "spend" && r == nil)
	if (r == nil) != (len(got.Codes) == 0) || (r != nil && !slices.Contains(got.Codes, r.Code)) {
		return fmt.Sprintf("op %s: library %v, keycheck %v", op, r, got.Codes)
	}
	return ""
}

func kindOf(err error) string {
	names := []string{"Malformed", "WrongOwner", "BadSig", "Loosens", "NotHolder", "UnknownKind", "Uncaveated"}
	for i, e := range chainErrs {
		if errors.Is(err, e) {
			return names[i]
		}
	}
	return err.Error()
}

func newTally() *tally {
	return &tally{codes: map[string]int{}, errs: map[error]int{}, kindDiffs: map[string]int{}}
}

// TestKeyDiff runs KEYDIFF_CASES seeds (default 20000) from KEYDIFF_FROM
// (default 0) and requires every refusal code and
// every chain error to be reached, and steps and calls to be admitted.
func TestKeyDiff(t *testing.T) {
	c := start(t)
	n := int64(20000)
	if s := os.Getenv("KEYDIFF_CASES"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		n = v
	}
	from := int64(0)
	if s := os.Getenv("KEYDIFF_FROM"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		from = v
	}
	tl := newTally()
	bad := 0
	for seed := from; seed < from+n; seed++ {
		if d := one(c, seed, tl); d != "" {
			bad++
			if bad <= 20 {
				t.Errorf("seed %d: %s", seed, d)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d cases disagree", bad, n)
	}
	for _, code := range codes {
		if tl.codes[code] == 0 {
			t.Errorf("no case reached refusal %q", code)
		}
	}
	for _, e := range chainErrs {
		if tl.errs[e] == 0 {
			t.Errorf("no case reached %v", e)
		}
	}
	if tl.admitted == 0 || tl.spendOK == 0 {
		t.Errorf("admitted steps %d, admitted calls %d", tl.admitted, tl.spendOK)
	}
	t.Logf("codes %v; admitted %d steps, %d calls; chain errors %v", tl.codes, tl.admitted, tl.spendOK, tl.errs)
	if len(tl.kindDiffs) > 0 {
		t.Logf("first-error kinds that differ (library / keycheck): %v", tl.kindDiffs)
	}
}

// FuzzKeyDiff is the same check over seeds the fuzzer picks.
func FuzzKeyDiff(f *testing.F) {
	for _, s := range []int64{0, 1, 2, 3} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		if d := one(start(t), seed, newTally()); d != "" {
			t.Fatal(d)
		}
	})
}

// TestDumpSeed logs the caveats of KEYDIFF_SEED's key, to read a
// disagreement the sweep reports.
func TestDumpSeed(t *testing.T) {
	s := os.Getenv("KEYDIFF_SEED")
	if s == "" {
		t.Skip()
	}
	seed, _ := strconv.ParseInt(s, 10, 64)
	g := gen{rand.New(rand.NewSource(seed))}
	w := g.key()
	for i, l := range w.k.Links {
		b, _ := json.Marshal(l.Caveats)
		t.Logf("link %d: %s", i, b)
	}
}
