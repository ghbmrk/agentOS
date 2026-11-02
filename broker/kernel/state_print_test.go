package kernel_test

// REQ: KRN-12

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// logKey is the rig's log key: synthetic, and not zero, so a print of it shows.
var logKey = [32]byte{0x5e, 0xc7, 0x3e, 0x7a, 0x11, 0x0f, 0xa5, 0x5e, 0xc7, 0x3e, 0x7a, 0x11, 0x0f, 0xa5, 0x01, 0x02,
	0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12}

// TestStatePrintsNoDecoy formats the kernel, its log, its state and its
// config in every verb a log line or error might use, before and after a
// honey key trips, and finds no decoy value, no honey key's ID, which would
// tell an intruder which key not to use, and not the box's signing key or
// the log key: raw, in the verb's own form, as hex or as decimal bytes,
// whether bare or JSON-escaped as the log's entry body holds them
// (DECOY-a-7, CLK-1, #4505, #4574).
func TestStatePrintsNoDecoy(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	secrets := [][]byte{r.head.priv, logKey[:]}
	for _, e := range tb.Entries() {
		if e.Value == "" { // a destination entry has no value
			continue
		}
		j, _ := json.Marshal(e.Value)
		secrets = append(secrets, []byte(e.Value), j[1:len(j)-1])
		var hk key.Key
		if e.Kind == decoy.KHoneyKey && json.Unmarshal([]byte(e.Value), &hk) == nil {
			id := hk.Tip()
			secrets = append(secrets, id[:])
		}
	}
	if len(secrets) < 4 {
		t.Fatalf("the table has no honey key: %d secrets", len(secrets))
	}
	c := cfg(r)
	if got := fmt.Sprintf("%v %+v %s", c, &c, c); got != "kernel.Config kernel.Config kernel.Config" {
		t.Fatalf("a config prints as %q", got)
	}
	printsNone(t, secrets, true, r.k, c, &c)

	// After honey-key trips at a plan, at Extend and in an Issue batch, the
	// paused scope and the trips name no honey key's ID.
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	exhaust(r, "t1", 100)
	honey, hk, intruder := honeyKey(t, tb, "t1")
	must(t, r.k.Submit(1, kernel.SignPlan(kernel.Plan{ID: "h", Key: hk, Steps: []kernel.PlanStep{st(key.Trash, "m")}}, intruder.priv)))
	if err := r.k.Extend(2, hk, "t1"); err == nil {
		t.Fatal("a honey key extended t1")
	}
	if err := r.k.Issue(3, approve([]key.Key{honey}, r.owner, r.spare), honey); err == nil {
		t.Fatal("a honey key was issued")
	}
	if n := len(r.k.State().Trips()); n != 3 || !r.k.State().Tripped() {
		t.Fatalf("%d trips, want 3 and planning stopped", n)
	}
	printsNone(t, secrets, true, r.k)
}

// A secret a clerk holds, which the kernel holds in an interface field, is
// shown by a holder of the kernel unless it sits behind a pointer to a
// pointer, as Log.p does (DECOY-b-8). Catches the rule being dropped, and a
// print check too weak to see such a secret.
func TestClerkSecretPrintsOnlyBehindAPointer(t *testing.T) {
	r := newRig(t)
	secret := []byte("synthetic-clerk-secret-0123456789")
	p := &secret
	for _, c := range []struct {
		clerk kernel.Clerk
		shows bool
	}{{&pointerClerk{&p}, false}, {&plainClerk{secret}, true}} {
		k, err := kernel.Boot(r.k.Log(), r.anchors(), map[string]kernel.Clerk{"mail": r.mail, "vault": c.clerk}, 0)
		must(t, err)
		printsNone(t, [][]byte{secret}, !c.shows, k)
	}
}

type pointerClerk struct{ p **[]byte }
type plainClerk struct{ secret []byte }

func (*pointerClerk) Do(kernel.Request, kernel.View) kernel.Result    { return kernel.Result{} }
func (*pointerClerk) Probe(kernel.Request, kernel.View) kernel.Result { return kernel.Result{} }
func (*plainClerk) Do(kernel.Request, kernel.View) kernel.Result      { return kernel.Result{} }
func (*plainClerk) Probe(kernel.Request, kernel.View) kernel.Result   { return kernel.Result{} }

// printsNone formats k, its log and its state, bare and in holders, in
// sixteen verbs, and each of more (a config, whose Format fmt skips under
// %w and %p, DECOY-b-8) in the fourteen others, and checks that none shows a
// secret when none is true, or that some print shows one when it is false.
func printsNone(t *testing.T, secrets [][]byte, none bool, k *kernel.Kernel, more ...any) {
	t.Helper()
	// fmt calls no method through an unexported field, and it prints a
	// nested pointer whole under a verb a pointer has no form for, so each
	// is also formatted inside a holder a caller might wrap it in.
	type holder struct {
		k  *kernel.Kernel
		kv kernel.Kernel
		l  *kernel.Log
		lv kernel.Log
		s  kernel.State
	}
	h := holder{k, *k, k.Log(), *k.Log(), *k.State()}
	shown := false
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b", "%w", "%p"}
	for i, v := range append([]any{k, *k, k.Log(), *k.Log(), k.State(), *k.State(), h, &h}, more...) {
		vs := verbs
		if i >= 8 {
			vs = verbs[:14]
		}
		for _, verb := range vs {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"),
					strings.Trim(fmt.Sprintf(verb, s), "[]"), strings.Trim(fmt.Sprintf(verb, string(s)), "[]\"")} {
					if len(f) >= 10 && strings.Contains(out, strings.ToLower(f)) {
						shown = true
						if none {
							t.Errorf("%s of %T shows a secret (%.20s...)", verb, v, f)
						}
					}
				}
			}
		}
	}
	if !none && !shown {
		t.Error("no print showed the secret: the check cannot see it")
	}
}
