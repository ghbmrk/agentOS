package kernel_test

// REQ: KEY-8, KRN-4

// The hold rule's model-checked vectors (FRM-key, #2936). formal/HoldRule.tla
// models one step under a hold caveat; TLC checks that an irreversible step
// is held and never dispatches before its window, that novelty only lengthens
// a window, and that a held step's due time never moves earlier, even when a
// step of the same shape completes under the root during the hold. For each
// scenario formal/vectors.py records the earliest dispatch the model allows,
// and this test runs the scenario through the real kernel and mail clerk,
// ticking every model hour, and requires the step to run at exactly that hour.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func TestFormalHoldRule(t *testing.T) {
	path := filepath.Join("testdata", "formal", "hold.json")
	if d := os.Getenv("FORMAL_VECTORS"); d != "" {
		path = filepath.Join(d, "hold.json")
	}
	b, err := os.ReadFile(path)
	must(t, err)
	var f struct {
		Unit      string `json:"unit"`
		Scenarios []struct {
			Hold    [2]int64 `json:"hold"`
			Verb    string   `json:"verb"`
			Seen    bool     `json:"seen"`
			MidHold bool     `json:"mid_hold"`
			SentAt  int64    `json:"sent_at"`
		} `json:"scenarios"`
	}
	must(t, json.Unmarshal(b, &f))
	if f.Unit != "hour" || len(f.Scenarios) == 0 {
		t.Fatalf("%s: unit %q, %d scenarios", path, f.Unit, len(f.Scenarios))
	}
	const t0 = hour // the model's time 0; a seen shape completes at 0
	for _, sc := range f.Scenarios {
		t.Run(fmt.Sprintf("%v-%s-seen=%v-mid=%v", sc.Hold, sc.Verb, sc.Seen, sc.MidHold), func(t *testing.T) {
			r := newRig(t)
			ck := r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "mail",
				Verbs: []key.Verb{key.Organize, key.Send}, Serial: "formal"}), 1<<40)
			// One shape, three fingerprints: the duplicate guard (KRN-8) stays out of it.
			step := func(msg string) kernel.PlanStep {
				s := st(key.Verb(sc.Verb), "x")
				s.Args[key.ArgNames(key.Verb(sc.Verb))[1]] = msg
				return s
			}
			if sc.Seen {
				must(t, r.k.Submit(0, r.sign(kernel.Plan{ID: "seen", Key: ck, Steps: []kernel.PlanStep{step("m0")}})))
				must(t, r.tick(0))
				if r.status("seen") != kernel.SDone {
					t.Fatalf("the earlier step of this shape did not complete: %s", r.status("seen"))
				}
			}
			held, err := key.Derive(ck, r.holder.priv, r.holder.pub, key.LimitHold(sc.Hold[0]*hour, sc.Hold[1]*hour))
			must(t, err)
			must(t, r.k.Submit(t0, r.sign(kernel.Plan{ID: "p", Key: held, Steps: []kernel.PlanStep{step("m1")}})))
			must(t, r.tick(t0))
			if sc.MidHold {
				must(t, r.k.Submit(t0, r.sign(kernel.Plan{ID: "mid", Key: ck, Steps: []kernel.PlanStep{step("m2")}})))
				must(t, r.tick(t0))
				if r.status("mid") != kernel.SDone {
					t.Fatalf("the step completing mid-hold did not complete: %s", r.status("mid"))
				}
			}
			idem := kernel.Idem("p", 0)
			for at := int64(0); at <= 6; at++ {
				must(t, r.tick(t0+at*hour))
				ran := false
				for _, e := range r.mail.Effects() {
					ran = ran || e.Idem == idem
				}
				switch {
				case ran && at < sc.SentAt:
					t.Fatalf("ran at hour %d; the model's earliest is %d (KEY-8)", at, sc.SentAt)
				case ran:
					return
				case at >= sc.SentAt:
					t.Fatalf("not run by hour %d; the model runs it at %d", at, sc.SentAt)
				}
			}
		})
	}
}
