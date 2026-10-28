package apply

// REQ: UPD-1, UPD-1a, UPD-3, UPD-6, KRN-4, KRN-8
//
// The update clerk (MIG-4-adapters-e, #3428): a release activation is one
// kernel plan step under the image-pinned update key, the clerk re-checks
// it just before it acts, and an answer lost in a crash is settled by its
// probe from the boot counter, never by a second Install.

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// submitted schedules release 1 (a security fix, due at once) and has the
// applier submit its plan, which the kernel holds undispatched.
func submitted(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.hold = true
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.hold = false
	if ps := r.plans(); len(ps) != 1 || ps[0].Status != kernel.SActive {
		t.Fatalf("plans: %+v", ps)
	}
	return r
}

// crashAfterDo dispatches the held step to the clerk and then loses the
// box before the kernel logs the answer: the log holds the dispatch, not
// the result, so the next boot marks the step unknown (KRN-8).
func (r *rig) crashAfterDo() kernel.Result {
	r.t.Helper()
	cs, err := r.k.Calls(r.ms())
	r.must(err)
	if len(cs) != 1 || cs[0].Kind != kernel.ActDispatch {
		r.t.Fatalf("calls: %+v", cs)
	}
	if ok, err := r.k.Send(r.ms(), cs[0]); !ok || err != nil {
		r.t.Fatalf("send: %v %v", ok, err)
	}
	res := clerkSide{r}.Do(cs[0].Req, r.k.State())
	r.bootKernel()
	return res
}

// step is the update clerk's only plan's step as the kernel logged it.
func (r *rig) step() kernel.StepState {
	r.t.Helper()
	ps := r.plans()
	if len(ps) != 1 {
		r.t.Fatalf("plans: %+v", ps)
	}
	return ps[0].Steps[0]
}

// The lifecycle matrix: each stage, driven through the kernel, by what
// the log holds as the step's result and how often the activator wrote a
// slot (at most once per step, KRN-8).
func TestLifecycleMatrix(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		stage   string
		run     func(r *rig)
		phase   string
		detail  string // a prefix of the logged result
		install int
	}{
		{"staged", func(r *rig) {}, "", "", 0},
		{"box busy", func(r *rig) { r.inCall = true; r.tick() }, kernel.PFailed, RBusy + ": a call is in progress", 0},
		{"activated", func(r *rig) { r.tick() }, kernel.PDone, "rollback point: release 0 on root " + strings.Repeat(oldHash, 32), 1},
		{"restart healthy", func(r *rig) {
			r.tick()
			r.must(r.act.Restart(ctx))
			r.restart()
			r.must(r.a.Resume(ctx))
		}, kernel.PDone, "rollback point:", 1},
		{"restart fell back", func(r *rig) {
			r.tick()
			r.act.failBoot = true
			r.must(r.act.Restart(ctx))
			r.restart()
			r.must(r.a.Resume(ctx))
		}, kernel.PDone, "rollback point:", 1},
		{"crash between activate and answer", func(r *rig) {
			r.crashAfterDo()
			r.restart()
			r.reconcile()
		}, kernel.PDone, "", 1},
	} {
		t.Run(c.stage, func(t *testing.T) {
			r := submitted(t)
			c.run(r)
			st := r.step()
			if c.phase == "" {
				if st.Phase != kernel.PQueued && st.Phase != kernel.PInflight && st.Phase != "" {
					t.Fatalf("staged step already ran: %+v", st)
				}
			} else if st.Phase != c.phase || !strings.HasPrefix(st.Detail, c.detail) {
				t.Fatalf("logged %s %q, want %s %q", st.Phase, st.Detail, c.phase, c.detail)
			}
			if len(r.act.installed) != c.install {
				t.Fatalf("activator wrote %d slots, want %d", len(r.act.installed), c.install)
			}
			// More kernel ticks never write a slot again.
			r.reconcile()
			r.reconcile()
			if len(r.act.installed) > 1 {
				t.Fatalf("activator wrote %d slots", len(r.act.installed))
			}
		})
	}
}

// KRN-8: the answer of a handed-over activation is lost in a crash. The
// kernel's probe settles it from saved state and the boot counter (still
// waiting for the restart, committed, or fell back) as done, and the
// activator never writes the slot again.
func TestActivateOnceAcrossCrash(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		boot   func(r *rig)
		detail string
	}{
		{"same boot", func(r *rig) {}, "handed over; restart pending"},
		{"rebooted healthy", func(r *rig) { r.must(r.act.Restart(ctx)) }, "committed"},
		{"rebooted, health check pending", func(r *rig) { r.act.pending = true; r.must(r.act.Restart(ctx)) }, "booted; health check pending"},
		{"rebooted, fell back", func(r *rig) { r.act.failBoot = true; r.must(r.act.Restart(ctx)) }, "fell back"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := submitted(t)
			if res := r.crashAfterDo(); res.Outcome != "ok" {
				t.Fatalf("do: %+v", res)
			}
			c.boot(r)
			r.restart()
			if st := r.step(); st.Phase != kernel.PUnknown {
				t.Fatalf("after the crash: %+v", st)
			}
			r.reconcile()
			if st := r.step(); st.Phase != kernel.PDone {
				t.Fatalf("not settled by its probe: %+v", st)
			}
			// The probe's finding, as the kernel asked it.
			if o := r.a.Probe(kernel.Request{Plan: r.plans()[0].Plan}, r.k.State()); o.Outcome != "done" || o.Detail != c.detail {
				t.Fatalf("probe %+v, want done %q", o, c.detail)
			}
			if len(r.act.installed) != 1 || r.dos != 1 {
				t.Fatalf("Install %d times, dispatched %d times", len(r.act.installed), r.dos)
			}
			// Mutant: a clerk that answers notdone here lets the kernel
			// redo the step; the release is no longer pending, so even
			// then nothing is installed twice.
			if res := r.a.Do(kernel.Request{Plan: r.plans()[0].Plan}, r.k.State()); res.Outcome != "ok" || len(r.act.installed) != 1 {
				t.Fatalf("second Do: %+v, installed %d", res, len(r.act.installed))
			}
		})
	}
}

// A crash during the slot write leaves a handover never recorded: the probe
// answers unknown until Resume abandons it, then notdone, so the kernel's
// retry is safe (KRN-8).
func TestUnrecordedHandoverProbesNotDoneOnceAbandoned(t *testing.T) {
	r := submitted(t)
	r.act.onInstall = func() { r.state.Fail, r.act.abandonErr = errIO, errIO }
	r.tick()
	if st := r.step(); st.Phase != kernel.PUnknown {
		t.Fatalf("logged %+v", st)
	}
	req := kernel.Request{Plan: r.plans()[0].Plan}
	if o := r.a.Probe(req, r.k.State()); o.Outcome != "unknown" {
		t.Fatalf("probe before the abandon: %+v", o)
	}
	r.state.Fail, r.act.abandonErr, r.act.onInstall = nil, nil, nil
	r.restart()
	r.must(r.a.Resume(context.Background()))
	if o := r.a.Probe(req, r.k.State()); o.Outcome != "notdone" {
		t.Fatalf("probe after the abandon: %+v", o)
	}
	r.reconcile()
	// The redo finds no release held after the process restart: refused,
	// and the slot is not written again.
	if st := r.step(); st.Phase != kernel.PFailed || len(r.act.installed) != 1 {
		t.Fatalf("logged %+v, installed %d", st, len(r.act.installed))
	}
}

// UPD-6: a step dispatched while the box is not free is refused by the
// clerk's own re-check (CLK-2), whatever the scheduler saw when it
// submitted; so is one while the channel is pinned (UPD-4). Once the box
// is free a new plan installs it.
func TestBusyBoxHoldsActivation(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		why  string
		set  func(r *rig, on bool)
		want string
	}{
		{"call", func(r *rig, on bool) { r.inCall = on }, RBusy + ": " + busyCall},
		{"work", func(r *rig, on bool) { r.working = on }, RBusy + ": " + busyWork},
		{"excluded", func(r *rig, on bool) { r.excluded = func(time.Time) bool { return on } }, RBusy + ": " + busyExcluded},
		{"talk", func(r *rig, on bool) {
			r.talk = time.Time{}
			if on {
				r.talk = r.clk.now()
			}
		}, RBusy + ": " + busyTalk},
		{"STOP", func(r *rig, on bool) { r.stopped = on }, RBusy + ": " + busyStop},
		{"pinned channel", func(r *rig, on bool) { r.paused = on }, RPaused},
	} {
		t.Run(c.why, func(t *testing.T) {
			r := submitted(t)
			c.set(r, true)
			r.tick()
			if st := r.step(); st.Phase != kernel.PFailed || st.Detail != c.want {
				t.Fatalf("logged %+v, want failed %q", st, c.want)
			}
			if len(r.act.installed) != 0 {
				t.Fatal("activated while held")
			}
			// While it holds, the scheduler submits nothing either (the
			// pinned channel is the clerk's alone to judge).
			if ok, err := r.a.Tick(ctx); ok || err != nil || len(r.act.installed) != 0 {
				t.Fatalf("tick while held: %v %v", ok, err)
			}
			c.set(r, false)
			r.clk.add(r.a.cfg.Quiet) // past the talk window
			if ok, err := r.a.Tick(ctx); !ok || err != nil || len(r.act.installed) != 1 {
				t.Fatalf("free again: %v %v, installed %d", ok, err, len(r.act.installed))
			}
		})
	}
}

// UPD-1: a release whose new slot fails its health check falls back by
// boot counting; the step stays done (the activation happened), its probe
// answers fell back, and Resume reverts the adoption with no owner action.
func TestFallbackAnswersFellBack(t *testing.T) {
	ctx := context.Background()
	r := submitted(t)
	r.act.failBoot = true
	r.tick()
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	req := kernel.Request{Plan: r.plans()[0].Plan}
	r.restart()
	if o := r.a.Probe(req, r.k.State()); o.Outcome != "done" || o.Detail != "fell back" {
		t.Fatalf("probe before Resume: %+v", o)
	}
	r.must(r.a.Resume(ctx))
	if o := r.a.Probe(req, r.k.State()); o.Outcome != "done" || o.Detail != "fell back" {
		t.Fatalf("probe after Resume: %+v", o)
	}
	if !r.a.FellBack(1) || len(r.pipe.failed) != 1 || r.pipe.failed[0] != "a1" {
		t.Fatalf("not judged a fallback: %+v", r.pipe)
	}
	if in, _ := r.store.Installed(); in.Version != 0 {
		t.Fatalf("installed %+v", in)
	}
	if len(r.act.installed) != 1 {
		t.Fatalf("installed %d times", len(r.act.installed))
	}
}

// KRN-4: only the image-pinned update key covers an activation. A step
// under any other key the kernel admits, the owner's own root for this
// clerk or a pinned root that also names another verb, is refused by the
// clerk's own check, and nothing is written.
func TestStepWithoutKeyRefused(t *testing.T) {
	_, opriv := seedKey(1)
	_, bpriv := seedKey(12)
	grant := func(r *rig, k key.Key) {
		batch := []key.Key{k}
		cos := []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}
		r.must(r.k.Issue(r.ms()-kernel.GrantHold, cos, batch...))
	}
	for _, c := range []struct {
		name string
		plan func(r *rig) kernel.Plan
	}{
		{"owner's root", func(r *rig) kernel.Plan {
			k := key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: Name, Verbs: []key.Verb{key.ChangeAccount}, Serial: "owner"})
			grant(r, k)
			return kernel.SignPlan(kernel.Plan{ID: "upd:apply:1:n7", Key: k, Steps: []kernel.PlanStep{Step(r.a.rel)}}, opriv)
		}},
		{"pinned root with another verb", func(r *rig) kernel.Plan {
			k := key.Issue(key.Ed25519Signer(r.holder), key.Root{Clerk: Name, Verbs: []key.Verb{key.ChangeAccount, key.Send}, Serial: "wide"})
			grant(r, k)
			return kernel.SignPlan(kernel.Plan{ID: "upd:apply:1:n8", Key: k, Steps: []kernel.PlanStep{Step(r.a.rel)}}, r.holder)
		}},
		{"pinned key, another release", func(r *rig) kernel.Plan {
			st := Step(r.a.rel)
			st.Args[ArgEntry] = strings.Repeat("ee", 32)
			return kernel.SignPlan(kernel.Plan{ID: "upd:apply:1:n9", Key: r.upkey, Steps: []kernel.PlanStep{st}}, r.holder)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.must(r.a.Schedule(r.release(1, true), "a1"))
			p := c.plan(r)
			r.must(r.k.Submit(r.ms(), p))
			r.tick()
			ps := r.k.State().Plans[p.ID]
			if ps.Status == kernel.SRejected {
				t.Fatalf("the kernel rejected it (%s), so the clerk's check was not reached", ps.Reject)
			}
			if st := ps.Steps[0]; st.Phase != kernel.PFailed {
				t.Fatalf("logged %+v", st)
			}
			if len(r.act.installed) != 0 {
				t.Fatal("activated under another key")
			}
		})
	}
}

// New takes only the pinned update key for activate, with its holder.
func TestNewRefusesAnotherKey(t *testing.T) {
	r := newRig(t)
	r.release(1, true)
	_, opriv := seedKey(1)
	for name, k := range map[string]key.Key{
		"owner's root": key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: Name, Verbs: []key.Verb{key.ChangeAccount}, Serial: "o"}),
		"wider root":   key.Issue(key.Ed25519Signer(r.holder), key.Root{Clerk: Name, Verbs: []key.Verb{key.ChangeAccount, key.Send}, Serial: "w"}),
		"other clerk":  key.Issue(key.Ed25519Signer(r.holder), key.Root{Clerk: "mail", Verbs: []key.Verb{key.ChangeAccount}, Serial: "m"}),
	} {
		cfg := r.a.cfg
		cfg.Key = k
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The update clerk links no old core: the journal and grants are gone
// from its graph (MIG-4-adapters-e).
func TestLinksNoOldCore(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".", "./activatortest").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		for _, old := range []string{"journal", "grants", "reversible"} {
			if p == "github.com/ghbmrk/agentos/broker/"+old || strings.HasPrefix(p, "github.com/ghbmrk/agentos/broker/"+old+"/") {
				t.Errorf("apply links %s", p)
			}
		}
	}
}
