package recalltool

// REQ: CAP-3

import (
	"context"
	"errors"
	"testing"
	"time"
)

// W3-forget-b2b: the owner's forget of a task takes the agent machine's
// work since the task back on the ask-first rule (Mark, 2026-10-05). Work
// is the rule's measure; TakeBack is the same reset a recall rollback
// runs, and tells the owner nothing (the forget's own texts do).
func TestCAP3ForgetTakesTheAgentBackOnTheAskFirstRule(t *testing.T) {
	x, read := newReachRig(t)
	if worked, ok := x.reach.Work("root", read); !ok || worked {
		t.Fatalf("no work since: worked %v ok %v", worked, ok)
	}
	x.vm.plan.Changes = 2
	if worked, _ := x.reach.Work("root", read); !worked {
		t.Fatal("files changed since are work")
	}
	x.vm.plan.Changes, x.vm.planErr = 0, errors.New("unmeasured")
	if worked, _ := x.reach.Work("root", read); !worked {
		t.Fatal("an unmeasured plan must count as work")
	}
	x.vm.planErr = nil
	x.j.submitted["late"] = read.Add(time.Second)
	if worked, _ := x.reach.Work("root", read); !worked {
		t.Fatal("an action since is work")
	}
	if err := x.reach.TakeBack(context.Background(), "root", read); err != nil {
		t.Fatal(err)
	}
	if len(x.vm.calls) != 1 || x.vm.calls[0] != "root" || !x.vm.since[0].Equal(read) {
		t.Fatalf("reset %v %v", x.vm.calls, x.vm.since)
	}
	if !x.j.erased["late"] || x.j.erased["early"] || !x.cs.forgot["late"] || len(x.told) != 0 {
		t.Fatalf("erased %v forgot %v told %v", x.j.erased, x.cs.forgot, x.told)
	}
	if len(x.r.prov.Resets("root")) != 0 || len(x.r.prov.Of("bystander")) == 0 {
		t.Fatal("reset left open, or another lineage touched")
	}
	// Again (a retry): it resets from the same point, and nothing was
	// done since, so nothing more is lost.
	if err := x.reach.TakeBack(context.Background(), "root", read); err != nil || len(x.vm.calls) != 2 {
		t.Fatalf("second take-back: %v %v", err, x.vm.calls)
	}
	if _, ok := (&Reach{Prov: x.r.prov}).Work("root", read); ok {
		t.Fatal("without machines nothing can be taken back")
	}
}

// A take-back interrupted after the machines went back is finished by
// Retry, though the lineage holds no deleted record that would revisit it.
func TestCAP3RetryFinishesAnInterruptedTakeBack(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	if err := x.r.prov.MarkReset("root", Reset{Since: read, At: x.clock, Until: x.clock}); err != nil {
		t.Fatal(err)
	}
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !x.j.erased["late"] || len(x.r.prov.Resets("root")) != 0 || len(x.vm.calls) != 0 {
		t.Fatalf("erased %v resets %v machines %v", x.j.erased, x.r.prov.Resets("root"), x.vm.calls)
	}
}
