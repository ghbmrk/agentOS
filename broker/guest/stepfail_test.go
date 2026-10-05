package guest

// REQ: REV-1

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// notes is every content item of a tool result after the first.
func (r *rig) notes(id, name string, args map[string]any) []string {
	r.t.Helper()
	res := r.rpc(id, "tools/call", map[string]any{"name": name, "arguments": args})
	var out []string
	for _, c := range res["content"].([]any)[1:] {
		out = append(out, c.(map[string]any)["text"].(string))
	}
	return out
}

// A failed step snapshot is not silent: the call whose step failed, or
// the next one when the step trailed, carries one fixed note naming the
// reason and no host path, once (SR2-3s; security R1 on #174).
func TestSR23sFailedStepTellsTheAgent(t *testing.T) {
	host := "/var/lib/agentos/machines/m1/upper"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"no room", fmt.Errorf("vm: m1: %w (layer at %s)", ErrStepNoRoom, host),
			"The rollback point after your last effect request was not saved: there is no room for it. Delete files you no longer need; until a rollback point is saved, your steps since then can't be rolled back."},
		{"too deep", fmt.Errorf("vm: m1: %w (at %s)", ErrStepTooDeep, host),
			"The rollback point after your last effect request was not saved: folders in your machine nest more than 256 deep. Flatten or delete them; until a rollback point is saved, your steps since then can't be rolled back."},
		{"other", fmt.Errorf("pause %s: %w", host, errors.New("input/output error")),
			"The rollback point after your last effect request was not saved. The broker tries again after your next effect request; until then your steps since then can't be rolled back."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(c *Config) { c.StepInterval = time.Hour })
			r.ms.failSteps(tc.err)
			got := r.notes("m1", "effect_request", send("r1"))
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("notes = %q, want %q", got, tc.want)
			}
			if strings.Contains(strings.Join(got, ""), "/") {
				t.Fatalf("a note names a path: %q", got)
			}
			if again := r.notes("m1", "effect_status", map[string]any{"request_id": "r1"}); len(again) != 0 {
				t.Fatalf("the note came twice: %q", again)
			}
			// Only the machine whose step failed is told (security S2).
			if other := r.notes("m2", "effect_status", map[string]any{"request_id": "r1"}); len(other) != 0 {
				t.Fatalf("another machine was told: %q", other)
			}
		})
	}
}

// A trailing step that fails is told in the machine's next tool result,
// whatever the tool.
func TestSR23sTrailingStepFailureComesWithTheNextResult(t *testing.T) {
	r := newRig(t, func(c *Config) { c.StepInterval = 50 * time.Millisecond })
	r.tool("m1", "effect_request", send("r1")) // snapshots at once, and succeeds
	r.ms.failSteps(fmt.Errorf("vm: %w", ErrStepNoRoom))
	if got := r.notes("m1", "effect_request", send("r2")); len(got) != 0 {
		t.Fatalf("a step inside the interval reported early: %q", got)
	}
	r.stepsSettle("m1") // the trailing snapshot runs, and fails
	if got := r.notes("m1", "effect_status", map[string]any{"request_id": "r2"}); len(got) != 1 || got[0] != stepNoteNoRoom {
		t.Fatalf("next result's notes = %q", got)
	}
}

// STATUS carries one line while a machine's step snapshots keep failing
// (two in a row), naming no machine or path, with the time of the last
// saved rollback point, and none once one succeeds (UX-SR23s-1, -2).
func TestSR23sStatusWhileStepsKeepFailing(t *testing.T) {
	for _, tc := range []struct {
		err  error
		line string
	}{
		{ErrStepNoRoom, "Rollback: the agent's files since %s can't be rolled back yet; they're full. It has been told to free space. UNDO still works. Nothing to do unless this lasts."},
		{ErrStepTooDeep, "Rollback: the agent's files since %s can't be rolled back yet; its folders nest too deep to save. It has been told to flatten them. UNDO still works. Nothing to do unless this lasts."},
		{errors.New("pause failed"), "Rollback: the agent's files since %s can't be rolled back yet; the box couldn't save them. It tries again after the agent's next action. UNDO still works. Nothing to do unless this lasts."},
	} {
		r := newRig(t, func(c *Config) { c.StepInterval = time.Millisecond })
		r.tool("m1", "effect_request", send("r0")) // a rollback point is saved
		st := &r.p.get("m1").steps
		st.mu.Lock()
		saved := st.last
		st.mu.Unlock()
		r.ms.failSteps(fmt.Errorf("vm: %w", tc.err))
		r.stepsSettle("m1")
		r.tool("m1", "effect_request", send("r1"))
		if n := r.p.StepNote(); n != "" {
			t.Fatalf("one failure gave the line %q", n)
		}
		r.stepsSettle("m1")
		r.tool("m1", "effect_request", send("r2"))
		want := fmt.Sprintf(tc.line, saved.Local().Format("15:04"))
		if n, shown := r.p.StepLine(); n != want || shown.IsZero() {
			t.Fatalf("line = %q (shown %v), want %q", n, shown, want)
		}
		r.ms.failSteps(nil)
		r.stepsSettle("m1")
		r.tool("m1", "effect_request", send("r3"))
		if n, shown := r.p.StepLine(); n != "" || !shown.IsZero() {
			t.Fatalf("line after a success = %q (shown %v)", n, shown)
		}
	}
}
