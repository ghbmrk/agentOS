package guest

// REQ: CH-2, KRN-5, OP-1

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Each guest-input defence in plan.go has a test that fails when it is
// reverted (L3 on #3090). These cover the ones no other test reached.

// A machine the manager no longer knows submits nothing.
func TestAnUnknownMachineSubmitsNothing(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	r.ms.mu.Lock()
	r.ms.gone["m1"] = true
	r.ms.mu.Unlock()
	if _, e := r.tool("m1", "plan", send("r1")); !strings.Contains(e, "unknown machine") || r.kern.plans() != 0 {
		t.Fatalf("unknown machine: %q, %d plans", e, r.kern.plans())
	}
}

// Arguments that are not an object are refused as such.
func TestPlanArgumentsMustBeAnObject(t *testing.T) {
	r := newRig(t, nil)
	res := r.rpc("m1", "tools/call", map[string]any{"name": "plan", "arguments": []any{"r1"}})
	text, _ := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] != true || !strings.Contains(text, "must be an object") || r.kern.plans() != 0 {
		t.Fatalf("array arguments: %v", res)
	}
}

// When the kernel cannot be read, the plane cannot tell a first plan from a
// repeat, so it submits nothing and says the state is unknown (KRN-5).
func TestAnUnreadableKernelSubmitsNothing(t *testing.T) {
	r := newRig(t, nil)
	r.kern.readErr = true
	if st, _ := r.tool("m1", "plan", send("r1")); st.State != "unknown" || st.Reason != reasonLost || r.kern.plans() != 0 {
		t.Fatalf("unreadable kernel: %+v, %d plans", st, r.kern.plans())
	}
}

// A guest that hangs up while its plan is being submitted does not cancel
// the submission: the plan reaches the kernel, and a repeat reads it (OP-1).
func TestAHangUpDoesNotCancelASubmission(t *testing.T) {
	r := newRig(t, nil)
	r.kern.entered, r.kern.hold = make(chan struct{}), make(chan struct{})
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "plan", "arguments": send("r1")}})
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://broker/mcp", strings.NewReader(string(b)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := r.client("m1").Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	<-r.kern.entered
	cancel()
	<-done
	time.Sleep(200 * time.Millisecond) // the server sees the hang-up
	close(r.kern.hold)
	deadline := time.Now().Add(5 * time.Second)
	for r.kern.ran("m1/r1") == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := r.kern.ran("m1/r1"); n != 1 {
		t.Fatalf("the hung-up plan ran %d times", n)
	}
	r.kern.hold = nil
	if st, _ := r.tool("m1", "plan", map[string]any{"request_id": "r1"}); st.State != "done" {
		t.Fatalf("repeat after the hang-up: %+v", st)
	}
}

// A plan the kernel refuses before logging it is reported refused, and
// nothing ran.
func TestAPlanTheKernelDidNotLogIsRefused(t *testing.T) {
	r := newRig(t, nil)
	r.kern.refuse = true
	if st, _ := r.tool("m1", "plan", send("r1")); st.State != "refused" || !strings.Contains(st.Reason, "nothing ran") || r.kern.plans() != 0 {
		t.Fatalf("unlogged plan: %+v", st)
	}
}
