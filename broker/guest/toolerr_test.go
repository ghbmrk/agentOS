package guest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type marked struct{ s string }

func (m marked) Error() string { return m.s }
func (marked) GuestVisible()   {}

// Every registered tool family's raw error is stripped of a host path at
// the exit. A sentence the tool package marked for the guest is kept,
// and so is a fixed refusal that names no path.
func TestSR23gToolErrorsNameNoHostPath(t *testing.T) {
	canary := "/var/lib/agentos/machines/m1/upper"
	raw := errors.New("open " + canary + ": permission denied")
	names := []string{
		"worker_create", "worker_exec", "worker_read_file", "worker_write_file",
		"worker_checkpoint", "worker_fork", "worker_diff", "worker_rollback",
		"worker_destroy", "worker_list", "worker_fit", "worker_keep", "worker_delete",
		"recall_search", "owner_preferences", "recall_note",
		"owner_question", "owner_question_status",
		"managed_tree",
		"effect_request", "effect_status",
	}
	for _, name := range names {
		got := ScrubToolError(name, raw).Error()
		if strings.Contains(got, canary) || strings.Contains(got, "/var/") {
			t.Fatalf("%s kept a path: %q", name, got)
		}
		if !strings.Contains(got, "ref ") {
			t.Fatalf("%s: %q", name, got)
		}
	}
	if got := ScrubToolError("recall_search", errors.New("give a query, a fact, or both")).Error(); got != "give a query, a fact, or both" {
		t.Fatalf("fixed sentence changed: %q", got)
	}
	kept := marked{"delete /tmp/notes first"}
	if got := ScrubToolError("worker_delete", kept).Error(); got != kept.s {
		t.Fatalf("marked text changed: %q", got)
	}
}

// The socket the guest reads is the exit, not only the helper.
func TestSR23gTheSocketStripsAHostPath(t *testing.T) {
	canary := "/var/lib/agentos/machines/m1/upper"
	ft := &pathTools{err: errors.New("open " + canary + ": permission denied")}
	r := newRig(t, func(c *Config) { c.Tools = ft })
	res := r.rpc("m1", "tools/call", map[string]any{"name": "recall_search", "arguments": map[string]any{}})
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] != true || strings.Contains(text, canary) || strings.Contains(text, "/var/") {
		t.Fatalf("result %v", res)
	}
}

type pathTools struct{ err error }

func (p *pathTools) List() []map[string]any {
	return []map[string]any{{"name": "recall_search"}}
}

func (p *pathTools) Call(context.Context, string, string, string, json.RawMessage) (string, bool, error) {
	return "", true, p.err
}
