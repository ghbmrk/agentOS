package workers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// toolProviderRun hands a whole subtask to a provider's agent CLI on the
// owner's plan (CAP-11). It is not a worker tool: the run's machine is
// broker-owned and no worker tool can name it.
const toolProviderRun = "provider_run"

// ProviderRequest is one provider_run call: the guest's provider, brief and
// task class, and the caller's label, class, reservation and lineage (RES-5
// caps a lineage's concurrent runs).
type ProviderRequest struct {
	Provider, Brief, TaskClass string
	Label                      vm.Label
	Class                      admission.Class
	MemMB                      int64
	Lineage                    string
}

// ProviderReason is a closed reason a run was refused or failed. The wiring
// maps the runner's own reasons onto these by name.
type ProviderReason string

// ProviderRefusal is a run that returned no result, for one closed reason.
type ProviderRefusal struct{ Reason ProviderReason }

func (r *ProviderRefusal) Error() string { return "provider_run: " + string(r.Reason) }

// ProviderRunner runs one provider agent. The wiring (agentosd) adapts
// provagent.Runner to it, so the worker tools link neither the runner nor
// the model route it is seeded from (ARC-2).
type ProviderRunner interface {
	Run(ctx context.Context, q ProviderRequest) (string, error)
}

// KnownProviderReason reports whether r has a guest text here.
func KnownProviderReason(r ProviderReason) bool { _, ok := providerReasons[r]; return ok }

// isProviderName is true for a name in the broker-owned provider worker
// space. Worker tools refuse it before any lookup (CAP-11), on top of the
// ID derivation, which already puts a guest's names beside "wk-".
func isProviderName(name string) bool { return strings.HasPrefix(name, vm.ProviderPrefix) }

var errProviderName = said{"name: provider workers are the broker's; pick another name"}

func providerTool() map[string]any {
	return map[string]any{"name": toolProviderRun,
		"description": "Hand a subtask to a provider's agent on the owner's plan and wait for its result. The brief is plain text, never a command: a leading / or ! is just text. You get the result file only, or a closed reason it was refused or failed (unqualified, opt-in-required, ungranted, unsigned, private-unmarked, pool-at-reserve, used-up, login-refused, vault-locked, route-busy, failed, timed-out, result-withheld), with one line on what to do; on used-up, login-refused, vault-locked, route-busy, failed, timed-out or pool-at-reserve use another route. The run is on your data label and reservation.",
		"inputSchema": obj(map[string]any{
			"provider":   map[string]any{"type": "string", "description": "A provider ID, e.g. codex."},
			"brief":      map[string]any{"type": "string", "description": "The subtask, as text."},
			"task_class": map[string]any{"type": "string", "description": "code or research."}}, "provider", "brief", "task_class")}
}

// providerRun serves provider_run for caller c.
func (t *Tools) providerRun(ctx context.Context, c caller, raw json.RawMessage) (any, error) {
	var a struct {
		Provider  string `json:"provider"`
		Brief     string `json:"brief"`
		TaskClass string `json:"task_class"`
	}
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	res, err := t.Provider.Run(ctx, ProviderRequest{
		Provider: a.Provider, Brief: a.Brief, TaskClass: a.TaskClass,
		Label: c.label, Class: workerClass(c), MemMB: c.spec.MemMB, Lineage: c.lineage,
	})
	if err != nil {
		var ref *ProviderRefusal
		if errors.As(err, &ref) {
			// The closed reason, never the wrapped cause. A reason this
			// table lacks leaves as a logged ref.
			if r, ok := providerReasons[ref.Reason]; ok {
				return nil, r
			}
		}
		return nil, err
	}
	return map[string]any{"result": res}, nil
}

// providerReasons is what the guest reads of each closed reason: the code,
// then one line on what to do (ONB-9's plain words).
var providerReasons = map[ProviderReason]said{
	"unqualified":      {"provider_run: unqualified: this provider's route is not qualified yet; use another route"},
	"opt-in-required":  {"provider_run: opt-in-required: the owner has not opted in to this provider; use another route"},
	"ungranted":        {"provider_run: ungranted: the owner has not granted this plan route; use another route"},
	"unsigned":         {"provider_run: unsigned: the owner has not signed in to this plan and has been asked to; use another route meanwhile"},
	"private-unmarked": {"provider_run: private-unmarked: the owner has not allowed private data on this plan; use another route"},
	"pool-at-reserve":  {"provider_run: pool-at-reserve: the plan is at the owner's reserve, or its usage is unread; use another route"},
	"used-up":          {"provider_run: used-up: the plan's limit is used up; use another route"},
	"login-refused":    {"provider_run: login-refused: the provider refused the plan's login and the owner has been asked to sign in again; use another route"},
	"vault-locked":     {"provider_run: vault-locked: the owner's vault is locked; ask the owner to unlock it, or use another route"},
	"route-busy":       {"provider_run: route-busy: the plan route is busy; try again later, or use another route"},
	"failed":           {"provider_run: failed: the run failed, or its brief or result was over the size cap; shorten the brief, or use another route"},
	"timed-out":        {"provider_run: timed-out: the run hit its time limit; split the task, or use another route"},
	"result-withheld":  {"provider_run: result-withheld: the result carried a credential format and was withheld; do not retry the same brief"},
}
