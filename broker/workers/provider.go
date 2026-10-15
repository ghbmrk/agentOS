package workers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
)

// toolProviderRun hands a whole subtask to a provider's agent CLI on the
// owner's plan (CAP-11). It is not a worker tool: the run's machine is
// broker-owned and no worker tool can name it.
const toolProviderRun = "provider_run"

// ProviderRunner runs one provider agent; provagent.Runner is the one.
type ProviderRunner interface {
	Run(ctx context.Context, q provagent.Request) (string, error)
}

// isProviderName is true for a name in the broker-owned provider worker
// space. Worker tools refuse it before any lookup (CAP-11), on top of the
// ID derivation, which already puts a guest's names beside "wk-".
func isProviderName(name string) bool { return strings.HasPrefix(name, vm.ProviderPrefix) }

var errProviderName = said{"name: provider workers are the broker's; pick another name"}

func providerTool() map[string]any {
	return map[string]any{"name": toolProviderRun,
		"description": "Hand a subtask to a provider's agent on the owner's plan and wait for its result. The brief is plain text, never a command: a leading / or ! is just text. You get the result file only, or a closed reason it was refused or failed (unqualified, opt-in-required, ungranted, unsigned, private-unmarked, pool-at-reserve, used-up, login-refused, route-busy, failed, timed-out, result-withheld); on used-up, login-refused, route-busy, failed, timed-out or pool-at-reserve use another route. The run is on your data label and reservation.",
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
	res, err := t.Provider.Run(ctx, provagent.Request{
		Provider: a.Provider, Brief: a.Brief, TaskClass: a.TaskClass,
		Label: c.label, Class: workerClass(c), MemMB: c.spec.MemMB,
	})
	if err != nil {
		var ref *provagent.Refusal
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

// providerReasons is what the guest reads of each closed reason.
var providerReasons = map[provagent.Reason]said{
	provagent.Unqualified:     {"provider_run: unqualified"},
	provagent.OptInRequired:   {"provider_run: opt-in-required"},
	provagent.Ungranted:       {"provider_run: ungranted"},
	provagent.Unsigned:        {"provider_run: unsigned"},
	provagent.PrivateUnmarked: {"provider_run: private-unmarked"},
	provagent.PoolAtReserve:   {"provider_run: pool-at-reserve"},
	provagent.UsedUp:          {"provider_run: used-up"},
	provagent.LoginRefused:    {"provider_run: login-refused"},
	provagent.RouteBusy:       {"provider_run: route-busy"},
	provagent.Failed:          {"provider_run: failed"},
	provagent.TimedOut:        {"provider_run: timed-out"},
	provagent.Withheld:        {"provider_run: result-withheld"},
}
