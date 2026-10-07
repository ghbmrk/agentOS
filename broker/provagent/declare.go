// Package provagent is the provider-agent declaration and guest resources
// tool (CAP-11, CAP-12). Declarations are data: no credentials, no account
// detail. The resources tool answers headroom and preference deny reasons
// from a closed set.
package provagent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/planquota"
)

type Custody string

const (
	BrokerHeld Custody = "broker-held"
	WorkerHeld Custody = "worker-held"
)

type PoolDecl struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

type Declaration struct {
	ID           string     `json:"id"`
	CLI          string     `json:"cli"`
	Versions     []string   `json:"versions"`
	Command      []string   `json:"command"`
	Custody      Custody    `json:"custody"`
	TermsNote    string     `json:"terms_note"`
	Hosts        []string   `json:"hosts"`
	Pools        []PoolDecl `json:"pools"`
	UsedUpSignal string     `json:"used_up_signal"`
	TaskClasses  []string   `json:"task_classes"`
	PrivateOK    bool       `json:"-"`
}

func (d Declaration) Validate() error {
	if d.ID == "" || d.CLI == "" || len(d.Command) == 0 {
		return fmt.Errorf("provagent: id, cli, and command are required")
	}
	if d.Custody != BrokerHeld && d.Custody != WorkerHeld {
		return fmt.Errorf("provagent: custody must be broker-held or worker-held")
	}
	if len(d.Hosts) == 0 || len(d.Pools) == 0 {
		return fmt.Errorf("provagent: hosts and pools are required")
	}
	raw, _ := json.Marshal(d)
	s := string(raw)
	for _, bad := range []string{"sk-", "Bearer ", "eyJ", "AKIA", "password", "refresh_token"} {
		if strings.Contains(s, bad) {
			return fmt.Errorf("provagent: declaration must not carry credential material")
		}
	}
	return nil
}

type DenyReason string

const (
	NotGranted      DenyReason = "not_granted"
	AtReserve       DenyReason = "pool_at_reserve"
	CoolingDown     DenyReason = "cooling_down"
	LabelNotAllowed DenyReason = "label_not_allowed"
	ConcurrencyFull DenyReason = "concurrency_full"
)

type RouteView struct {
	ID           string     `json:"id"`
	Kind         string     `json:"kind"`
	TaskClasses  []string   `json:"task_classes"`
	Pools        []PoolView `json:"pools,omitempty"`
	MarginalCost string     `json:"marginal_cost"`
	FreeConc     int        `json:"free_concurrency"`
	LabelOK      bool       `json:"label_ok"`
}

type PoolView struct {
	ID       string  `json:"id"`
	Headroom float64 `json:"headroom"`
	Reset    string  `json:"reset,omitempty"`
}

type Registry struct {
	Decls []Declaration
	Gate  *planquota.Gate
	Now   func() time.Time
}

func (r *Registry) Resources(privateCaller bool) []RouteView {
	out := make([]RouteView, 0, len(r.Decls))
	for _, d := range r.Decls {
		if err := d.Validate(); err != nil {
			continue
		}
		labelOK := !privateCaller || d.PrivateOK
		rv := RouteView{
			ID: d.ID, Kind: "plan_agent", TaskClasses: append([]string(nil), d.TaskClasses...),
			MarginalCost: "0", LabelOK: labelOK,
		}
		free := planquota.DefaultConcurrency
		for _, pd := range d.Pools {
			pv := PoolView{ID: pd.ID}
			if r.Gate != nil {
				if p, ok := r.Gate.Get(pd.ID); ok {
					pv.Headroom = p.Headroom(false)
					if !p.Reset.IsZero() {
						pv.Reset = p.Reset.UTC().Format(time.RFC3339)
					}
					left := p.Cap() - p.Running
					if left < free {
						free = left
					}
				}
			}
			rv.Pools = append(rv.Pools, pv)
		}
		if free < 0 {
			free = 0
		}
		rv.FreeConc = free
		out = append(out, rv)
	}
	return out
}

func (r *Registry) Honour(want string, privateCaller bool) (use string, why DenyReason) {
	var d *Declaration
	for i := range r.Decls {
		if r.Decls[i].ID == want {
			d = &r.Decls[i]
			break
		}
	}
	if d == nil {
		return "", NotGranted
	}
	if privateCaller && !d.PrivateOK {
		return "", LabelNotAllowed
	}
	if r.Gate == nil {
		return want, ""
	}
	ids := make([]string, len(d.Pools))
	for i, p := range d.Pools {
		ids[i] = p.ID
	}
	err := r.Gate.Admit(ids, false)
	if err == nil {
		r.Gate.Release(ids)
		return want, ""
	}
	var ref planquota.Refusal
	if !asRefusal(err, &ref) {
		return "", NotGranted
	}
	switch ref.Reason {
	case "at_reserve":
		return "", AtReserve
	case "concurrency_full":
		return "", ConcurrencyFull
	default:
		return "", NotGranted
	}
}

func asRefusal(err error, r *planquota.Refusal) bool {
	if err == nil {
		return false
	}
	if v, ok := err.(planquota.Refusal); ok {
		*r = v
		return true
	}
	return false
}

func ToolJSON(views []RouteView) ([]byte, error) {
	b, err := json.Marshal(views)
	if err != nil {
		return nil, err
	}
	s := string(b)
	for _, bad := range []string{"sk-", "Bearer ", "eyJ", "AKIA", "refresh_token", "password"} {
		if strings.Contains(s, bad) {
			return nil, fmt.Errorf("provagent: resources JSON must not carry credential material")
		}
	}
	return b, nil
}
