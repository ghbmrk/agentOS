package dailyhost

import "github.com/ghbmrk/agentos/broker/digestqueue/dailypolicy"

// NewProvisioned assembles the opt-in host against one already constructed
// shared Gate, requiring existing accounting state and a configured store
// latency observation. It never provisions state, starts a runner or activates.
//
// Leave Daily.Gate/Recheck, PolicyHealth and policy.Engine unset: this function
// owns all four bindings. policy.Budget must be the actual approval/question
// Gate; its identity outside this assembly remains trusted caller custody.
// Missing/faulted accounting produces a held recovery Host with owner controls,
// not a replacement counter. Configuration errors return no Host and require
// the caller's independent startup control/recovery path.
func NewProvisioned(cfg Config, policy dailypolicy.Config) (*Host, error) {
	if !policy.Budget.ProvisionedPacingConfigured() || policy.Engine != nil ||
		cfg.Daily.Gate != nil || cfg.Daily.Recheck != nil || cfg.PolicyHealth != nil {
		return nil, ErrConfig
	}
	policy.Engine = cfg.Owner.Engine
	p, err := dailypolicy.New(policy)
	if err != nil {
		return nil, ErrConfig
	}
	cfg.Daily.Gate = p.Check
	cfg.Daily.Recheck = p.Recheck
	cfg.PolicyHealth = p.Health
	return New(cfg)
}
