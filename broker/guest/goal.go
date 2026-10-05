package guest

// Goal IDs (G14). Every effect request is stamped with the owner message
// its lineage is serving, so a task is one owner request rather than a
// whole guest lineage (OP-1's goal_id; compiled skills, Loop 1 mining, and
// replay group by it). The broker chooses the goal; nothing the guest
// sends names one. The goal is part of an intent's identity (OP-1), so it
// is fixed by the request's first submission: a repeat keeps it, whatever
// the lineage is serving by then.

// GoalID is the goal ID of the task an owner message started.
func GoalID(msgID string) string { return "owner:" + msgID }

// lineageOf is machine m's fork lineage, or "" if the manager cannot say.
func (p *Plane) lineageOf(m *machine) string {
	if m.lineage != "" {
		return m.lineage
	}
	l, _ := p.cfg.Machines.Lineage(m.id)
	return l
}

// lineageOpen reports whether any open machine is in lineage.
func (p *Plane) lineageOpen(lineage string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.ms {
		if m.lineage == lineage {
			return true
		}
	}
	return false
}

// handedOut records that m's guest was handed owner message id: from now
// on its lineage serves it.
func (p *Plane) handedOut(m *machine, id string) {
	if l := p.lineageOf(m); l != "" {
		p.store.setGoal(l, id)
	}
}

// goal is the goal a new request from lineage serves. It is the one owner
// message the lineage's guests hold unanswered; with none, the last one
// it was handed (work that goes on after the answer still serves it);
// with several, none, since the broker cannot tell which one a request
// is for and does not guess.
func (p *Plane) goal(lineage string) string {
	if lineage == "" {
		return ""
	}
	p.mu.Lock()
	ms := make([]*machine, 0, len(p.ms))
	for _, m := range p.ms {
		if m.lineage == lineage {
			ms = append(ms, m)
		}
	}
	p.mu.Unlock()
	var open []string
	for _, m := range ms {
		open = append(open, m.box.handed()...)
	}
	switch len(open) {
	case 0:
		if id := p.store.goal(lineage); id != "" {
			return GoalID(id)
		}
		return ""
	case 1:
		return GoalID(open[0])
	}
	return ""
}
