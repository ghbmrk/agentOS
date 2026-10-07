package grants

import "time"

// HeldUntil is when the last effect the owner approved under an undo
// window is released (REV-3, CH-16), or zero when none is held. A restart
// cancels every held effect (reversible RV6), so the updater's planned
// restart waits until then (apply Config.Held, UX-76-2). An effect still
// waiting for the owner, released, or undone does not count.
func (g *Gate) HeldUntil() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	var last time.Time
	for _, w := range g.waiting {
		if w.held && w.sendAt.After(last) {
			last = w.sendAt
		}
	}
	return last
}
