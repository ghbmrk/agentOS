package locks

import "time"

// WaitWork waits until no lock's relock or code push is running.
func (g *Gate) WaitWork() {
	for {
		g.mu.Lock()
		idle := len(g.busy) == 0
		g.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// WaitTold waits until the teller has raised every waiting alert.
func (g *Gate) WaitTold() {
	for {
		g.mu.Lock()
		idle := !g.telling && len(g.tells) == 0
		g.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
}
