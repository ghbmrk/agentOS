package change

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-4
//
// A save that published the new state but failed only at the directory
// sync (#1320) is the state a restart loads, so the change it carried is
// reported applied, not not_applied.

// dirSyncStore saves, then fails as durable.WriteFile does after the
// rename when the directory sync fails.
type dirSyncStore struct{ *MemStore }

func (d dirSyncStore) Save(b []byte) error {
	if err := d.MemStore.Save(b); err != nil {
		return err
	}
	return fmt.Errorf("%w: sync /var/lib/agentos/change: input/output error", durable.ErrDirSync)
}

func TestPublishedAdoptionIsReportedApplied(t *testing.T) {
	var logged []string
	e := newEnv(t, func(c *Config) {
		c.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	})
	e.p.cfg.Store = dirSyncStore{e.store}
	e.p.mu.Lock()
	next := e.p.st.Active.clone()
	next["skills/greet"] = []byte("hello")
	e.p.props["cX"] = &proposal{base: e.p.st.Active.Hash(), next: next, report: Report{Basis: BasisStanding}}
	e.p.mu.Unlock()
	adopt := journal.Intent{ID: "chg:cX:adopt", Action: ActionAdopt, GrantRef: BasisStanding}
	if o := e.p.Execute(bg, adopt, 1); o.Result != journal.ResultSucceeded {
		t.Fatalf("published adoption reported %v (%s)", o.Result, o.Evidence)
	}
	if err := e.p.healthy(); err != nil {
		t.Fatal("a directory sync failure broke the pipeline:", err)
	}
	if got := string(e.p.Files("skills")["skills/greet"]); got != "hello" {
		t.Fatalf("active skill %q after a published adoption", got)
	}
	// The owner's log says the save may not survive a power cut, naming
	// no host path (PE5).
	if len(logged) != 1 || strings.Contains(logged[0], "/var/") {
		t.Fatalf("logged %q", logged)
	}
	e.p.cfg.Store = e.store
	e.reopen()
	if o := e.p.Reconcile(bg, adopt, 1); o.Result != journal.ResultSucceeded {
		t.Fatalf("after restart the adoption reconciles %v", o.Result)
	}
	if got := string(e.p.Files("skills")["skills/greet"]); got != "hello" {
		t.Fatalf("after restart active skill %q", got)
	}
}
