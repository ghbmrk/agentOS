package change

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-11, CHG-6, SM-AD-1, SM-AD-2, SM-AD-3, SM-AD-4
//
// SM-adoption-journal-a: the adoption lifecycle (adopt and stage, confirm,
// withdraw, revert) is a journaled intent at every step; the adoption set
// and the proposals awaiting the owner are rebuilt from the journal at
// boot, and the JSON store keeps only bulk.

// driveLifecycle drives every transition: release 40 is adopted (staged) and
// confirmed; release 41 is staged, then withdrawn and reverted by the
// owner; a local skill is adopted and reverted by the owner.
func driveLifecycle(t *testing.T, e *env) (r40, r41, sk Report) {
	t.Helper()
	e.cases(12, ClassSkill, "skills/greet", "hi")
	e.owner.approve = true
	r40 = e.release(release(t, 40, false, map[string][]byte{"host-image/release": []byte("a")}))
	if r40.State != StateAdopted {
		t.Fatal(r40)
	}
	if err := e.p.ConfirmStaged(r40.ID); err != nil {
		t.Fatal(err)
	}
	r41 = e.release(release(t, 41, false, map[string][]byte{"host-image/release": []byte("b")}))
	if r41.State != StateAdopted || !e.adoption(r41.ID).Staged {
		t.Fatal(r41)
	}
	e.p.SetWithdrawer(&withdrawer{})
	if err := e.p.Revert(bg, r41.Short, OriginOwner); err != nil {
		t.Fatal(err)
	}
	sk = e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hi"), "skills/extra": []byte("x")}})
	if sk.State != StateAdopted {
		t.Fatalf("skill: %+v", sk)
	}
	if err := e.p.Revert(bg, sk.Short, OriginOwner); err != nil {
		t.Fatal(err)
	}
	return r40, r41, sk
}

// adoptions is the adoption set, with times read as they are stored.
func (e *env) adoptions() []Adoption {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	var out []Adoption
	for _, a := range e.p.st.Adoptions {
		c := *a
		c.At = c.At.UTC().Round(0)
		out = append(out, c)
	}
	return out
}

func (e *env) journaled(prefix string) bool {
	for _, st := range e.eng.List() {
		if strings.HasPrefix(st.Intent.ID, prefix) && st.State == journal.Succeeded {
			return true
		}
	}
	return false
}

func TestEveryTransitionIsJournaled(t *testing.T) {
	e := newEnv(t, nil)
	r40, r41, sk := driveLifecycle(t, e)
	for _, step := range []string{
		adoptID(r40.ID),                // adopt: release 40 staged
		"chg:" + r40.ID + ":confirm:",  // confirm
		adoptID(r41.ID),                // adopt: release 41 staged
		"chg:" + r41.ID + ":withdraw:", // withdraw, before the applier is asked
		"chg:" + r41.ID + ":revert:",   // revert
		adoptID(sk.ID),
		"chg:" + sk.ID + ":revert:",
	} {
		if !e.journaled(step) {
			t.Errorf("no succeeded intent %s*", step)
		}
	}
	// The bulk store names no lifecycle: a transition visible only in the
	// JSON would be lost to replay.
	raw, _ := e.store.Load()
	for _, f := range []string{`"staged"`, `"confirmed"`, `"reverted"`, `"withdrawn_for"`, `"adoptions"`} {
		if bytes.Contains(raw, []byte(f)) {
			t.Errorf("the JSON store holds %s", f)
		}
	}
}

func TestAdoptionsRebuiltFromJournalAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "change.json")
	e := newEnv(t, func(c *Config) { c.Store = FileStore{Path: path} })
	driveLifecycle(t, e)
	want := e.adoptions()
	if len(want) != 3 {
		t.Fatalf("adoptions: %+v", want)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cfg := e.p.cfg
	cfg.Rand = bytes.NewReader(testSplitKey)
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.open(p)
	if got := e.adoptions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rebuilt from the journal:\n got %+v\nwant %+v", got, want)
	}
}

func TestProposalSurvivesRestart(t *testing.T) {
	for _, approve := range []bool{true, false} {
		e := newEnv(t, nil)
		e.cases(12, ClassSkill, "skills/greet", "hello")
		e.p.Attach(holdJournal{e.eng})
		a := e.propose(Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}})
		if a.State != StateAwaitingOwner {
			t.Fatalf("config change: %+v", a)
		}
		e.reopen()
		e.owner.approve = approve
		st, err := e.eng.Authorize(bg, adoptID(a.ID))
		if approve && err != nil {
			t.Fatal(err)
		}
		r, err := e.p.Settle(bg, a.ID)
		if approve {
			if err != nil || r.State != StateAdopted || string(e.p.Files("config")["config/a"]) != "1" {
				t.Fatalf("approved after a restart: %+v %v", r, err)
			}
			continue
		}
		if st.State != journal.Denied || r.State == StateAdopted {
			t.Fatalf("rejected after a restart: %+v %+v %v", st, r, err)
		}
		if _, ok := e.p.Files("config")["config/a"]; ok {
			t.Fatal("a rejected proposal adopted")
		}
		e.reopen()
		if _, err := e.p.Settle(bg, a.ID); err == nil {
			t.Fatal("a rejected proposal came back")
		}
	}
}

// crashStores snapshot the bulk store, the content store and the journal
// after every write, so each snapshot is a crash between two steps.
type crashStores struct {
	mu    sync.Mutex
	bulk  *MemStore
	cont  *MemContent
	jrnl  *journal.MemStore
	snaps []snapshot
}

type snapshot struct {
	bulk []byte
	cont map[string][]byte
	jrnl []byte
}

func (c *crashStores) snap() {
	b, _ := c.bulk.Load()
	j, _ := c.jrnl.ReadAll()
	c.cont.mu.Lock()
	m := make(map[string][]byte, len(c.cont.m))
	for k, v := range c.cont.m {
		m[k] = bytes.Clone(v)
	}
	c.cont.mu.Unlock()
	c.mu.Lock()
	c.snaps = append(c.snaps, snapshot{b, m, j})
	c.mu.Unlock()
}

type crashBulk struct{ c *crashStores }

func (s crashBulk) Load() ([]byte, error) { return s.c.bulk.Load() }
func (s crashBulk) Save(b []byte) error {
	err := s.c.bulk.Save(b)
	s.c.snap()
	return err
}

type crashContent struct{ c *crashStores }

func (s crashContent) Get(n string) ([]byte, error) { return s.c.cont.Get(n) }
func (s crashContent) Put(n string, b []byte) error {
	err := s.c.cont.Put(n, b)
	s.c.snap()
	return err
}
func (s crashContent) Delete(n string) error {
	err := s.c.cont.Delete(n)
	s.c.snap()
	return err
}

type crashJournal struct{ c *crashStores }

func (s crashJournal) Append(l []byte) error {
	err := s.c.jrnl.Append(l)
	s.c.snap()
	return err
}
func (s crashJournal) ReadAll() ([]byte, error)  { return s.c.jrnl.ReadAll() }
func (s crashJournal) Truncate(n int64) error    { return s.c.jrnl.Truncate(n) }
func (s crashJournal) Rewrite(data []byte) error { return s.c.jrnl.Rewrite(data) }

// legal is SM-AD-4's invariant on one adoption.
func legal(a Adoption) string {
	image := slices.Contains(a.Classes, ClassHostImage) || slices.Contains(a.Classes, ClassGuestImage)
	switch {
	case a.Confirmed && a.Staged:
		return "both staged and confirmed"
	case a.Confirmed && !image:
		return "confirmed but never staged"
	case a.Staged && !image:
		return "staged but not an image"
	case a.WithdrawnFor != "" && a.Confirmed:
		return "withdrawn after it was confirmed"
	case a.WithdrawnFor != "" && a.Reverted == "" && !a.Staged:
		return "withdrawn but never staged"
	}
	return ""
}

func TestCrashBetweenTransitionStepsSettles(t *testing.T) {
	c := &crashStores{bulk: &MemStore{}, cont: &MemContent{}, jrnl: &journal.MemStore{}}
	e := newEnvOn(t, crashJournal{c}, func(cfg *Config) {
		cfg.Store = crashBulk{c}
		cfg.Content = crashContent{c}
	})
	driveLifecycle(t, e)
	c.mu.Lock()
	snaps := slices.Clone(c.snaps)
	c.mu.Unlock()
	if len(snaps) < 20 {
		t.Fatalf("only %d steps", len(snaps))
	}
	live := e.adoptions()
	cfg := e.p.cfg
	for i, s := range snaps {
		bulk := &MemStore{data: s.bulk}
		js := &journal.MemStore{}
		if err := js.Rewrite(s.jrnl); err != nil {
			t.Fatal(err)
		}
		var first []Adoption
		for round := 0; round < 2; round++ { // replay settles, then stays
			r := &env{t: t, store: bulk, jstore: js, owner: &ownerPolicy{approve: true},
				ev: &evaluator{ran: map[string]bool{}, tasks: map[string]bool{}}}
			rc := cfg
			rc.Store, rc.Content, rc.Evaluator = bulk, &MemContent{m: s.cont}, r.ev
			rc.Rand = bytes.NewReader(testSplitKey)
			p, err := New(rc)
			if err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			r.open(p)
			if p.broken != nil {
				t.Fatalf("step %d: replay broke: %v", i, p.broken)
			}
			got := r.adoptions()
			for _, a := range got {
				if why := legal(a); why != "" {
					t.Fatalf("step %d: %s %s: %+v", i, a.ID, why, a)
				}
			}
			if round == 0 {
				first = got
				if i == len(snaps)-1 && !reflect.DeepEqual(got, live) {
					t.Fatalf("after the last step:\n got %+v\nwant %+v", got, live)
				}
			} else if !reflect.DeepEqual(got, first) {
				t.Fatalf("step %d: a second restart moved on:\n got %+v\nwant %+v", i, got, first)
			}
		}
	}
}
