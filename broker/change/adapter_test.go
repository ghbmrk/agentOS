package change

// REQ: ADP-8, ADP-6, ADP-2, A13

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/verb"
)

// demoTarget is the adapters target with its demo harness: it reports
// the effects it is set to observe for each operation, never anything the
// adapter declares.
type demoTarget struct {
	mu      sync.Mutex
	tree    Tree
	observe map[string][]string // operation -> observed effects; absent: not run
	err     error
	demoed  []string // tools demoed
}

func (d *demoTarget) Current() (Tree, error) { return Tree{}, nil }

func (d *demoTarget) Apply(t Tree) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tree = t
	return nil
}

func (d *demoTarget) Demo(tool string, a Adapter) ([]verb.DemoRun, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.demoed = append(d.demoed, tool)
	if d.err != nil {
		return nil, d.err
	}
	var runs []verb.DemoRun
	for op := range a.Operations {
		if eff, ok := d.observe[op]; ok {
			runs = append(runs, verb.DemoRun{Operation: op, Effects: eff})
		}
	}
	return runs, nil
}

const mailAdapter = `{"operations":{"list":"read","save":"draft","deliver":"send"},"grants":["mail"]}`

func adapterEnv(t *testing.T, observe map[string][]string) (*env, *demoTarget) {
	d := &demoTarget{observe: observe}
	e := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"adapters": d} })
	return e, d
}

func adapterCandidate(body string) Candidate {
	return Candidate{Source: Local, Origin: "adapter-builder", Files: Tree{"adapters/mail.json": []byte(body)}}
}

func truthful() map[string][]string {
	return map[string][]string{"list": {verb.Read}, "save": {verb.Draft}, "deliver": {verb.Send}}
}

// A13, ADP-8: an agent-drafted adapter whose operation labelled "draft"
// sends in the demo environment is not adopted, and the owner is never
// asked to adopt it. The effect comes from the harness, not the adapter.
func TestA13MislabelledDraftThatSendsBlocksAdoption(t *testing.T) {
	obs := truthful()
	obs["save"] = []string{verb.Draft, verb.Send}
	e, d := adapterEnv(t, obs)
	e.owner.approve = true
	rep := e.propose(adapterCandidate(mailAdapter))
	if rep.State != StateRejected || !strings.Contains(rep.Reason, `"save"`) || !strings.Contains(rep.Reason, "send") {
		t.Fatalf("got %s %q", rep.State, rep.Reason)
	}
	if len(d.demoed) != 1 || d.demoed[0] != "mail" {
		t.Fatalf("demoed %v, want the mail tool once", d.demoed)
	}
	if _, ok := e.p.Files("adapters")["adapters/mail.json"]; ok {
		t.Fatal("the mislabelled adapter is active")
	}
	if len(e.owner.asked) != 0 {
		t.Fatalf("the owner was asked to adopt it: %v", e.owner.asked)
	}
}

// ADP-6: the same adapter, truthful in the demo environment, is never
// authority-neutral: the owner is asked, sees its grants and mappings in
// the file, and only then is it applied.
func TestADP6AdapterGoesToTheOwner(t *testing.T) {
	e, d := adapterEnv(t, truthful())
	rep := e.propose(adapterCandidate(mailAdapter))
	if !refusedByOwner(e, rep) || d.tree["adapters/mail.json"] != nil {
		t.Fatalf("got %s neutral=%v %q: want the owner asked and refusing", rep.State, rep.Neutral, rep.Reason)
	}
	e.owner.approve = true
	rep = e.propose(adapterCandidate(mailAdapter))
	if rep.State != StateAdopted || !e.owner.wasAsked(adoptID(rep.ID)) {
		t.Fatalf("got %s %q, asked=%v", rep.State, rep.Reason, e.owner.asked)
	}
	if string(d.tree["adapters/mail.json"]) != mailAdapter {
		t.Fatalf("applied %q", d.tree)
	}
}

// Brief item 5: an operation the harness never exercised is not a pass.
func TestADP8AdapterWithAnUnexercisedOperationIsNotAdopted(t *testing.T) {
	obs := truthful()
	delete(obs, "deliver")
	e, _ := adapterEnv(t, obs)
	e.owner.approve = true
	rep := e.propose(adapterCandidate(mailAdapter))
	if rep.State != StateRejected || !strings.Contains(rep.Reason, `"deliver"`) || !strings.Contains(rep.Reason, "never exercised") {
		t.Fatalf("got %s %q", rep.State, rep.Reason)
	}
}

// Brief item 6: a payment mapped to send blocks, though both are
// irreversible (the owner may pre-allow send, ADP-9).
func TestADP8PaymentMappedToSendIsNotAdopted(t *testing.T) {
	obs := truthful()
	obs["deliver"] = []string{verb.Buy}
	e, _ := adapterEnv(t, obs)
	e.owner.approve = true
	rep := e.propose(adapterCandidate(mailAdapter))
	if rep.State != StateRejected || !strings.Contains(rep.Reason, `"deliver"`) || !strings.Contains(rep.Reason, "buy") {
		t.Fatalf("got %s %q", rep.State, rep.Reason)
	}
}

// ADP-8 fails closed: no harness, or a harness that cannot run the demo
// (no demo environment), adopts nothing.
func TestADP8AdapterWithoutADemoRunIsNotAdopted(t *testing.T) {
	e := newEnv(t, nil)
	e.owner.approve = true
	if rep := e.propose(adapterCandidate(mailAdapter)); rep.State != StateRejected || !strings.Contains(rep.Reason, "demo") {
		t.Fatalf("no harness: got %s %q", rep.State, rep.Reason)
	}
	e2, d := adapterEnv(t, truthful())
	e2.owner.approve = true
	d.err = errors.New("no demo environment")
	if rep := e2.propose(adapterCandidate(mailAdapter)); rep.State != StateRejected || !strings.Contains(rep.Reason, "no demo environment") {
		t.Fatalf("harness error: got %s %q", rep.State, rep.Reason)
	}
}

// ADP-2: an unmapped operation is checked as draft-only and goes to the
// owner with the rest; one that sends blocks. An adapter cannot set a
// class or name a verb off the list.
func TestADP2AdapterMappingRules(t *testing.T) {
	odd := `{"operations":{"list":"read","odd":""}}`
	e, _ := adapterEnv(t, map[string][]string{"list": nil, "odd": {verb.Draft}})
	if rep := e.propose(adapterCandidate(odd)); !refusedByOwner(e, rep) {
		t.Fatalf("unmapped that drafts: got %s neutral=%v %q", rep.State, rep.Neutral, rep.Reason)
	}
	e, _ = adapterEnv(t, map[string][]string{"list": nil, "odd": {verb.Send}})
	if rep := e.propose(adapterCandidate(odd)); rep.State != StateRejected || !strings.Contains(rep.Reason, `"odd"`) {
		t.Fatalf("unmapped that sends: got %s %q", rep.State, rep.Reason)
	}
	for name, body := range map[string]string{
		"claims a class": `{"operations":{"list":"read"},"class":"reversible"}`,
		"claims effects": `{"operations":{"list":"read"},"effects":{"list":[]}}`,
		"verb off list":  `{"operations":{"list":"peek"}}`,
		"no operations":  `{"operations":{}}`,
		"not json":       `operations: list`,
	} {
		e, _ := adapterEnv(t, map[string][]string{"list": nil})
		e.owner.approve = true
		if rep := e.propose(adapterCandidate(body)); rep.State != StateRejected {
			t.Errorf("%s: got %s", name, rep.State)
		}
	}
	e, _ = adapterEnv(t, truthful())
	e.owner.approve = true
	c := adapterCandidate(mailAdapter)
	c.Files = Tree{"adapters/mail/v2.json": []byte(mailAdapter)}
	if rep := e.propose(c); rep.State != StateRejected {
		t.Fatalf("nested adapter path: got %s", rep.State)
	}
}

// ADP-6, OSS-3: an adapter is private-derived. A shared package cannot
// carry one, and an adopted one is never exported, even from public
// inputs.
func TestADP6AdapterIsPrivateDerived(t *testing.T) {
	e, _ := adapterEnv(t, truthful())
	e.owner.approve = true
	pkg, err := json.Marshal(Package{Format: PackageFormat, Files: Tree{"adapters/mail.json": []byte(mailAdapter)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.p.Import(bg, pkg); err == nil || !strings.Contains(err.Error(), "CHG-5") {
		t.Fatalf("imported a shared adapter: %v", err)
	}
	if cl := e.p.classify([]Edit{{Path: "adapters/mail.json", After: []byte(mailAdapter)}}, Tree{}, Shared); cl.forbidden == "" {
		t.Fatal("a shared source may carry an adapter")
	}
	c := adapterCandidate(mailAdapter)
	c.Public = true
	rep := e.propose(c)
	if rep.State != StateAdopted {
		t.Fatalf("got %s %q", rep.State, rep.Reason)
	}
	if err := e.p.SetSharing(bg, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.Export(bg, rep.ID); !errors.Is(err, ErrNotShareable) {
		t.Fatalf("exported an adapter: %v", err)
	}
}

// Removing an adapter narrows authority: no demo, but still the owner's.
func TestADP6AdapterRemovalGoesToTheOwner(t *testing.T) {
	e, d := adapterEnv(t, truthful())
	e.owner.approve = true
	if rep := e.propose(adapterCandidate(mailAdapter)); rep.State != StateAdopted {
		t.Fatal(rep)
	}
	d.err = errors.New("no demo environment")
	e.owner.approve = false
	rep := e.propose(Candidate{Source: Local, Delete: []string{"adapters/mail.json"}})
	if !refusedByOwner(e, rep) {
		t.Fatalf("got %s neutral=%v %q", rep.State, rep.Neutral, rep.Reason)
	}
}

// refusedByOwner reports that rep qualified, was not neutral, and went to
// the owner, who said no (the env's owner refuses unless approve is set).
func refusedByOwner(e *env, rep Report) bool {
	return rep.State == StateRejected && rep.Basis == BasisOwner && !rep.Neutral && e.owner.wasAsked(adoptID(rep.ID))
}

// ADP-6, ADP-2 (Security, L3 and UX finding on #2049): the owner's item
// for an adapter names the tool, every grant it asks for, each operation
// that acts irreversibly and each left unmapped (draft only), never reads
// as a learned procedure, and is always high tier.
func TestADP6AdapterOwnerItemNamesToolGrantsAndOperations(t *testing.T) {
	const body = `{"operations":{"list":"read","save":"draft","deliver":"send","forward":""},"grants":["mail","contacts"]}`
	obs := truthful()
	obs["forward"] = []string{verb.Draft}
	e, _ := adapterEnv(t, obs)
	e.p.Attach(holdJournal{e.eng})
	e.owner.approve = true
	rep := e.propose(adapterCandidate(body))
	if rep.State != StateAwaitingOwner {
		t.Fatalf("got %s %q", rep.State, rep.Reason)
	}
	it, err := e.p.Line(journal.Intent{ID: adoptID(rep.ID), Action: ActionAdopt})
	if err != nil {
		t.Fatal(err)
	}
	if it.Facts.Kind != owner.GrantChange || it.Facts.Verb != "adopt" {
		t.Fatalf("facts %+v: want a high-tier adopt", it.Facts)
	}
	if it.Object != "a connection to mail" {
		t.Fatalf("object %q", it.Object)
	}
	if it.Detail != "can send; asks for mail, contacts; 1 draft only" {
		t.Fatalf("detail %q", it.Detail)
	}
	ts, ok := it.Terms.List()
	if !ok {
		t.Fatalf("terms %q", it.Terms)
	}
	want := []owner.Term{
		{Label: "Tool", Value: "mail"},
		{Label: "Asks for", Value: "mail"},
		{Label: "Asks for", Value: "contacts"},
		{Label: "Acts for good", Value: "deliver: send"},
		{Label: "Draft only", Value: "forward, until you choose what it does"},
		{Label: "Also", Value: "list: read"},
		{Label: "Also", Value: "save: draft"},
	}
	if !slices.Equal(ts, want) {
		t.Fatalf("terms\n got %v\nwant %v", ts, want)
	}
	for _, s := range append([]string{it.Object, it.Detail}, termText(ts)...) {
		if strings.Contains(s, "learned") || strings.Contains(s, "adapters/") {
			t.Fatalf("%q reads as a learned change or shows a file path", s)
		}
	}
	a := &Adoption{Classes: []Class{ClassAdapter}, Edits: []Edit{{Path: "adapters/mail.json", After: []byte(body)}}}
	if got := e.p.what(a); got != "Connected mail" {
		t.Fatalf("what %q", got)
	}
	a.Edits[0].After = nil
	if got := e.p.what(a); got != "Removed the connection to mail" {
		t.Fatalf("what %q", got)
	}
}

// ADP-6: removing an adapter names the tool and is high tier.
func TestADP6AdapterRemovalOwnerItem(t *testing.T) {
	e, d := adapterEnv(t, truthful())
	e.owner.approve = true
	if rep := e.propose(adapterCandidate(mailAdapter)); rep.State != StateAdopted {
		t.Fatal(rep)
	}
	d.err = errors.New("no demo environment")
	e.p.Attach(holdJournal{e.eng})
	rep := e.propose(Candidate{Source: Local, Delete: []string{"adapters/mail.json"}})
	if rep.State != StateAwaitingOwner {
		t.Fatalf("got %s %q", rep.State, rep.Reason)
	}
	it, err := e.p.Line(journal.Intent{ID: adoptID(rep.ID), Action: ActionAdopt})
	if err != nil {
		t.Fatal(err)
	}
	if it.Facts.Kind != owner.GrantChange || it.Facts.Verb != "remove" || it.Object != "the connection to mail" || it.Terms != "" {
		t.Fatalf("item %+v", it)
	}
}

// ADP-6, CRED-6 (Security delta on #2049): an operation mapped to the
// secret verb is shown as acting for good and leads the texted detail,
// never filed under "Also", so key export cannot be approved unseen.
func TestADP6AdapterSecretOperationIsNamedToTheOwner(t *testing.T) {
	const body = `{"operations":{"list":"read","export":"reveal-or-create-secret"},"grants":["mail"]}`
	obs := map[string][]string{"list": {verb.Read}, "export": {verb.RevealSecret}}
	e, _ := adapterEnv(t, obs)
	e.p.Attach(holdJournal{e.eng})
	e.owner.approve = true
	rep := e.propose(adapterCandidate(body))
	if rep.State != StateAwaitingOwner {
		t.Fatalf("got %s %q", rep.State, rep.Reason)
	}
	it, err := e.p.Line(journal.Intent{ID: adoptID(rep.ID), Action: ActionAdopt})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(it.Detail, "can reveal-or-create-secret") {
		t.Fatalf("detail %q: want the secret verb first", it.Detail)
	}
	ts, _ := it.Terms.List()
	if !slices.Contains(ts, owner.Term{Label: "Acts for good", Value: "export: reveal-or-create-secret"}) {
		t.Fatalf("terms %q", termText(ts))
	}
	for _, x := range ts {
		if x.Label == "Also" && strings.Contains(x.Value, "secret") {
			t.Fatalf("secret op filed under Also: %q", termText(ts))
		}
	}
}

func termText(ts []owner.Term) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Label, t.Value)
	}
	return out
}
