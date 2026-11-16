package graph

// REQ: KEY-9, CLK-10, CLK-14

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// inProc is the kernel's owner calls made in process, as proc.Owner makes
// them over the socket.
type inProc struct {
	k  *kernel.Kernel
	at int64
}

func (p inProc) DeclReach() (kernel.DeclReach, error)  { return p.k.State().DeclReach(), nil }
func (p inProc) DeclareReach(d kernel.DeclReach) error { return p.k.DeclareReach(p.at, d) }

type passkey struct {
	pk   key.PublicKey
	pass key.Signer
}

func passkeyOf(seed byte) passkey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return passkey{key.Ed25519(p.Public().(ed25519.PublicKey)), key.Ed25519Signer(p)}
}

// bootKernel is a kernel whose anchors are the owner's two hardware keys.
func bootKernel(t *testing.T) (*kernel.Kernel, passkey, passkey) {
	t.Helper()
	owner, spare := passkeyOf(1), passkeyOf(12)
	pub, priv, _ := ed25519.GenerateKey(nil)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: pub, Sign: priv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, []key.PublicKey{owner.pk, spare.pk}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return k, owner, spare
}

// mailbank is the owner, a mailbox the mail clerk is rooted on, and a bank
// account; reset says whether the mailbox can reset the bank's password.
func mailbank(t *testing.T, reset bool) *Graph {
	t.Helper()
	owner := n("p.owner", Person, "Ana", nil)
	owner.Owner = true
	nodes := []Node{owner, n("a.mail", Account, "Mailbox", dom("provider:mail"), Data),
		n("a.bank", Account, "Bank", dom("provider:bank"), Money, Identity)}
	edges := []Edge{e(Act, "a.mail", "p.owner")}
	if reset {
		edges = append(edges, e(Reset, "a.bank", "a.mail"))
	}
	g, err := New(nodes, edges)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// KEY-9-reach-writer acceptance: a mailbox that resets a bank, written
// through the writer, makes a new `read` mail grant need the co-sign. A
// writer that drops the edge leaves the grant at rank 1, one tap.
func TestReachWriterMailboxResetMakesMailGrantNeedCosign(t *testing.T) {
	for _, reset := range []bool{false, true} {
		k, owner, spare := bootKernel(t)
		read := func(serial string) key.Key {
			return key.Issue(owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Read}, Serial: serial})
		}
		first := []key.Key{read("r0")} // a new verb: big, co-signed
		cos := []key.Cosign{key.Approve(owner.pass, kernel.BatchHash(first...)), key.Approve(spare.pass, kernel.BatchHash(first...))}
		if err := k.Issue(0, cos, first...); err != nil {
			t.Fatal(err)
		}
		live := kernel.GrantHold
		if err := k.Issue(live, nil, read("r1")); err != nil {
			t.Fatalf("a rank-1 read key with one tap before any declaration: %v", err)
		}
		if err := WriteReach(inProc{k, live}, mailbank(t, reset), map[string]string{"mail": "a.mail"}); err != nil {
			t.Fatal(err)
		}
		err := k.Issue(live, nil, read("r2"))
		if reset && !errors.Is(err, kernel.ErrNeedsCosign) {
			t.Fatalf("a read mail key over the mailbox's reset of the bank, one tap: %v, want %v", err, kernel.ErrNeedsCosign)
		}
		if !reset && err != nil {
			t.Fatalf("a read mail key with no edge to the bank, one tap: %v", err)
		}
		// Written again, the log already holds it all: nothing more is logged.
		logged := k.Log().Len()
		if err := WriteReach(inProc{k, live}, mailbank(t, reset), map[string]string{"mail": "a.mail"}); err != nil || k.Log().Len() != logged {
			t.Fatalf("a second write of the same graph: %v, log %d, want %d", err, k.Log().Len(), logged)
		}
	}
}

// The writer sends only additions: an edge it gains later goes as one
// entry naming only that edge, and the log then prices as the whole graph.
func TestReachWriterSendsOnlyAdditions(t *testing.T) {
	k, _, _ := bootKernel(t)
	clerks := map[string]string{"mail": "a.mail"}
	for _, reset := range []bool{false, true} {
		if err := WriteReach(inProc{k, 0}, mailbank(t, reset), clerks); err != nil {
			t.Fatal(err)
		}
	}
	es := k.Log().Entries()
	var bodies []kernel.DeclReach
	for _, e := range es {
		if e.Type == kernel.TDeclReach {
			bodies = append(bodies, decode(t, e.Body))
		}
	}
	want := kernel.DeclReach{Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"a.mail"}, To: "a.bank"}}}
	if len(bodies) != 2 || !reflect.DeepEqual(bodies[1], want) {
		t.Fatalf("decl.reach entries %+v, want the second to be %+v", bodies, want)
	}
	all, _ := mailbank(t, true).Decl(clerks)
	if add, held := Additions(k.State().DeclReach(), all); len(add.Nodes)+len(add.Edges)+len(held) != 0 {
		t.Fatalf("the log lacks %+v of the graph", add)
	}
}

// CLK-14: classes map one to one; a device is safety only when marked so.
func TestDeclMapsClassesAndControlEdges(t *testing.T) {
	owner := n("p.owner", Person, "Ana", nil)
	owner.Owner = true
	g, err := New([]Node{owner, n("d.hub", Device, "Hub", nil), n("d.lamp", Device, "Lamp", nil), n("d.lock", Device, "Lock", nil, Safety),
		n("a.bank", Account, "Bank", nil, Money, Identity, Data)},
		[]Edge{e(Act, "d.hub", "p.owner"), e(Act, "d.lamp", "d.hub"), e(Act, "d.lock", "d.hub"), e(Cutoff, "d.lamp", "d.hub"),
			e(Copy, "a.bank", "d.hub"), e(Watch, "d.lock", "d.lamp")})
	if err != nil {
		t.Fatal(err)
	}
	d, err := g.Decl(map[string]string{"home": "d.hub"})
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string][]key.Asset{}
	for _, nd := range d.Nodes {
		classes[nd.ID] = nd.Classes
		if (nd.Clerk != "") != (nd.ID == "d.hub") || nd.ID == "d.hub" && nd.Clerk != "home" {
			t.Fatalf("node %s roots clerk %q", nd.ID, nd.Clerk)
		}
	}
	if len(classes["d.lamp"]) != 0 || !slices.Equal(classes["d.lock"], []key.Asset{key.AssetSafety}) ||
		!slices.Equal(classes["a.bank"], []key.Asset{key.AssetMoney, key.AssetIdentity, key.AssetData}) {
		t.Fatalf("classes %v", classes)
	}
	var kinds []string
	for _, ed := range d.Edges {
		kinds = append(kinds, ed.Kind)
	}
	if !slices.Equal(kinds, []string{"act", "act", "act", "copy"}) {
		t.Fatalf("edge kinds %v, want only the control edges", kinds)
	}
	if _, err := g.Decl(map[string]string{"home": "d.gone"}); err == nil {
		t.Fatal("a clerk rooted on a node the graph lacks maps")
	}
	if _, err := g.Decl(map[string]string{"": "d.hub"}); err == nil {
		t.Fatal("an unnamed clerk maps")
	}
	// Two clerks on one node: a node roots one clerk, so the kernel would
	// bind only one and the other's keys would price on direct reach.
	for range 20 {
		if _, err := mailbank(t, true).Decl(map[string]string{"mail": "a.mail", "cal": "a.mail"}); err == nil {
			t.Fatal("two clerks rooted on one node map")
		}
	}
}

// A binding the log holds is kept: the writer never sends a clerk moved to
// another node, a node rebound to another clerk or a first declaration of a
// node an earlier edge named, which the kernel would refuse whole along with
// every other addition; it names each one it holds back.
func TestAdditionsKeepTheLogsBindings(t *testing.T) {
	have := kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "mail", Classes: []key.Asset{key.AssetData}}, {ID: "bank"}},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox", "bank"}, To: "bank"}, {Kind: "act", From: []string{"mbox"}, To: "shop"}},
	}
	want := kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "cal", Classes: []key.Asset{key.AssetData, key.AssetMoney, key.AssetMoney}},
			{ID: "bank", Clerk: "bank"}, {ID: "new", Clerk: "mail"}, {ID: "shop", Classes: []key.Asset{key.AssetData}}},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"bank", "mbox"}, To: "bank"}, {Kind: "act", From: []string{"new"}, To: "bank"},
			{Kind: "act", From: []string{"new"}, To: "bank"}},
	}
	got, held := Additions(have, want)
	exp := kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Classes: []key.Asset{key.AssetMoney}}, {ID: "bank", Clerk: "bank"}, {ID: "new"}},
		Edges: []kernel.ReachEdge{{Kind: "act", From: []string{"new"}, To: "bank"}},
	}
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("additions %+v, want %+v", got, exp)
	}
	if want := []string{`node "mbox" keeps clerk "mail", not "cal"`, `clerk "mail" stays on node "mbox", not "new"`, `node "shop" stays undeclared: an earlier edge named it`}; !slices.Equal(held, want) {
		t.Fatalf("held %q, want %q", held, want)
	}
	k, _, _ := bootKernel(t)
	if err := k.DeclareReach(0, have); err != nil {
		t.Fatal(err)
	}
	if err := k.DeclareReach(0, got); err != nil {
		t.Fatalf("the kernel refuses the writer's additions: %v", err)
	}
}

// A write that holds a binding back still sends the rest, then says what it
// held, so the caller can alert on a clerk priced on a stale root.
func TestWriteReachSaysWhatItHeld(t *testing.T) {
	k, _, _ := bootKernel(t)
	if err := WriteReach(inProc{k, 0}, mailbank(t, false), map[string]string{"mail": "a.mail"}); err != nil {
		t.Fatal(err)
	}
	err := WriteReach(inProc{k, 0}, mailbank(t, true), map[string]string{"mail": "a.bank"})
	if !errors.Is(err, ErrHeld) || !strings.Contains(err.Error(), `clerk "mail" stays on node "a.mail", not "a.bank"`) {
		t.Fatalf("a moved clerk: %v, want %v naming it", err, ErrHeld)
	}
	reset := kernel.ReachEdge{Kind: "reset", From: []string{"a.mail"}, To: "a.bank"}
	if got := k.State().DeclReach().Edges; !slices.ContainsFunc(got, func(e kernel.ReachEdge) bool { return reflect.DeepEqual(e, reset) }) {
		t.Fatalf("the reset edge was not sent with the held move: edges %+v", got)
	}
}

func decode(t *testing.T, b []byte) kernel.DeclReach {
	t.Helper()
	var d kernel.DeclReach
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}
