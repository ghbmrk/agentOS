package graph

import (
	"testing"
	"time"
)

// Fixture households, built by hand. IDs carry a dot so a test can check
// that no owner text names one; names are what the owner calls things.
// Every node and edge here is synthetic.

var fixtureNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func n(id string, k Kind, name string, doms []string, assets ...Class) Node {
	return Node{ID: id, Kind: k, Name: name, Domains: doms, Assets: assets, Source: Shipped}
}

func e(k EdgeKind, to string, from ...string) Edge {
	return Edge{Kind: k, From: from, To: to, Source: Shipped}
}

func dom(ds ...string) []string { return ds }

// household builds Ana (two keys of one maker, a lock behind an enforcer)
// or Ben (one key, no enforcer, the lock reached by the box alone).
func household(t *testing.T, ana bool) *Graph {
	t.Helper()
	phone := "phone:ana"
	owner := "Ana"
	if !ana {
		phone, owner = "phone:ben", "Ben"
	}
	owner_ := n("p.owner", Person, owner, nil)
	owner_.Owner = true
	payee := n("b.payee", BrakeKind, "New-payee hold", nil)
	payee.Set = true
	payee.Page = "Bank app, Security, New payee hold"
	card := n("b.card", BrakeKind, "Card limit", nil)
	card.Page = "Bank app, Cards, Limits"
	mail := n("a.mail", Account, "Mailbox", dom("provider:google"), Data)
	mail.LastUse = fixtureNow.Add(-24 * time.Hour)
	oldmail := n("a.oldmail", Account, "Old email", dom("provider:yahoo"))
	oldmail.LastUse = fixtureNow.AddDate(-3, 0, 0)
	blog := n("a.blog", Account, "Old blog", nil, Data)
	blog.LastUse = fixtureNow.AddDate(0, -18, 0)
	phoneN := n("d.phone", Device, owner+"'s phone", dom(phone))
	phoneN.LastUse = fixtureNow.AddDate(-5, 0, 0) // a device, never listed as idle

	nodes := []Node{
		owner_,
		n("k.one", Key, "Key 1", dom("maker:yubico")),
		phoneN,
		n("v.google", Provider, "Google", dom("provider:google")),
		mail,
		n("a.carrier", Account, "Phone number", dom("provider:carrier")),
		n("c.codes", Credential, "Registrar recovery codes", nil),
		n("a.bank", Account, "Bank", nil, Money, Data),
		n("a.registrar", Account, "Domain registrar", nil, Identity),
		n("d.car", Device, "Car", nil, Safety),
		n("d.lock", Device, "Front door lock", nil, Safety),
		n("n.core", NodeKind, "Box", dom("node:core")),
		payee, card,
		n("v.power", Power, "Home power", nil),
		n("v.uplink", Uplink, "Home internet", nil),
		oldmail, blog,
		n("p.sis", Person, "Sister", nil), // a recovery contact: not the owner, so she can fail
	}
	edges := []Edge{
		e(Act, "k.one", "p.owner"),
		e(Act, "d.phone", "p.owner"),
		e(Act, "n.core", "p.owner"),
		e(Act, "a.mail", "k.one"),
		e(Reset, "a.bank", "a.mail"),
		e(Reset, "a.carrier", "a.mail"),
		e(Reset, "a.carrier", "p.sis"),
		e(Act, "a.bank", "d.phone"),
		e(Reset, "a.registrar", "a.mail", "a.carrier"),
		e(Copy, "c.codes", "a.mail"),
		e(Reset, "a.registrar", "c.codes"),
		e(Act, "d.car", "d.phone"),
		e(Brake, "a.bank", "b.payee"),
		e(Brake, "a.bank", "b.card"),
		e(Watch, "b.payee", "a.mail"),
		e(Reset, "a.blog", "a.oldmail"),
		e(Cutoff, "a.mail", "v.google"),
		e(Cutoff, "v.uplink", "v.power"),
		e(Cutoff, "a.mail", "v.uplink"),
		e(Cutoff, "a.bank", "a.mail"),
		e(Cutoff, "n.core", "v.power"),
	}
	if ana {
		nodes = append(nodes,
			n("k.two", Key, "Key 2", dom("maker:yubico")),
			n("n.door", NodeKind, "Door controller", dom("node:home")))
		edges = append(edges,
			e(Act, "k.two", "p.owner"),
			e(Act, "n.door", "p.owner"),
			e(Act, "a.mail", "k.two"),
			Edge{Kind: Act, From: []string{"k.one", "k.two"}, To: "a.registrar", Source: Answer},
			e(Act, "d.lock", "n.core", "n.door"),
			e(Cutoff, "n.door", "v.power"))
	} else {
		edges = append(edges,
			Edge{Kind: Act, From: []string{"k.one"}, To: "a.registrar", Source: Answer},
			e(Act, "d.lock", "n.core"))
	}
	g, err := New(nodes, edges)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// Hand-worked cut sets. Ana: the keys (one maker) and Google each reach the
// mailbox, which resets the bank, the carrier and, with the copied codes,
// the registrar; the bank's new-payee hold is watched from the mailbox, so
// the phone alone compromises the bank but takes only its data; the
// registrar's reset needs the mailbox AND the carrier, so the carrier alone
// takes nothing; the old email takes the old blog; the lock needs the box
// AND the door controller. Ben: the same, but the lock falls to the box.
// The sister can reset the carrier, so her own failure takes the carrier,
// but the registrar still needs the mailbox too, which falls alone anyway.
// Every unlabelled node also fails on its own (its "self:" domain): the
// bank alone loses its data but its money stays held by the watched hold,
// and the registrar, the codes, the car, the lock and the blog each fall
// alone.
var anaCuts = map[Class][]Cut{
	Money: {{"a.bank", dom("maker:yubico")}, {"a.bank", dom("provider:google")}},
	Identity: {
		{"a.registrar", dom("maker:yubico")}, {"a.registrar", dom("provider:google")},
		{"a.registrar", dom("self:a.registrar")}, {"a.registrar", dom("self:c.codes")},
	},
	Data: {
		{"a.bank", dom("maker:yubico")}, {"a.bank", dom("phone:ana")}, {"a.bank", dom("provider:google")}, {"a.bank", dom("self:a.bank")},
		{"a.blog", dom("provider:yahoo")}, {"a.blog", dom("self:a.blog")},
		{"a.mail", dom("maker:yubico")}, {"a.mail", dom("provider:google")},
	},
	Safety: {
		{"d.car", dom("phone:ana")}, {"d.car", dom("self:d.car")},
		{"d.lock", dom("self:d.lock")}, {"d.lock", dom("node:core", "node:home")},
	},
}

func benCuts() map[Class][]Cut {
	return map[Class][]Cut{
		Money:    anaCuts[Money],
		Identity: anaCuts[Identity],
		Data: {
			{"a.bank", dom("maker:yubico")}, {"a.bank", dom("phone:ben")}, {"a.bank", dom("provider:google")}, {"a.bank", dom("self:a.bank")},
			{"a.blog", dom("provider:yahoo")}, {"a.blog", dom("self:a.blog")},
			{"a.mail", dom("maker:yubico")}, {"a.mail", dom("provider:google")},
		},
		Safety: {
			{"d.car", dom("phone:ben")}, {"d.car", dom("self:d.car")},
			{"d.lock", dom("node:core")}, {"d.lock", dom("self:d.lock")},
		},
	}
}

// Hand-worked cut-offs. Google and the uplink each cut the mailbox, and the
// mailbox's loss cuts the bank; power cuts the uplink (so the mailbox and
// the bank) and the box and door controller (so the lock). The registrar
// stays reached through the keys, the car through the phone. The old blog
// is never reached.
var anaCutOffs = map[Class][]CutOff{
	Money:    {{"a.bank", []string{"v.google", "v.power", "v.uplink"}}},
	Identity: nil,
	Data: {
		{"a.bank", []string{"v.google", "v.power", "v.uplink"}},
		{"a.mail", []string{"v.google", "v.power", "v.uplink"}},
	},
	Safety: {{"d.lock", []string{"v.power"}}},
}

var anaUnreached = map[Class][]string{Data: {"a.blog"}}

var anaBoard = Board{
	Money:    {ThiefNeed: 1, CutOff: 3, Assets: 1},
	Identity: {ThiefNeed: 1, CutOff: 0, Assets: 1},
	Safety:   {ThiefNeed: 1, CutOff: 1, Assets: 2},
	Data:     {ThiefNeed: 1, CutOff: 3, Assets: 3},
}

// Ben's cut-offs and board are Ana's: the lock is lost to power through the
// box alone instead of the box and the door controller.
var benCutOffs, benBoard = anaCutOffs, anaBoard

// Candidate proposals against Ana. Taking the bank's reset off the mailbox
// lifts money to 2; a watcher outside the household lifts it to 2 as well,
// and both together to 3. The car key removes one of the car's two single
// cuts: no class gain, but a step. The card limit has no watcher, so it
// changes nothing.
var (
	bankReset = Proposal{
		Text: "Stop the mailbox from resetting the bank", Minutes: 10, Structural: true,
		DropEdges: []Edge{e(Reset, "a.bank", "a.mail")},
	}
	carKey = Proposal{
		Text: "Make the car need Key 1 as well as the phone", Minutes: 10, Structural: true,
		DropEdges: []Edge{e(Act, "d.car", "d.phone")},
		AddEdges:  []Edge{e(Act, "d.car", "d.phone", "k.one")},
	}
	witness = Proposal{
		Text: "Let a friend's phone watch the new-payee hold", Minutes: 1,
		AddNodes: []Node{n("n.friend", NodeKind, "Friend's phone", dom("phone:friend"))},
		AddEdges: []Edge{e(Watch, "b.payee", "n.friend")},
	}
	both = Proposal{
		Text: "Add a watcher and stop mailbox resets of the bank", Minutes: 5,
		AddNodes:  witness.AddNodes,
		AddEdges:  witness.AddEdges,
		DropEdges: bankReset.DropEdges,
	}
	cardLimit = Proposal{Text: "Turn on the card limit", Minutes: 2, SetBrakes: []string{"b.card"}}
)
