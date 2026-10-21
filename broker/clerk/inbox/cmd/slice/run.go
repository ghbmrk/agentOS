package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const (
	dayMS       = int64(86_400_000)
	baseHoldMS  = int64(600_000)
	noveltyMS   = dayMS
	startOfRun  = "2026-10-19T09:00:00Z"
	statusCause = "trash-not-restorable"
	statusText  = "Spam was not deleted: this account empties its trash too soon for a delete to be undone."
)

// Input is one run of the slice: the world, the mailbox as the fake reader
// returns it, the owner and the script of what happens during the run.
type Input struct {
	World         inbox.World      `json:"world"`
	Mails         []inbox.Mail     `json:"mails"`
	Owner         string           `json:"owner"`
	OneClickBody  string           `json:"one_click_body"`
	RetentionDays int              `json:"trash_retention_days"`
	Prior         []inbox.Delivery `json:"prior_unsubscribes"`
	Script        []Scripted       `json:"script"`
	Standing      *KeyView         `json:"standing"`
}

// Scripted is one thing that happens during the run: the owner stops a hold,
// or the planner issues a step it was not given a key for.
type Scripted struct {
	Owner       string       `json:"owner"`
	Mail        string       `json:"mail"`
	PlannerStep *PlannerStep `json:"planner_step"`
	Forced      bool         `json:"forced"`
}

type PlannerStep struct {
	Op   string `json:"op"`
	Mail string `json:"mail"`
}

// KeyView is a key as the owner sees it.
type KeyView struct {
	Verbs   []string `json:"verbs"`
	Account string   `json:"account"`
}

type Hold struct {
	Mail    string `json:"mail"`
	Window  string `json:"window"`
	Seconds int64  `json:"seconds"`
	Stopped bool   `json:"stopped"`
}

type StatusLine struct {
	Cause string `json:"cause"`
	Text  string `json:"text"`
}

// Outcome is everything observable about a run. LogDigest is the hash of the
// last log entry, so a replay that differs anywhere differs here.
type Outcome struct {
	Requests         []inbox.Post    `json:"requests"`
	Effects          []inbox.Effect  `json:"effects"`
	Refusals         []inbox.Refusal `json:"refusals"`
	StatusLines      []StatusLine    `json:"status_lines"`
	Holds            []Hold          `json:"holds"`
	OwnerTaps        []string        `json:"owner_taps"`
	KeysAtApproval   *KeyView        `json:"keys_at_approval"`
	KeysAtEnd        KeyView         `json:"keys_at_end"`
	OutsideMailClerk []string        `json:"outside_mail_clerk"`
	LogDigest        string          `json:"log_digest"`
}

// handleSecret keys the sender handles. Fixed here so a run replays to the same
// log; a real account draws its own and keeps it with the clerk (ASSUMPTIONS.md).
var handleSecret = []byte("agentos-slice-inbox-handles-v1")

func pair(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

func ms(date string) (int64, error) {
	t, err := time.Parse("2006-01-02", date)
	return t.UnixMilli(), err
}

// Run performs the slice once on a fresh kernel. Keys and the clock are fixed,
// so the same input gives the same log (ASSUMPTIONS.md).
func Run(in Input) (Outcome, error) {
	ownerPub, ownerPriv := pair(1)
	holderPub, holderPriv := pair(2)
	headPub, headPriv := pair(3)
	plannerPub, plannerPriv := pair(4)
	sparePub, sparePriv := pair(5) // the owner's second hardware key
	anchors := []ed25519.PublicKey{ownerPub, sparePub}

	verbs := []key.Verb{key.Organize, key.Trash, key.Unsubscribe}
	if in.Standing != nil {
		verbs = verbs[:0]
		for _, v := range in.Standing.Verbs {
			verbs = append(verbs, key.Verb(v))
		}
	}
	standing := in.Standing != nil

	acct, err := inbox.NewAccount(anchors, handleSecret, func() inbox.World { return in.World }, in.Mails,
		in.RetentionDays, in.OneClickBody)
	if err != nil {
		return Outcome{}, err
	}
	today, err := ms(in.World.Today)
	if err != nil {
		return Outcome{}, err
	}
	issued := today
	for _, d := range in.Prior {
		t, err := ms(d.Date)
		if err != nil {
			return Outcome{}, err
		}
		issued = min(issued, t)
	}
	issued -= dayMS

	store, anchor := &kernel.MemStore{}, &kernel.MemAnchor{}
	log, err := kernel.Open(kernel.Config{Store: store, Anchor: anchor, Pub: headPub, Sign: headPriv,
		Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		return Outcome{}, err
	}
	k, err := kernel.Boot(log, anchors, map[string]kernel.Clerk{inbox.Name: acct}, issued)
	if err != nil {
		return Outcome{}, err
	}
	acct.Bind(k.State())
	// The clerk's own clock runs on the run's time, which each tick sets.
	clock := issued
	acct.Clock = func() int64 { return clock }
	tick := func(at int64) error { clock = at; return k.Tick(at) }
	// The owner's passkey granted the root and the home clerk's key to it at
	// setup, a hold before the run, and the second hardware key co-signed the
	// batch, since it is new power (D-146). The clerk key outlives the run and
	// spends nothing.
	root := key.Issue(ownerPriv, key.Root{Clerk: inbox.Name, Verbs: verbs, Serial: "inbox-1"})
	ck, err := key.ClerkKey(root, ownerPriv, holderPub, today, 0)
	if err != nil {
		return Outcome{}, err
	}
	if err := k.Issue(issued-kernel.GrantHold, []key.Cosign{key.Approve(sparePriv, kernel.BatchHash(root, ck))}, root, ck); err != nil {
		return Outcome{}, err
	}
	if err := log.Anchor(); err != nil {
		return Outcome{}, err
	}
	var approved *KeyView
	if !standing {
		v, err := keyView(ck, holderPriv, ownerPub, in.Owner)
		if err != nil {
			return Outcome{}, err
		}
		approved = &v
	}
	// The hold and the daily cap are caveats on the keys handed to the planner,
	// not properties of the planner: it cannot lift them (inbox.PlannerKeys).
	bulk, unsub, err := inbox.PlannerKeys(ck, holderPriv, plannerPub, baseHoldMS, noveltyMS)
	if err != nil {
		return Outcome{}, err
	}

	// Earlier unsubscribes: replayed as done, so their senders are no longer novel.
	prior := append([]inbox.Delivery(nil), in.Prior...)
	sort.Slice(prior, func(i, j int) bool { return prior[i].Date < prior[j].Date })
	seeded := map[string]bool{}
	seedPlans := map[string]bool{}
	for _, d := range prior {
		h := acct.Handle(d.From)
		t, _ := ms(d.Date)
		id := "seed-" + h
		if seeded[h] {
			continue
		}
		seeded[h] = true
		seedPlans[id] = true
		acct.Preload(kernel.Idem(id, 0))
		step := kernel.PlanStep{Verb: key.Unsubscribe, Clerk: inbox.Name, Args: map[string]string{"to": h}}
		if err := k.Submit(t, kernel.SignPlan(kernel.Plan{ID: id, Key: unsub, Steps: []kernel.PlanStep{step}}, plannerPriv)); err != nil {
			return Outcome{}, err
		}
		for _, at := range []int64{t, t + noveltyMS} {
			if err := tick(at); err != nil {
				return Outcome{}, err
			}
		}
	}

	now0, err := time.Parse(time.RFC3339, startOfRun)
	if err != nil {
		return Outcome{}, err
	}
	t0 := now0.UnixMilli()
	listing := acct.Listing()
	plans, left := inbox.Plans(listing, bulk, unsub, plannerPriv)
	for _, p := range plans {
		if err := k.Submit(t0, p); err != nil {
			return Outcome{}, err
		}
	}
	if err := tick(t0); err != nil {
		return Outcome{}, err
	}

	handleOf := map[string]string{}
	for _, it := range listing {
		if it.Sender != "" {
			handleOf[it.Mail] = it.Sender
		}
	}
	var kernelRefusals []inbox.Refusal
	for i, s := range in.Script {
		switch {
		case s.Owner == "STOP":
			if h, ok := handleOf[s.Mail]; ok {
				if err := k.Cancel(t0+1000, "unsub-"+h); err != nil {
					return Outcome{}, err
				}
			}
		case s.PlannerStep != nil:
			rf, err := plannerStep(k, acct, bulk, plannerPriv, fmt.Sprintf("script-%d", i), *s.PlannerStep, s.Forced, t0)
			if err != nil {
				return Outcome{}, err
			}
			kernelRefusals = append(kernelRefusals, rf...)
		}
	}
	for _, at := range []int64{t0 + baseHoldMS, t0 + noveltyMS} {
		if err := tick(at); err != nil {
			return Outcome{}, err
		}
	}

	end, err := keyView(ck, holderPriv, ownerPub, in.Owner)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Requests: acct.Posts(), Effects: acct.Effects(), Refusals: append(acct.Refusals(), kernelRefusals...),
		StatusLines: []StatusLine{}, Holds: holds(k, acct, unsub, plannerPriv, ownerPub, seedPlans), OwnerTaps: ownerTaps(k, standing),
		KeysAtApproval: approved, KeysAtEnd: end, OutsideMailClerk: outside(listing)}
	for _, r := range out.Refusals {
		if r.Reason == statusCause {
			out.StatusLines = []StatusLine{{Cause: statusCause, Text: statusText}}
			break
		}
	}
	if line, ok := capLine(left); ok {
		out.StatusLines = append(out.StatusLines, line)
	}
	h := log.Entries()[len(log.Entries())-1].Hash()
	out.LogDigest = hex.EncodeToString(h[:])
	return out, nil
}

// plannerStep delivers a step the planner was never given a key for. Unforced
// it goes through the kernel, which refuses it and returns that refusal; forced
// it goes straight to the clerk, which refuses and records it itself.
func plannerStep(k *kernel.Kernel, acct *inbox.Account, planner key.Key, holder ed25519.PrivateKey, id string, ps PlannerStep, forced bool, now int64) ([]inbox.Refusal, error) {
	args := map[string]string{}
	var mail *string
	if ps.Mail != "" {
		args["target"] = ps.Mail
		mail = &ps.Mail
	}
	step := kernel.PlanStep{Verb: key.Verb(ps.Op), Clerk: inbox.Name, Args: args}
	if forced {
		p := kernel.SignPlan(kernel.Plan{ID: id, Key: planner, Steps: []kernel.PlanStep{step}}, holder)
		acct.Do(kernel.Request{Plan: p}, k.State())
		return nil, nil
	}
	if err := k.Submit(now, kernel.SignPlan(kernel.Plan{ID: id, Key: planner, Steps: []kernel.PlanStep{step}}, holder)); err != nil {
		return nil, err
	}
	p := k.State().Plans[id]
	if p == nil || p.Status != kernel.SRejected {
		return nil, fmt.Errorf("step %s was not rejected by the kernel", ps.Op)
	}
	return []inbox.Refusal{{Op: ps.Op, Mail: mail, At: "kernel", Reason: inbox.Reason(rejectionCode(k, id))}}, nil
}

// keyView is what the key lets its holder do, read from the key itself; the
// holder signs, as any use of a key must.
func keyView(k key.Key, holder ed25519.PrivateKey, owner ed25519.PublicKey, account string) (KeyView, error) {
	v, err := key.Verify(k, []ed25519.PublicKey{owner}, nil, key.Sign(k, holder, nil))
	if err != nil {
		return KeyView{}, err
	}
	vs := append([]string(nil), v.Limits.Verbs...)
	sort.Strings(vs)
	return KeyView{Verbs: vs, Account: account}, nil
}

// ownerTaps lists the owner approvals the log holds: every entry that widens
// what may happen. A standing key was approved before this run and is not a tap.
func ownerTaps(k *kernel.Kernel, standing bool) []string {
	taps := []string{}
	for _, e := range k.Log().Entries() {
		if kernel.Widening(e.Type) {
			taps = append(taps, "approve-key")
		}
	}
	if standing && len(taps) > 0 {
		taps = taps[1:]
	}
	return taps
}

func rejectionCode(k *kernel.Kernel, plan string) string {
	for _, e := range k.Log().Entries() {
		if e.Type != kernel.TPlanRejected {
			continue
		}
		var b struct{ Plan, Code string }
		if json.Unmarshal(e.Body, &b) == nil && b.Plan == plan {
			return b.Code
		}
	}
	return ""
}

// holds reports the hold each unsubscribe step waited behind, read from the log.
func holds(k *kernel.Kernel, acct *inbox.Account, unsub key.Key, planner ed25519.PrivateKey, owner ed25519.PublicKey, seeds map[string]bool) []Hold {
	ver, err := key.Verify(unsub, []ed25519.PublicKey{owner}, nil, key.Sign(unsub, planner, nil))
	if err != nil {
		return []Hold{}
	}
	out := []Hold{}
	for _, e := range k.Log().Entries() {
		if e.Type != kernel.TStepHeld {
			continue
		}
		var b struct {
			Plan  string `json:"plan"`
			Novel bool   `json:"novel"`
		}
		if json.Unmarshal(e.Body, &b) != nil || seeds[b.Plan] {
			continue
		}
		p := k.State().Plans[b.Plan]
		if p == nil || len(p.Plan.Steps) != 1 || p.Plan.Steps[0].Verb != key.Unsubscribe {
			continue
		}
		w := "base"
		if b.Novel {
			w = "novelty"
		}
		out = append(out, Hold{Mail: acct.Origin(p.Plan.Steps[0].Args["to"]), Window: w,
			Seconds: ver.Limits.Window(b.Novel) / 1000,
			Stopped: p.Status == kernel.SCancelled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mail < out[j].Mail })
	return out
}

// outside lists what left the clerk toward the planner: ids, classes and handles.
func outside(listing []inbox.Item) []string {
	out := []string{}
	for _, it := range listing {
		out = append(out, it.Mail+":"+it.Class)
		if it.Sender != "" {
			out = append(out, it.Sender)
		}
	}
	return out
}

// capLine is the one STATUS line for work the daily cap put off, counted by
// action (VRB-2: asked once, as one batch).
func capLine(l inbox.Left) (StatusLine, bool) {
	var parts []string
	if l.Trash > 0 {
		parts = append(parts, fmt.Sprintf("%d to trash", l.Trash))
	}
	if l.Organize > 0 {
		parts = append(parts, fmt.Sprintf("%d to label", l.Organize))
	}
	if len(parts) == 0 {
		return StatusLine{}, false
	}
	return StatusLine{Cause: "daily-cap", Text: fmt.Sprintf("Over today's limit of %d: %s left for tomorrow.",
		inbox.DailyCap, strings.Join(parts, " and "))}, true
}
