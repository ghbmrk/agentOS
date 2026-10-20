package slice

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
	During      string       `json:"during"`
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
	plannerPub, _ := pair(4)

	verbs := []key.Verb{key.Organize, key.Trash, key.Unsubscribe}
	taps := []string{"approve-key"}
	if in.Standing != nil {
		verbs, taps = verbs[:0], []string{}
		for _, v := range in.Standing.Verbs {
			verbs = append(verbs, key.Verb(v))
		}
	}
	view := KeyView{Verbs: sortedVerbs(verbs), Account: in.Owner}
	approved := &view
	if in.Standing != nil {
		approved = nil
	}

	acct := inbox.NewAccount(ownerPub, in.World, in.Mails, in.RetentionDays, in.OneClickBody)
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
	k, err := kernel.Boot(log, ownerPub, map[string]kernel.Clerk{inbox.Name: acct}, issued)
	if err != nil {
		return Outcome{}, err
	}
	root := key.Issue(ownerPriv, key.Root{Holder: holderPub, Clerk: inbox.Name, Verbs: verbs, Serial: "inbox-1"})
	if err := k.Issue(issued, root); err != nil {
		return Outcome{}, err
	}
	if err := log.Anchor(); err != nil {
		return Outcome{}, err
	}
	// The hold is a caveat on the key handed to the planner, not a property of
	// the clerk: the planner cannot lift it.
	planner, err := key.Derive(root, holderPriv, plannerPub, key.LimitHold(baseHoldMS, noveltyMS))
	if err != nil {
		return Outcome{}, err
	}

	// Earlier unsubscribes: replayed as done, so their senders are no longer novel.
	prior := append([]inbox.Delivery(nil), in.Prior...)
	sort.Slice(prior, func(i, j int) bool { return prior[i].Date < prior[j].Date })
	seeded := map[string]bool{}
	for _, d := range prior {
		h := inbox.Handle(d.From)
		t, _ := ms(d.Date)
		id := "seed-" + h
		if seeded[h] {
			continue
		}
		seeded[h] = true
		acct.Preload(kernel.Idem(id, 0))
		step := kernel.Normalize(id, key.Step{Verb: key.Unsubscribe, Clerk: inbox.Name,
			Args: map[string]key.Arg{"to": {Value: h}}})
		if err := k.Submit(t, kernel.Plan{ID: id, Key: planner, Steps: []key.Step{step}}); err != nil {
			return Outcome{}, err
		}
		for _, at := range []int64{t, t + noveltyMS} {
			if err := k.Tick(at); err != nil {
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
	for _, p := range inbox.Plans(listing, planner) {
		if err := k.Submit(t0, p); err != nil {
			return Outcome{}, err
		}
	}
	if err := k.Tick(t0); err != nil {
		return Outcome{}, err
	}

	handleOf := map[string]string{}
	for _, it := range listing {
		if it.Sender != "" {
			handleOf[it.Mail] = it.Sender
		}
	}
	var refused []inbox.Refusal
	for i, s := range in.Script {
		switch {
		case s.Owner == "STOP":
			if h, ok := handleOf[s.Mail]; ok {
				if err := k.Cancel(t0+1000, "unsub-"+h); err != nil {
					return Outcome{}, err
				}
			}
		case s.PlannerStep != nil:
			rf, err := plannerStep(k, acct, planner, fmt.Sprintf("script-%d", i), *s.PlannerStep, s.Forced, t0)
			if err != nil {
				return Outcome{}, err
			}
			refused = append(refused, rf...)
		}
	}
	for _, at := range []int64{t0 + baseHoldMS, t0 + noveltyMS} {
		if err := k.Tick(at); err != nil {
			return Outcome{}, err
		}
	}

	out := Outcome{Requests: acct.Posts(), Effects: acct.Effects(), Refusals: append(acct.Refusals(), refused...),
		StatusLines: []StatusLine{}, Holds: holds(k, acct, planner, ownerPub), OwnerTaps: taps,
		KeysAtApproval: approved, KeysAtEnd: view, OutsideMailClerk: outside(in.Mails, listing)}
	for _, r := range out.Refusals {
		if r.Reason == statusCause {
			out.StatusLines = []StatusLine{{Cause: statusCause, Text: statusText}}
			break
		}
	}
	h := log.Entries()[len(log.Entries())-1].Hash()
	out.LogDigest = hex.EncodeToString(h[:])
	return out, nil
}

// plannerStep delivers a step the planner was never given a key for. Unforced
// it goes through the kernel; forced it goes straight to the clerk. Either
// way something refuses it.
func plannerStep(k *kernel.Kernel, acct *inbox.Account, planner key.Key, id string, ps PlannerStep, forced bool, now int64) ([]inbox.Refusal, error) {
	args := map[string]key.Arg{}
	var mail *string
	if ps.Mail != "" {
		args["target"] = key.Arg{Value: ps.Mail}
		mail = &ps.Mail
	}
	step := kernel.Normalize(id, key.Step{Verb: key.Verb(ps.Op), Clerk: inbox.Name, Args: args})
	if forced {
		before := len(acct.Refusals())
		acct.Do(kernel.Request{Plan: id, Step: step, Key: planner, Idem: kernel.Idem(id, 0), Now: now}, k.State())
		return acct.Refusals()[before:], nil
	}
	if err := k.Submit(now, kernel.Plan{ID: id, Key: planner, Steps: []key.Step{step}}); err != nil {
		return nil, err
	}
	p := k.State().Plans[id]
	if p == nil || p.Status != kernel.SRejected {
		return nil, fmt.Errorf("step %s was not rejected by the kernel", ps.Op)
	}
	reason := rejectionCode(k, id)
	if reason == kernel.CPlan || reason == key.RVerb {
		reason = "outside-key"
	}
	return []inbox.Refusal{{Op: ps.Op, Mail: mail, At: "kernel", Reason: reason}}, nil
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
func holds(k *kernel.Kernel, acct *inbox.Account, planner key.Key, owner ed25519.PublicKey) []Hold {
	ver, err := key.Verify(planner, owner)
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
		if json.Unmarshal(e.Body, &b) != nil || !strings.HasPrefix(b.Plan, "unsub-") {
			continue
		}
		w := "base"
		if b.Novel {
			w = "novelty"
		}
		out = append(out, Hold{Mail: acct.Origin(strings.TrimPrefix(b.Plan, "unsub-")), Window: w,
			Seconds: ver.Limits.Window(b.Novel) / 1000,
			Stopped: k.State().Plans[b.Plan].Status == kernel.SCancelled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mail < out[j].Mail })
	return out
}

// outside lists what left the clerk toward the planner: ids, classes and handles.
func outside(mails []inbox.Mail, listing []inbox.Item) []string {
	out := []string{}
	for _, it := range listing {
		out = append(out, it.Mail+":"+it.Class)
		if it.Sender != "" {
			out = append(out, it.Sender)
		}
	}
	return out
}

func sortedVerbs(vs []key.Verb) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, string(v))
	}
	sort.Strings(out)
	return out
}
