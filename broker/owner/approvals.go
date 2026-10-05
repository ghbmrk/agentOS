package owner

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Bounds on what the channel holds (CH-2: nothing may grow until the
// channel stalls, STOP included).
const (
	// MaxOpen caps open requests plus queued auto-replies.
	MaxOpen = 50
	// MaxTTL caps how long any request stays open, so a restart record
	// can never carry an item forward for longer.
	MaxTTL = 24 * time.Hour
	// MaxExpired caps the digest list; older entries are counted, not kept.
	MaxExpired = 200
	// RetireFor keeps a closed ID from being reused, so a late reply
	// cannot land on a new request with the same ID (CH-18).
	RetireFor = 24 * time.Hour
	// LocalTTL is how long a request asked only on the Wi-Fi page stays
	// open by default: the owner has to reach the box's Wi-Fi first
	// (P2-2a, UX A1).
	LocalTTL = 4 * time.Hour
)

// ErrFull is returned when MaxOpen requests and replies are already open.
var ErrFull = errors.New("owner: too many open requests")

// ErrLocalOnly is returned for an item that cannot be approved by text
// because its recipients do not render in full (SMSApprovable).
var ErrLocalOnly = errors.New("owner: approvable only on the local page")

type request struct {
	id      string
	n       uint64 // opening order, for the local page
	local   bool   // asked on the local page only (P2-2a)
	items   []Item
	tier    Tier
	code    string // texted code, low tier only
	expires time.Time
	wrong   int
	done    []bool
}

// Request opens an approval request for items and texts it to the owner.
// ttl bounds how long it stays open (0: CodeTTL); a low-tier request never
// outlives CodeTTL, since its texted code expires then (CH-10).
func (c *Channel) Request(items []Item, ttl time.Duration) (string, error) {
	if c.cfg.Modem == nil {
		return "", errors.New("owner: no modem")
	}
	now := c.cfg.Now()
	c.mu.Lock()
	r, err := c.openLocked(items, ttl, now, false)
	if err != nil {
		c.mu.Unlock()
		return "", err
	}
	text := c.renderLocked(r)
	c.mu.Unlock()
	if err := c.cfg.Modem.Send(c.cfg.Owner, text); err != nil {
		c.dropOpen([]string{r.id}, now)
		return "", err
	}
	return r.id, nil
}

// RequestEach opens one single-item request per item, each with its own
// ID and code, and texts them together: as one text when they fit, else
// as few as fit (GR10 re-issue after a restart: one approval per intent,
// one text per batch). ttls[i] bounds item i's request as Request's ttl
// does. ids[i] is "" for an item that was not asked; err is the first
// failure.
func (c *Channel) RequestEach(items []Item, ttls []time.Duration) (ids []string, err error) {
	ids = make([]string, len(items))
	if len(ttls) != len(items) {
		return ids, errors.New("owner: one ttl per item")
	}
	if c.cfg.Modem == nil {
		return ids, errors.New("owner: no modem")
	}
	now := c.cfg.Now()
	type part struct {
		idx  []int
		text string
	}
	var parts []part
	c.mu.Lock()
	for i, it := range items {
		r, e := c.openLocked([]Item{it}, ttls[i], now, false)
		if e != nil {
			if err == nil {
				err = e
			}
			continue
		}
		ids[i] = r.id
		t := c.renderLocked(r)
		if n := len(parts); n > 0 && fits(parts[n-1].text+" "+t) {
			parts[n-1].text += " " + t
			parts[n-1].idx = append(parts[n-1].idx, i)
			continue
		}
		parts = append(parts, part{idx: []int{i}, text: t})
	}
	c.mu.Unlock()
	for _, p := range parts {
		if e := c.cfg.Modem.Send(c.cfg.Owner, p.text); e != nil {
			var drop []string
			for _, i := range p.idx {
				drop = append(drop, ids[i])
				ids[i] = ""
			}
			c.dropOpen(drop, now)
			if err == nil {
				err = e
			}
		}
	}
	return ids, err
}

// RequestLocal opens a request for an item that can be approved only on
// the local page (P2-2a, UX-144-2), its recipients not textable
// (ErrLocalOnly), and texts the owner a notice that names no recipient.
// It is always high tier and has no texted code: the page approves it
// with a code-generator code (LocalAnswer). NO works by text; YES by text
// is refused, since the owner never saw where it goes.
func (c *Channel) RequestLocal(it Item, ttl time.Duration) (string, error) {
	if c.cfg.Modem == nil {
		return "", errors.New("owner: no modem")
	}
	now := c.cfg.Now()
	c.mu.Lock()
	r, err := c.openLocked([]Item{it}, ttl, now, true)
	if err != nil {
		c.mu.Unlock()
		return "", err
	}
	text := c.renderLocked(r)
	c.mu.Unlock()
	if err := c.cfg.Modem.Send(c.cfg.Owner, text); err != nil {
		c.dropOpen([]string{r.id}, now)
		return "", err
	}
	return r.id, nil
}

// openLocked validates items and opens a request for them, recorded for a
// restart, without texting it. A local request skips the text check and
// is always high tier.
func (c *Channel) openLocked(items []Item, ttl time.Duration, now time.Time, local bool) (*request, error) {
	if len(items) == 0 || len(items) > 20 {
		return nil, errors.New("owner: a request has 1 to 20 items")
	}
	for _, it := range items {
		if !local && !SMSApprovable(it) {
			return nil, ErrLocalOnly
		}
	}
	if len(c.open)+len(c.queued) >= MaxOpen {
		return nil, ErrFull
	}
	tier := Low
	for _, it := range items {
		if Classify(it.Facts, c.cfg.Limits, now) == High {
			tier = High
		}
	}
	if c.codes.st.LowLocked || local {
		tier = High // texted codes are off (CH-18), or the page asks it
	}
	if ttl <= 0 {
		ttl = c.cfg.CodeTTL
		if local {
			ttl = LocalTTL
		}
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	if tier == Low && ttl > c.cfg.CodeTTL {
		ttl = c.cfg.CodeTTL
	}
	id, err := c.newIDLocked(now)
	if err != nil {
		return nil, err
	}
	c.reqN++
	r := &request{id: id, n: c.reqN, local: local, items: append([]Item(nil), items...), tier: tier,
		expires: now.Add(ttl), done: make([]bool, len(items))}
	if tier == Low {
		r.code = c.codes.textedCode()
	}
	asked := now
	if len(items) == 1 && !items[0].Asked.IsZero() {
		// A re-issued item keeps the time it was first asked, through any
		// number of restarts.
		asked = items[0].Asked
	}
	ref := PendingRef{ID: id, Refs: make([]string, len(items)), Asked: asked, Expires: r.expires, Sums: make([]string, len(items))}
	for i, it := range items {
		ref.Refs[i], ref.Sums[i] = it.Ref, ItemSum(it)
	}
	if err := c.codes.commit(func(s *State) { s.Pending = append(s.Pending, ref) }); err != nil {
		return nil, err
	}
	c.open[id] = r
	return r, nil
}

// dropOpen closes requests whose text was never sent.
func (c *Channel) dropOpen(ids []string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		delete(c.open, id)
		c.retireLocked(id, now)
	}
}

// renderLocked is the approval text (CH-12): fixed wording from verified
// fields, the expiry, and the valid replies, in GSM-7 within three
// segments. Items that do not fit are left to MORE.
func (c *Channel) renderLocked(r *request) string {
	exp := r.expires.In(c.cfg.Location).Format("15:04")
	var replies string
	if r.local {
		// Only the verified verb, object and recipient count: the page
		// shows the rest (Security D4, UX A2).
		it := r.items[0]
		n := len(strings.Split(it.Recipient, ","))
		pre := ""
		if it.Unverified {
			pre = "UNVERIFIED: "
		}
		return fmt.Sprintf("%s: %syour agent wants to %s \"%s\" to %d recipient%s I can't show in a text. Approve or deny on my Wi-Fi page before %s, or reply NO %s.",
			r.id, pre, field(it.Facts.Verb, 12), field(it.Object, 40), n, map[bool]string{true: "s"}[n != 1], exp, r.id)
	}
	switch {
	case r.tier == High && len(r.items) == 1:
		replies = fmt.Sprintf("Reply YES %s and a code from your code generator%s, or NO %s.", r.id, c.gridOr(), r.id)
	case r.tier == High:
		replies = fmt.Sprintf("Reply YES %s and a code from your code generator%s (add item numbers to approve some; the rest are denied), or NO %s.", r.id, c.gridOr(), r.id)
	case len(r.items) == 1:
		replies = fmt.Sprintf("Reply YES %s %s or NO %s.", r.id, r.code, r.id)
	default:
		replies = fmt.Sprintf("Reply YES %s %s for all, YES %s 1 2 %s for some (the rest are denied), or NO %s.", r.id, r.code, r.id, r.code, r.id)
	}
	if len(r.items) == 1 {
		return fmt.Sprintf("%s: %s. Expires %s. %s", r.id, c.itemLine(r.items[0]), exp, replies)
	}
	for shown := len(r.items); shown >= 0; shown-- {
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %d items.", r.id, len(r.items))
		for i := 0; i < shown; i++ {
			fmt.Fprintf(&b, " %d %s.", i+1, c.itemLine(r.items[i]))
		}
		if shown < len(r.items) {
			fmt.Fprintf(&b, " Items %d-%d: MORE %s.", shown+1, len(r.items), r.id)
		}
		fmt.Fprintf(&b, " Expires %s. %s", exp, replies)
		if fits(b.String()) {
			return b.String()
		}
	}
	return fmt.Sprintf("%s: %d items. MORE %s lists them. Expires %s. %s", r.id, len(r.items), r.id, exp, replies)
}

// moreLocked lists a request's open items (CH-12's MORE).
func (c *Channel) moreLocked(id string) string {
	r := c.open[id]
	if r == nil {
		return fmt.Sprintf("No open request %s.", id)
	}
	var b strings.Builder
	b.WriteString(id + ":")
	for i, it := range r.items {
		if r.done[i] {
			continue
		}
		next := fmt.Sprintf(" %d %s.", i+1, c.itemLine(it))
		if !fits(b.String() + next + " Rest on the box's Wi-Fi page.") {
			b.WriteString(" Rest on the box's Wi-Fi page.")
			break
		}
		b.WriteString(next)
	}
	return b.String()
}

// answerLocked applies YES or NO to a request (CH-13). accepted reports an
// accepted code; wrong reports a code that counted as wrong. page is set
// for an answer from the local page, the only place a local request can
// be approved.
func (c *Channel) answerLocked(rp reply, now time.Time, decided *[]Decision, page bool) (out []string, accepted, wrong bool) {
	r, msg := c.findLocked(rp)
	if r == nil {
		if rp.word == "YES" && rp.code != "" && rp.id == "" {
			// A code that names no request is a wrong code, or texted
			// codes could be guessed without limit (CH-18).
			locked, err := c.codes.wrong(now)
			if err != nil {
				return []string{stateErr}, false, true
			}
			return []string{"Wrong code. " + msg + lockNote(locked)}, false, true
		}
		return []string{msg}, false, false
	}
	if r.local && rp.word == "YES" && !page {
		// Not a wrong code: the owner never saw where it goes (P2-2a).
		// A valid code is spent all the same, so a text that leaked it
		// cannot be replayed on the page (Security R1 on #165); a save
		// failure only leaves it as unspent as before.
		if rp.code != "" {
			_, _, _ = c.codes.checkStrong(rp.code, now, strongOpts{silent: true})
		}
		return []string{fmt.Sprintf("Approve %s on my Wi-Fi page: it shows where this goes. Or reply NO %s.", r.id, r.id)}, false, false
	}
	for _, n := range rp.items {
		if n > len(r.items) || r.done[n-1] {
			return []string{fmt.Sprintf("%s has no open item %d.", r.id, n)}, false, false
		}
	}
	chosen := map[int]bool{}
	for _, n := range rp.items {
		chosen[n-1] = true
	}
	all := len(rp.items) == 0
	if rp.word == "NO" {
		c.closeLocked(r, func(i int) (bool, bool) { return all || chosen[i], false }, "owner", now, decided)
		if all {
			return []string{"Denied " + r.id + "."}, false, false
		}
		return []string{fmt.Sprintf("Denied %s item %s.", r.id, list(rp.items))}, false, false
	}
	strong := r.tier == High || c.codes.st.LowLocked
	if rp.code == "" || (strong && rp.id == "") {
		// A code-generator code proves the owner, not which request they
		// read, so it must come with the ID (CH-3, CH-18).
		return []string{fmt.Sprintf("Include the ID and the code: YES %s <code>.", r.id)}, false, false
	}
	texted := r.code
	if r.tier == High {
		texted = ""
	}
	ok, locked, emsg := c.checkLocked(texted, rp.code, now)
	if emsg != "" {
		return []string{emsg}, false, true
	}
	if !ok {
		r.wrong++
		if r.wrong >= WrongPerRequest {
			c.closeLocked(r, func(int) (bool, bool) { return true, false }, "void", now, decided)
			return []string{fmt.Sprintf("Wrong code 3 times; %s is void and denied.", r.id) + lockNote(locked)}, false, true
		}
		return []string{fmt.Sprintf("Wrong code for %s. %d tries left.", r.id, WrongPerRequest-r.wrong) + lockNote(locked)}, false, true
	}
	// A partial YES closes the batch: the listed items are approved and the
	// rest denied, so the single-use code is not left open (O3).
	var denied []int
	for i := range r.items {
		if !r.done[i] && !all && !chosen[i] {
			denied = append(denied, i+1)
		}
	}
	n := len(*decided)
	c.closeLocked(r, func(i int) (bool, bool) { return true, all || chosen[i] }, "", now, decided)
	s := "Approved " + r.id + "."
	if !all {
		s = fmt.Sprintf("Approved %s item %s.", r.id, list(rp.items))
		if len(denied) > 0 {
			s += fmt.Sprintf(" Denied %s.", list(denied))
		}
	}
	return []string{s + c.holdLocked(r, (*decided)[n:], now, s)}, true, false
}

// holdLocked holds each approved item of r that has an undo window (REV-3):
// it is queued under its own UNDO ID until the window passes, recorded for
// a restart, and its decision carries the hold. It returns the sentence
// the confirmation ends with (CH-16): when the first held item runs and
// the IDs that stop them. An item that cannot be held (no free ID, the
// restart record cannot be saved) is denied rather than run without the
// undo its request promised.
func (c *Channel) holdLocked(r *request, ds []Decision, now time.Time, prefix string) string {
	var items []int
	var ids []string
	var untils []time.Time
	fail := ""
	var first time.Time
	var failed []int
	for k := range ds {
		d := &ds[k]
		if !d.Approved || r.items[d.Item-1].UndoWindow <= 0 {
			continue
		}
		until := now.Add(r.items[d.Item-1].UndoWindow)
		id, err := c.newIDLocked(now)
		if err == nil {
			err = c.codes.commit(func(s *State) { s.Queued = append(s.Queued, QueuedRef{ID: id, Ref: d.Ref, Held: true}) })
		}
		if err != nil {
			d.Approved, d.Why = false, "not held"
			failed = append(failed, d.Item)
			continue
		}
		c.queued[id] = &Queued{ID: id, SendAt: until, Reply: AutoReply{Ref: d.Ref}, Held: true}
		d.Hold, d.Until = id, until
		items = append(items, d.Item)
		ids = append(ids, id)
		untils = append(untils, until)
		if first.IsZero() || until.Before(first) {
			first = until
		}
	}
	if len(failed) > 0 {
		fail = fmt.Sprintf(" Could not hold %s for undo, so it did not run. Ask your agent again.", list(failed))
	}
	s := ""
	switch {
	case len(ids) == 1 && len(r.items) == 1:
		s = fmt.Sprintf(" It runs at %s unless you reply UNDO %s.", c.clock(first), ids[0])
	case len(ids) == 1:
		s = fmt.Sprintf(" Item %d runs at %s unless you reply UNDO %s.", items[0], c.clock(first), ids[0])
	case len(ids) > 1:
		pairs := make([]string, len(ids))
		same := true
		for i := range ids {
			pairs[i] = fmt.Sprintf("%s for %d", ids[i], items[i])
			same = same && untils[i].Equal(first)
		}
		s = fmt.Sprintf(" Held items run from %s unless you reply UNDO and an ID: %s.", c.clock(first), strings.Join(pairs, ", "))
		if !same {
			for i := range ids {
				pairs[i] += " at " + c.clock(untils[i])
			}
			// Each item's own time when they differ, if it fits; else the
			// earliest, which is never later than any.
			if t := fmt.Sprintf(" Held items run unless you reply UNDO and an ID: %s.", strings.Join(pairs, ", ")); fits(prefix + t + fail) {
				s = t
			}
		}
	}
	return s + fail
}

// findLocked resolves which request a reply answers.
func (c *Channel) findLocked(rp reply) (*request, string) {
	if rp.id != "" {
		if r := c.open[rp.id]; r != nil {
			return r, ""
		}
		return nil, fmt.Sprintf("No open request %s.", rp.id)
	}
	if len(c.open) == 1 {
		for _, r := range c.open {
			return r, ""
		}
	}
	// A texted code names its request (CH-18: bound to one request).
	if rp.code != "" && !c.codes.st.LowLocked {
		for _, r := range c.open {
			if r.tier == Low && eq(rp.code, r.code) {
				return r, ""
			}
		}
	}
	if len(c.open) == 0 {
		return nil, "No open requests."
	}
	return nil, fmt.Sprintf("%d requests are open. Reply with an ID: %s.", len(c.open), strings.Join(c.openIDsLocked(), ", "))
}

// closeLocked settles items: pick(i) says whether item i is settled now and
// whether it is approved. The request closes, and its ID retires, when no
// item is left.
func (c *Channel) closeLocked(r *request, pick func(int) (settle, approve bool), why string, now time.Time, decided *[]Decision) {
	for i, it := range r.items {
		if r.done[i] {
			continue
		}
		settle, approve := pick(i)
		if !settle {
			continue
		}
		w := why
		if w == "" {
			w = "owner"
			if !approve {
				w = "not chosen"
			}
		}
		r.done[i] = true
		*decided = append(*decided, Decision{Request: r.id, Item: i + 1, Ref: it.Ref, Approved: approve, Why: w})
	}
	for _, d := range r.done {
		if !d {
			return
		}
	}
	delete(c.open, r.id)
	c.retireLocked(r.id, now)
}

// retireLocked drops an ID from the restart record and keeps it from reuse
// for RetireFor. The save is best effort: if it fails, a restart reports
// the request as dropped, and Decide ignores what is already settled.
func (c *Channel) retireLocked(id string, now time.Time) {
	_ = c.codes.commit(func(s *State) {
		var p []PendingRef
		for _, x := range s.Pending {
			if x.ID != id {
				p = append(p, x)
			}
		}
		s.Pending = p
		var q []QueuedRef
		for _, x := range s.Queued {
			if x.ID != id {
				q = append(q, x)
			}
		}
		s.Queued = q
		for k, t := range s.Retired {
			if now.Sub(t) >= RetireFor {
				delete(s.Retired, k)
			}
		}
		s.Retired[id] = now
	})
}

// expireLocked denies requests past their expiry and drops stale held
// messages and RESUME codes. Expired items are kept for the digest (CH-13).
func (c *Channel) expireLocked(now time.Time) []Decision {
	var out []Decision
	for _, id := range c.openIDsLocked() {
		r := c.open[id]
		if now.Before(r.expires) {
			continue
		}
		c.closeLocked(r, func(int) (bool, bool) { return true, false }, "expired", now, &out)
	}
	c.addExpiredLocked(out)
	if c.held != nil && !now.Before(c.held.expires) {
		c.held = nil
	}
	if c.resume != nil && !now.Before(c.resume.expires) {
		c.resume = nil
	}
	return out
}

func (c *Channel) addExpiredLocked(ds []Decision) {
	c.expired = append(c.expired, ds...)
	if n := len(c.expired) - MaxExpired; n > 0 {
		c.expiredMore += n
		c.expired = append([]Decision(nil), c.expired[n:]...)
	}
}

// Tick expires what is due; Run calls it every minute.
func (c *Channel) Tick() {
	c.mu.Lock()
	d := c.expireLocked(c.cfg.Now())
	c.mu.Unlock()
	c.decide(d)
	c.FlushLocal()
}

// TakeExpired returns and clears the items that expired or were dropped by
// a restart, for the next digest (CH-13). more counts entries beyond
// MaxExpired that were not kept.
func (c *Channel) TakeExpired() (ds []Decision, more int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ds, more = c.expired, c.expiredMore
	c.expired, c.expiredMore = nil, 0
	return ds, more
}

func (c *Channel) decide(ds []Decision) {
	if c.cfg.Decide == nil {
		return
	}
	for _, d := range ds {
		c.cfg.Decide(d)
	}
}

func (c *Channel) openIDsLocked() []string {
	ids := make([]string, 0, len(c.open))
	for id := range c.open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// idLetters avoids I and O, which read as 1 and 0.
const idLetters = "ABCDEFGHJKLMNPQRSTUVWXYZ"

// newIDLocked returns an ID unused by open requests, queued replies, the
// restart record, and IDs retired in the last RetireFor: a letter and a
// digit, or a letter and two digits when those run out (CH-12: at most 3
// characters). It gives up after a bounded search.
func (c *Channel) newIDLocked(now time.Time) (string, error) {
	taken := func(id string) bool {
		if c.open[id] != nil || c.queued[id] != nil {
			return true
		}
		if t, ok := c.codes.st.Retired[id]; ok && now.Sub(t) < RetireFor {
			return true
		}
		for _, p := range c.codes.st.Pending {
			if p.ID == id {
				return true
			}
		}
		for _, q := range c.codes.st.Queued {
			if q.ID == id {
				return true
			}
		}
		return false
	}
	for tries := 0; tries < 64; tries++ {
		id := fmt.Sprintf("%c%d", idLetters[randInt(c.cfg.Rand, len(idLetters))], 2+randInt(c.cfg.Rand, 8))
		if !taken(id) {
			return id, nil
		}
	}
	n := len(idLetters) * 100
	start := randInt(c.cfg.Rand, n)
	for i := 0; i < n; i++ {
		k := (start + i) % n
		id := fmt.Sprintf("%c%02d", idLetters[k/100], k%100)
		if !taken(id) {
			return id, nil
		}
	}
	return "", errors.New("owner: no free request ID")
}

func list(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}
