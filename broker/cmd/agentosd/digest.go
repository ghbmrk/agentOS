package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/modemlink"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// The daily digest (CH-15, W5-Dc): once a day at digestHour box-local time
// the box collects what its sources hold into the digest queue and sends
// it to the owner through the queue's Sender, the only path from a batch
// to the modem link. What cannot be proven sent is never resent (OP-2);
// it is named in STATUS and in one line of the next accepted digest
// (OP-9). The hour is the brief's provisional 08:00 (SG-2).
const digestHour = 8

// digestLimits is the queue's persisted policy. A NotSent costs one
// attempt (W5-Dc-r4); the box tries a ready batch every digestRetry, so
// 96 attempts is 48 tries over the batch's own day and 48 over its late
// day.
var digestLimits = digestqueue.Limits{MaxBatches: 128, MaxSources: 16, MaxAttempts: 96, MaxBytes: 8 << 20}

const digestRetry = 30 * time.Minute

// digestStatusMax bounds the surfaced lines per digest, so a run of them
// cannot push the digest past one text; the rest follow next day.
const digestStatusMax = 3

// The digest's own lines. Each is checked by ownerWorded in the tests.
const (
	digestHead        = "Daily digest: %s; reply STATUS for more."
	digestLateHead    = "Digest of %s: sent late; nothing to do."
	digestDayLine     = "Today: nothing else to report; no action needed."
	digestUnknownLine = "Digest of %s: may not have arrived and is not resent; nothing to do."
	digestFailedLine  = "Digest of %s: could not be sent and is not resent; nothing to do."
	digestHeldLine    = "Digest of %s: was held and is not sent; nothing to do."
)

// The STATUS lines (OP-9), in capLineTexts.
const (
	digestUnknownStatus = "Daily digest: one may not have reached you; the next digest says which."
	digestFailedStatus  = "Daily digest: one could not be sent; the next digest says which."
	digestHeldStatus    = "Daily digest: one was held and not sent; the next digest says which."
	digestDownStatus    = "Daily digest: its store did not open, so none is sent; restart the box."
	digestOwedStatus    = "Daily digest: the one due today is not ready yet; the box tries again every 30 minutes."
)

// digestOutageLine is DC-8's fixed text, sent at most once a day when the
// queue does not open; only sendOutage sends it (provisional, SG-3).
const digestOutageLine = "Daily digest: not sent today, its store did not open; restart the box."

const digestDate = "Mon 2 Jan"

// The box's own sources' names.
const (
	digestDaySource    = "day"
	digestStatusSource = "digest-status"
)

// digestLineTexts are every digest line shape, for the wording test.
func digestLineTexts() []string {
	d := "Mon 5 Oct"
	return []string{fmt.Sprintf(digestHead, d), fmt.Sprintf(digestLateHead, d), digestDayLine,
		fmt.Sprintf(digestUnknownLine, d), fmt.Sprintf(digestFailedLine, d), fmt.Sprintf(digestHeldLine, d),
		digestOutageLine}
}

type digestConfig struct {
	// Queue is the digest queue's store; State is the box's own sources'
	// (digest-sources.json).
	Queue, State digestqueue.Store
	// Sources are DIG-1's, beside the box's day and digest-status ones.
	Sources   map[string]digestqueue.Source
	Transport digestqueue.Transport
	// Inform sends the outage line; nothing else (sendOutage).
	Inform func(string) error
	Now    func() time.Time
	Loc    *time.Location
	Logf   func(string, ...any)
}

// digestState is the box's own sources' persisted state.
type digestState struct {
	// LastDay is the day number whose digest step ran.
	LastDay uint64 `json:"last_day"`
	// DayGen is the last day line acknowledged.
	DayGen uint64 `json:"day_gen"`
	// StatusGen is the last digest-status generation acknowledged;
	// Carried maps a surfaced batch to the generation that carried its
	// line, and Done lists those whose carrier was accepted.
	StatusGen uint64            `json:"status_gen"`
	Carried   map[uint64]uint64 `json:"carried,omitempty"`
	Done      []uint64          `json:"done,omitempty"`
}

// digestBox runs the digest. mu serializes collection, sending and forget,
// so a forget never interleaves with a collection (DC-7).
type digestBox struct {
	cfg digestConfig

	mu  sync.Mutex
	q   *digestqueue.Queue
	col *digestqueue.Collector
	snd *digestqueue.Sender
	st  digestState
	// day is the day number a collection is for (the day source's
	// generation).
	day       uint64
	outageDay uint64
	lastTry   time.Time
	// forgets are the references whose forget the queue has not done
	// (not open, or refused in flight): open purges them before anything
	// is sent, and no batch holding one is sent (CAP-3, security B2 on
	// #592).
	forgets map[string]bool

	// owing is a day whose collection failed: it stays owed and is
	// collected again every digestRetry (L3 1 on #592).
	down, unknown, failed, held, owing atomic.Bool
}

func newDigestBox(cfg digestConfig) *digestBox {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Loc == nil {
		cfg.Loc = time.Local
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &digestBox{cfg: cfg}
}

// register adds the STATUS lines; call before capLines.wire.
func (d *digestBox) register(r *capLines) {
	r.add("digest-down", capHost, func() string { return lineIf(d.down.Load(), digestDownStatus) })
	r.add("digest-unknown", capHeld, func() string { return lineIf(d.unknown.Load(), digestUnknownStatus) })
	r.add("digest-failed", capHeld, func() string { return lineIf(d.failed.Load(), digestFailedStatus) })
	r.add("digest-held", capHeld, func() string { return lineIf(d.held.Load(), digestHeldStatus) })
	r.add("digest-owed", capHeld, func() string { return lineIf(d.owing.Load(), digestOwedStatus) })
}

// open (re)opens the queue and the box's state.
func (d *digestBox) open(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.openLocked(ctx); err != nil {
		d.cfg.Logf("digest: not open: %v", err)
	}
	d.flags(d.cfg.Now())
}

func (d *digestBox) openLocked(ctx context.Context) error {
	d.q, d.col, d.snd = nil, nil, nil
	d.down.Store(true)
	if err := d.load(); err != nil {
		return err
	}
	q, err := digestqueue.New(d.cfg.Queue, digestLimits)
	if err != nil {
		return err
	}
	for ref := range d.forgets {
		if err = q.Forget(ref); err == nil {
			delete(d.forgets, ref)
		}
	}
	sources := maps.Clone(d.cfg.Sources)
	if sources == nil {
		sources = map[string]digestqueue.Source{}
	}
	sources[digestDaySource] = daySource{d}
	sources[digestStatusSource] = statusSource{d}
	col, err := digestqueue.NewCollector(q, sources)
	if err != nil {
		return err
	}
	snd, err := digestqueue.NewSender(q, d.cfg.Transport, d.render, d.cfg.Now)
	if err != nil {
		return err
	}
	d.q, d.col, d.snd = q, col, snd
	d.down.Store(false)
	// A source that does not answer is not an outage: Collect retries it.
	if err = col.Recover(ctx); err != nil {
		d.cfg.Logf("digest: recovery: %v", err)
	}
	return nil
}

func (d *digestBox) load() error {
	raw, err := d.cfg.State.Load()
	if err != nil {
		return err
	}
	st := digestState{}
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &st); err != nil {
			return err
		}
	}
	d.st = st
	return nil
}

func (d *digestBox) save() error {
	raw, err := json.Marshal(d.st)
	if err != nil {
		return err
	}
	return d.cfg.State.Save(raw)
}

// dayOf is t's box-local date as days since 1970-01-01.
func (d *digestBox) dayOf(t time.Time) uint64 {
	y, m, dd := t.In(d.cfg.Loc).Date()
	return uint64(time.Date(y, m, dd, 0, 0, 0, 0, time.UTC).Unix() / 86400)
}

// digestAt is the digest time on day n.
func (d *digestBox) digestAt(n uint64) time.Time {
	t := time.Unix(int64(n)*86400, 0).UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), digestHour, 0, 0, 0, d.cfg.Loc)
}

// run steps the digest every minute until ctx ends.
func (d *digestBox) run(ctx context.Context) {
	d.open(ctx)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		d.step(ctx, d.cfg.Now())
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// step runs the day's digest once it is due, and otherwise retries ready
// batches every digestRetry.
func (d *digestBox) step(ctx context.Context, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	today := d.dayOf(now)
	switch {
	case today > d.st.LastDay && !now.Before(d.digestAt(today)) && (!d.owing.Load() || now.Sub(d.lastTry) >= digestRetry):
		d.lastTry = now
		d.daily(ctx, now, today)
	case now.Sub(d.lastTry) >= digestRetry:
		d.lastTry = now
		if d.q == nil {
			if err := d.openLocked(ctx); err != nil {
				break
			}
		}
		d.sendReady(ctx, now)
		d.settle()
	}
	d.flags(now)
}

// daily runs day today's digest step. A collection that fails with the
// queue still reading leaves the day owed, so the step runs again after
// digestRetry; any other end of the step closes the day.
func (d *digestBox) daily(ctx context.Context, now time.Time, today uint64) {
	owed := false
	defer func() {
		d.owing.Store(owed)
		if !owed {
			d.st.LastDay = today
		}
		if err := d.save(); err != nil {
			d.cfg.Logf("digest: state not saved: %v", err)
		}
	}()
	if d.q == nil {
		if err := d.openLocked(ctx); err != nil {
			d.cfg.Logf("digest: not open: %v", err)
			d.outage(today)
			return
		}
	}
	if err := d.q.Expire(now); err != nil {
		if d.broken(err) {
			d.outage(today)
			return
		}
		d.cfg.Logf("digest: expiry: %v", err)
	}
	d.day = today
	if _, err := d.col.Collect(ctx, now, d.digestAt(today+1)); err != nil {
		if d.broken(err) {
			d.outage(today)
			return
		}
		d.cfg.Logf("digest: collection: %v; retrying", err)
		owed = true
	}
	held, err := d.q.Held(now)
	if err != nil {
		d.broken(err)
		return
	}
	for _, b := range held {
		if !b.Late {
			if err = d.q.Late(b.ID, now, d.digestAt(today+1)); err != nil {
				d.cfg.Logf("digest: batch %d not re-armed: %v", b.ID, err)
			}
		}
	}
	d.sendReady(ctx, now)
	d.settle()
	if !d.owesFailed() {
		if err = d.q.Compact(); err != nil {
			d.broken(err)
		}
	}
}

// broken reports whether the queue no longer reads, and if so drops it so
// the next step reopens it.
func (d *digestBox) broken(err error) bool {
	if _, lerr := d.q.List(); lerr == nil {
		return false
	}
	d.cfg.Logf("digest: queue unavailable: %v", err)
	d.q, d.col, d.snd = nil, nil, nil
	d.down.Store(true)
	return true
}

// outage sends the outage line at most once a day (DC-8).
func (d *digestBox) outage(today uint64) {
	if d.outageDay == today {
		return
	}
	d.outageDay = today
	d.sendOutage()
}

// sendOutage is the only sender of digestOutageLine and the only caller of
// Inform; it carries no batch.
func (d *digestBox) sendOutage() {
	if d.cfg.Inform == nil {
		d.cfg.Logf("digest: outage line not sent: no owner channel")
		return
	}
	if err := d.cfg.Inform(digestOutageLine); err != nil {
		d.cfg.Logf("digest: outage line not sent: %v", err)
	}
}

// sendReady sends each batch the queue would begin, oldest first.
func (d *digestBox) sendReady(ctx context.Context, now time.Time) {
	bs, err := d.q.List()
	if err != nil {
		d.broken(err)
		return
	}
	for _, b := range bs {
		if b.State != digestqueue.Ready || b.Redacted || !now.Before(b.Expires) || b.Attempts >= digestLimits.MaxAttempts ||
			slices.Contains(b.Acknowledged, false) || refersTo(b, d.forgets) {
			continue
		}
		out, err := d.snd.Send(ctx, b.ID)
		if err != nil {
			d.cfg.Logf("digest: batch %d: %s: %v", b.ID, out, err)
			if d.broken(err) {
				return
			}
		}
	}
}

// surfaced reports whether b needs a line in a digest: an unknown or
// exhausted send, or a late batch held again, whose line is not yet in an
// accepted digest.
func (d *digestBox) surfaced(b digestqueue.Batch, now time.Time) bool {
	if slices.Contains(d.st.Done, b.ID) {
		return false
	}
	switch b.State {
	case digestqueue.Unknown, digestqueue.Failed:
		return true
	case digestqueue.Ready:
		return b.Late && !now.Before(b.Expires)
	}
	return false
}

// refersTo reports whether a snapshot of b holds one of refs.
func refersTo(b digestqueue.Batch, refs map[string]bool) bool {
	for _, s := range b.Snapshots {
		for _, r := range s.References {
			if refs[r] {
				return true
			}
		}
	}
	return false
}

// carrier is the batch holding digest-status generation g.
func carrier(bs []digestqueue.Batch, g uint64) (digestqueue.Batch, bool) {
	for _, b := range bs {
		for _, s := range b.Snapshots {
			if s.Source == digestStatusSource && s.Generation == g {
				return b, true
			}
		}
	}
	return digestqueue.Batch{}, false
}

// settle marks done each surfaced batch whose carrier was accepted, and
// drops state for batches the queue no longer holds.
func (d *digestBox) settle() {
	bs, err := d.q.List()
	if err != nil {
		return
	}
	ids := map[uint64]bool{}
	for _, b := range bs {
		ids[b.ID] = true
	}
	changed := false
	for id, g := range d.st.Carried {
		c, ok := carrier(bs, g)
		switch {
		case !ids[id]:
			delete(d.st.Carried, id)
			changed = true
		case ok && c.State == digestqueue.Accepted:
			if !slices.Contains(d.st.Done, id) {
				d.st.Done = append(d.st.Done, id)
			}
			delete(d.st.Carried, id)
			changed = true
		}
	}
	done := slices.DeleteFunc(slices.Clone(d.st.Done), func(id uint64) bool { return !ids[id] })
	if len(done) != len(d.st.Done) {
		d.st.Done, changed = done, true
	}
	if changed {
		if err = d.save(); err != nil {
			d.cfg.Logf("digest: state not saved: %v", err)
		}
	}
}

// owesFailed reports an exhausted batch not yet named in an accepted
// digest: Compact would drop it.
func (d *digestBox) owesFailed() bool {
	bs, err := d.q.List()
	if err != nil {
		return true
	}
	return slices.ContainsFunc(bs, func(b digestqueue.Batch) bool {
		return b.State == digestqueue.Failed && !slices.Contains(d.st.Done, b.ID)
	})
}

// flags sets the STATUS lines from the queue.
func (d *digestBox) flags(now time.Time) {
	var unknown, failed, held bool
	if d.q != nil {
		bs, err := d.q.List()
		if err != nil {
			d.broken(err)
		}
		for _, b := range bs {
			if !d.surfaced(b, now) {
				continue
			}
			unknown = unknown || b.State == digestqueue.Unknown
			failed = failed || b.State == digestqueue.Failed
			held = held || b.State == digestqueue.Ready
		}
	}
	d.down.Store(d.q == nil)
	d.unknown.Store(unknown)
	d.failed.Store(failed)
	d.held.Store(held)
}

// render is the digest's text: its head, then each snapshot's lines. One
// that would not fit one text is refused, never cut.
func (d *digestBox) render(b digestqueue.Batch) (string, error) {
	date := b.Created.In(d.cfg.Loc).Format(digestDate)
	head := fmt.Sprintf(digestHead, date)
	if b.Late {
		head = fmt.Sprintf(digestLateHead, date)
	}
	lines := []string{head}
	for _, s := range b.Snapshots {
		lines = append(lines, s.Lines...)
	}
	text := strings.Join(lines, "\n")
	if len(text) > control.MaxText {
		return "", fmt.Errorf("digest of %d bytes is over one text", len(text))
	}
	return text, nil
}

// forget purges ref from the queue (CAP-3). A batch in flight refuses it
// (digestqueue.ErrInFlight), as does a queue that is not open, so the
// forget stays owed and its retry asks again; meanwhile ref is kept in
// forgets, so open purges it first and no batch holding it is sent.
func (d *digestBox) forget(ref string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !digestRef(ref) {
		// No snapshot can carry it.
		return nil
	}
	err := errors.New("digest: queue not open")
	if d.q != nil {
		err = d.q.Forget(ref)
	}
	if err == nil {
		delete(d.forgets, ref)
		return nil
	}
	if d.forgets == nil {
		d.forgets = map[string]bool{}
	}
	d.forgets[ref] = true
	return err
}

// digestRef reports a reference the queue accepts.
func digestRef(ref string) bool {
	_, err := digestqueue.NewSnapshot("x", 1, []string{"x"}, []string{ref})
	return err == nil
}

// daySource offers the day line once a day when no other source has
// anything to say. It runs under the box's mu (Collect).
type daySource struct{ d *digestBox }

func (s daySource) Peek(ctx context.Context) (*digestqueue.Snapshot, error) {
	d := s.d
	if d.day == 0 || d.st.DayGen >= d.day {
		return nil, nil
	}
	others := []digestqueue.Source{statusSource{d}}
	for _, o := range d.cfg.Sources {
		others = append(others, o)
	}
	for _, o := range others {
		snap, err := o.Peek(ctx)
		if err != nil {
			return nil, err
		}
		if snap != nil {
			return nil, nil
		}
	}
	snap, err := digestqueue.NewSnapshot(digestDaySource, d.day, []string{digestDayLine}, nil)
	return &snap, err
}

func (s daySource) Ack(_ context.Context, snap digestqueue.Snapshot) error {
	if snap.Generation <= s.d.st.DayGen {
		return nil
	}
	s.d.st.DayGen = snap.Generation
	return s.d.save()
}

// statusSource offers one line per surfaced batch whose line is not in a
// digest still on its way. It runs under the box's mu (Collect).
type statusSource struct{ d *digestBox }

func (s statusSource) Peek(context.Context) (*digestqueue.Snapshot, error) {
	d := s.d
	bs, err := d.q.List()
	if err != nil {
		return nil, err
	}
	now := d.cfg.Now()
	var lines, refs []string
	for _, b := range bs {
		if !d.surfaced(b, now) || d.pending(bs, b.ID, now) {
			continue
		}
		f := digestHeldLine
		switch b.State {
		case digestqueue.Unknown:
			f = digestUnknownLine
		case digestqueue.Failed:
			f = digestFailedLine
		}
		lines = append(lines, fmt.Sprintf(f, b.Created.In(d.cfg.Loc).Format(digestDate)))
		refs = append(refs, "digest:"+strconv.FormatUint(b.ID, 10))
		if len(lines) == digestStatusMax {
			break
		}
	}
	if len(lines) == 0 {
		return nil, nil
	}
	snap, err := digestqueue.NewSnapshot(digestStatusSource, d.st.StatusGen+1, lines, refs)
	return &snap, err
}

// pending reports that id's line is in a digest that may still go: ready
// and not held after Late, or sending.
func (d *digestBox) pending(bs []digestqueue.Batch, id uint64, now time.Time) bool {
	g, ok := d.st.Carried[id]
	if !ok {
		return false
	}
	c, ok := carrier(bs, g)
	if !ok {
		return false
	}
	switch c.State {
	case digestqueue.Sending, digestqueue.Accepted:
		return true
	case digestqueue.Ready:
		return !(c.Late && !now.Before(c.Expires))
	}
	return false
}

func (s statusSource) Ack(_ context.Context, snap digestqueue.Snapshot) error {
	d := s.d
	if snap.Generation <= d.st.StatusGen {
		return nil
	}
	if d.st.Carried == nil {
		d.st.Carried = map[uint64]uint64{}
	}
	for _, r := range snap.References {
		if id, err := strconv.ParseUint(strings.TrimPrefix(r, "digest:"), 10, 64); err == nil {
			d.st.Carried[id] = snap.Generation
		}
	}
	d.st.StatusGen = snap.Generation
	return d.save()
}

// digestTransport is the digest queue's Transport over the modem link
// (DC-5). It keeps only the receipt's evidence (W5-Dc-r6) and sends the
// text as Inform does, through Disclose and Fit.
type digestTransport struct {
	to   string
	send func(to, text string) (modemlink.Receipt, error)
}

// newDigestTransport is the only use of SendReceipt (digestgate_test).
func newDigestTransport(link *modemlink.Link, to string) digestTransport {
	return digestTransport{to: to, send: link.SendReceipt}
}

func (t digestTransport) Deliver(_ context.Context, text string) (digestqueue.Outcome, string) {
	// The error is as Send's and says no more than the receipt.
	r, _ := t.send(t.to, control.Fit(ownerch.Disclose(text)))
	switch r.Outcome {
	case modemlink.ReceiptAccepted:
		return digestqueue.TransportAccepted, r.Evidence
	case modemlink.ReceiptNotSent:
		return digestqueue.NotSent, r.Evidence
	case modemlink.ReceiptUnknown:
		return digestqueue.OutcomeUnknown, r.Evidence
	}
	return digestqueue.OutcomeUnknown, ""
}

// prepareDigestDir makes dir the digest's own directory: created 0700
// if missing, refused if it is a symlink or not a directory, else set to
// 0700, and any temporary file a crashed save left is removed, so a save
// never keeps a wider mode it had (security R3 on #592).
func prepareDigestDir(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("digest: %s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmps, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		return err
	}
	for _, t := range tmps {
		if err := os.Remove(t); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// downStore is a store that does not open, for a digest directory
// prepareDigestDir refused: the box says its store is down.
type downStore struct{ err error }

func (s downStore) Load() ([]byte, error) { return nil, s.err }
func (s downStore) Save([]byte) error     { return s.err }
