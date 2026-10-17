package photo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recall"
)

// The photo store (CH-26). A kept photo is content named by its hash in
// Dir (OP-11: content); its receipt, each delivery to a machine and its
// deletion are journal intents, and the listing is a pure fold of the
// journal. Receipts are a journal.Lifecycle with a cap of 200 a day (CH-26);
// deleting a photo removes its bytes and erases its intents' content from
// the journal and its entries from recall (CAP-3).

const (
	// Executor is the journal executor name the store registers under.
	Executor = "photo"
	// Origin is the origin of every intent the store submits.
	Origin = "broker:photo"
	// Kind is the receipt lifecycle's action prefix.
	Kind = "photo.keep."
	// ActionKeep, plus the source, is a receipt: photo.keep.upload.
	ActionKeep    = Kind
	ActionDeliver = "photo.deliver"
	ActionDelete  = "photo.delete"
	// RecallKind is the recall source kind of a photo.
	RecallKind = "photo"

	SourceUpload = "upload"
	SourceMMS    = "mms"

	DailyCap     = 200
	MaxPerUpload = 10
	DefaultDays  = 30

	thumbSuffix = ".thumb"
)

var (
	ErrEmpty          = errors.New("photo: no photos")
	ErrTooMany        = fmt.Errorf("photo: more than %d photos in one upload", MaxPerUpload)
	ErrDailyCap       = fmt.Errorf("photo: %d photos received today, the daily cap", DailyCap)
	ErrReserve        = errors.New("photo: the state disk's reserve is short")
	ErrSource         = errors.New("photo: unknown source")
	ErrUnknown        = errors.New("photo: no such photo")
	ErrCorrupt        = errors.New("photo: kept bytes do not match their hash")
	ErrUntrustedClock = errors.New("photo: the clock is not trusted; nothing expires by time")
	ErrNotDone        = errors.New("photo: the journal did not record the effect as done")
)

var keepLifecycle = journal.Lifecycle{
	Kind:     Kind,
	Inverse:  journal.Irreversible,
	Bounds:   []string{"photo", "hash"},
	DailyCap: DailyCap,
}

func init() {
	if err := journal.Register(keepLifecycle); err != nil {
		panic(err)
	}
}

// Journal is what the store needs of journal.Engine.
type Journal interface {
	Submit(journal.Intent) (journal.Status, error)
	Authorize(ctx context.Context, id string) (journal.Status, error)
	Dispatch(ctx context.Context, id string) (journal.Status, error)
	Get(id string) (journal.Status, error)
	ReadTrail() ([]journal.Record, error)
	Erase(ids []string) (erased, held []string, err error)
}

// Clock is what the store needs of clock.Guard.
type Clock interface {
	Earliest(ctx context.Context) (time.Time, clock.Status)
	Latest(ctx context.Context) (time.Time, clock.Status)
}

// Recall is what the store needs of recall.Index.
type Recall interface {
	DeleteSource(kind, account, rawRef string) (recall.DeleteReport, error)
}

// Store keeps photos. Build it, open the journal engine with it as the
// "photo" executor, set Journal, then call Open.
type Store struct {
	Dir     string
	Journal Journal
	// Clock is the trusted clock (clock.Guard). Without one, or while it
	// is not verified, nothing expires by time.
	Clock Clock
	// Reserve is asked for the bytes an upload will write before any is
	// written (RES-4); nil means no reserve applies.
	Reserve func(need int64) error
	// Recall, when set, loses a photo's entries when the photo goes.
	Recall Recall
	// Backups names the backups holding a photo received at that time,
	// for the deletion confirmation.
	Backups func(received time.Time) []string
	// Running reports whether a machine is running now.
	Running func(machine string) bool
	// Days is the owner's retention setting, read at receipt; nil or a
	// value below 1 means DefaultDays.
	Days func() int
	// Location is the box's time zone, for the daily cap; nil means Local.
	Location *time.Location
	Now      func() time.Time

	mu sync.Mutex
	// rename is durable.Rename; tests replace it to cut a keep short.
	rename func(from, to string) error
}

var renameDurable = durable.Rename

// Received is one photo to keep.
type Received struct {
	Photo  Photo
	Source string // SourceUpload or SourceMMS
	Task   string // the task it came in for, if any
}

// Entry is one kept photo, as the journal records it.
type Entry struct {
	ID       string
	Hash     string
	Source   string
	Task     string
	Width    int
	Height   int
	Bytes    int64
	Received time.Time
	Expires  time.Time
	// Machines are the machines it was delivered to, sorted.
	Machines []string

	thumb string
}

// Confirmation is what the owner is told after a deletion (CH-26): the
// running machines that had a copy, which keep it until they stop, and the
// backups that still hold it.
type Confirmation struct {
	ID       string
	Machines []string
	Backups  []string
}

// Line is the confirmation in one sentence for the owner.
func (c Confirmation) Line() string {
	s := "Deleted photo " + c.ID + "."
	if len(c.Machines) > 0 {
		s += " Still on running " + plural(len(c.Machines), "machine") + " " + strings.Join(c.Machines, ", ") + " until it stops."
	}
	if len(c.Backups) > 0 {
		s += " Still in " + strings.Join(c.Backups, ", ") + " until it ages out."
	}
	return s
}

func plural(n int, w string) string {
	if n == 1 {
		return w
	}
	return w + "s"
}

// RecallSource is the recall source a photo is indexed under.
func RecallSource(id string) (kind, account, ref string) {
	return RecallKind, journal.BrokerAccount, id
}

func keepID(id string) string                 { return "photo:keep:" + id }
func deliverID(id, machine string) string     { return "photo:deliver:" + id + ":" + machine }
func deleteID(id string) string               { return "photo:delete:" + id }
func (s *Store) imagePath(hash string) string { return filepath.Join(s.Dir, hash) }
func (s *Store) thumbPath(hash string) string { return filepath.Join(s.Dir, hash+thumbSuffix) }
func (s *Store) stagePath(id string) string   { return filepath.Join(s.Dir, durable.TempPrefix+id) }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) loc() *time.Location {
	if s.Location != nil {
		return s.Location
	}
	return time.Local
}

func (s *Store) days() int {
	if s.Days != nil {
		if d := s.Days(); d > 0 {
			return d
		}
	}
	return DefaultDays
}

func (s *Store) doRename(from, to string) error {
	if s.rename != nil {
		return s.rename(from, to)
	}
	return renameDurable(from, to)
}

// trusted reports whether the clock may decide something by time.
func trusted(st clock.Status) bool {
	return st.Verified && st.State != clock.Unchecked && !st.Restricted()
}

// Open prepares Dir after a start: staged files a crash left are removed,
// as are kept files no live photo or unsettled receipt names, and photos
// past their time are deleted if the clock is trusted.
func (s *Store) Open() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := durable.SweepTemp(s.Dir); err != nil {
		return err
	}
	v, err := s.view()
	if err != nil {
		return err
	}
	des, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}
	for _, d := range des {
		if !v.held(strings.TrimSuffix(d.Name(), thumbSuffix), "") {
			if err := os.Remove(filepath.Join(s.Dir, d.Name())); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	if _, err := s.sweep(context.Background()); err != nil && !errors.Is(err, ErrUntrustedClock) {
		return err
	}
	return nil
}

// Keep keeps an upload's photos, all or none past the checks: at most
// MaxPerUpload, within the daily cap, and within the reserve.
func (s *Store) Keep(ctx context.Context, rs []Received) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(rs) == 0 {
		return nil, ErrEmpty
	}
	if len(rs) > MaxPerUpload {
		return nil, ErrTooMany
	}
	var need int64
	for _, r := range rs {
		if r.Source != SourceUpload && r.Source != SourceMMS {
			return nil, fmt.Errorf("%w: %q", ErrSource, r.Source)
		}
		need += int64(len(r.Photo.Image) + len(r.Photo.Thumb))
	}
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	now := s.now()
	if keepLifecycle.DailyCount(v.records, journal.BrokerAccount, now.In(s.loc()))+len(rs) > DailyCap {
		return nil, ErrDailyCap
	}
	if s.Reserve != nil {
		if err := s.Reserve(need); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrReserve, err)
		}
	}
	received := now
	if s.Clock != nil {
		if t, st := s.Clock.Latest(ctx); trusted(st) {
			received = t
		}
	}
	expires := received.AddDate(0, 0, s.days())
	var out []Entry
	for i, r := range rs {
		id := "P" + strconv.Itoa(v.next+i)
		e, err := s.keepOne(ctx, id, r, received, expires)
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) keepOne(ctx context.Context, id string, r Received, received, expires time.Time) (Entry, error) {
	e := Entry{ID: id, Hash: hexHash(r.Photo.Image), Source: r.Source, Task: r.Task,
		Width: r.Photo.Width, Height: r.Photo.Height, Bytes: int64(len(r.Photo.Image)),
		Received: received.Truncate(time.Second), Expires: expires.Truncate(time.Second), thumb: hexHash(r.Photo.Thumb)}
	stage := s.stagePath(id)
	defer os.Remove(stage)
	defer os.Remove(stage + thumbSuffix)
	if err := durable.WriteFile(stage, r.Photo.Image, 0o600); err != nil {
		return Entry{}, err
	}
	if err := durable.WriteFile(stage+thumbSuffix, r.Photo.Thumb, 0o600); err != nil {
		return Entry{}, err
	}
	in := s.intent(keepID(id), ActionKeep+r.Source, map[string]any{
		"photo": id, "hash": e.Hash, "thumb": e.thumb, "source": e.Source, "task": e.Task,
		"width": e.Width, "height": e.Height, "bytes": e.Bytes,
		"received": e.Received.Unix(), "expires": e.Expires.Unix(),
	})
	if err := keepLifecycle.Check(in); err != nil {
		return Entry{}, err
	}
	if err := s.run(ctx, in); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func hexHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (s *Store) intent(id, action string, params map[string]any) journal.Intent {
	return journal.Intent{ID: id, Origin: Origin, Account: journal.BrokerAccount, Action: action,
		Params: params, Executor: Executor}
}

// run takes an intent through the journal to a succeeded effect. An intent
// already submitted is carried on from its state.
func (s *Store) run(ctx context.Context, in journal.Intent) error {
	st, err := s.Journal.Get(in.ID)
	if err != nil {
		if st, err = s.Journal.Submit(in); err != nil {
			return err
		}
	}
	if st.State == journal.Pending {
		if st, err = s.Journal.Authorize(ctx, in.ID); err != nil {
			return err
		}
	}
	if st.State == journal.Authorized || st.State == journal.NotApplied {
		if st, err = s.Journal.Dispatch(ctx, in.ID); err != nil {
			return err
		}
	}
	if st.State != journal.Succeeded {
		return fmt.Errorf("%w: %s is %s", ErrNotDone, in.ID, st.State)
	}
	return nil
}

// Deliver records that a photo was delivered to a machine.
func (s *Store) Deliver(ctx context.Context, id, machine string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.view()
	if err != nil {
		return err
	}
	if v.live[id] == nil {
		return fmt.Errorf("%w: %s", ErrUnknown, id)
	}
	return s.run(ctx, s.intent(deliverID(id, machine), ActionDeliver, map[string]any{"photo": id, "machine": machine}))
}

// List returns the live photos, oldest first.
func (s *Store) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.entries(), nil
}

// Image returns a live photo's bytes, checked against its hash.
func (s *Store) Image(id string) ([]byte, error) { return s.read(id, false) }

// Thumb returns a live photo's thumbnail, checked against its hash.
func (s *Store) Thumb(id string) ([]byte, error) { return s.read(id, true) }

func (s *Store) read(id string, thumb bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	e := v.live[id]
	if e == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknown, id)
	}
	path, want := s.imagePath(e.Hash), e.Hash
	if thumb {
		path, want = s.thumbPath(e.Hash), e.thumb
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if hexHash(b) != want {
		return nil, fmt.Errorf("%w: %s", ErrCorrupt, id)
	}
	return b, nil
}

// Delete deletes a photo at the owner's word.
func (s *Store) Delete(ctx context.Context, id string) (Confirmation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.delete(ctx, id, "owner")
}

// DeleteAll deletes every live photo.
func (s *Store) DeleteAll(ctx context.Context) ([]Confirmation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	var out []Confirmation
	for _, e := range v.entries() {
		c, err := s.delete(ctx, e.ID, "owner")
		if err != nil {
			return out, err
		}
		out = append(out, c)
	}
	return out, nil
}

// delete removes the bytes (unless another live photo shares them), the
// recall entries, and the content of every intent about the photo. A retry
// after a failure part way carries on where it stopped. Caller holds mu.
func (s *Store) delete(ctx context.Context, id, why string) (Confirmation, error) {
	v, err := s.view()
	if err != nil {
		return Confirmation{}, err
	}
	p := v.photos[id]
	if p == nil {
		return Confirmation{}, fmt.Errorf("%w: %s", ErrUnknown, id)
	}
	c := Confirmation{ID: id}
	if e := v.live[id]; e != nil {
		for _, m := range e.Machines {
			if s.Running != nil && s.Running(m) {
				c.Machines = append(c.Machines, m)
			}
		}
		if s.Backups != nil {
			c.Backups = s.Backups(e.Received)
		}
		if !p.deleteSubmitted {
			last := !v.held(e.Hash, id)
			in := s.intent(deleteID(id), ActionDelete, map[string]any{"photo": id, "hash": e.Hash, "last": last, "why": why})
			if _, err := s.Journal.Submit(in); err != nil {
				return Confirmation{}, err
			}
		}
		if err := s.run(ctx, journal.Intent{ID: deleteID(id)}); err != nil {
			return Confirmation{}, err
		}
	}
	if s.Recall != nil {
		kind, account, ref := RecallSource(id)
		if _, err := s.Recall.DeleteSource(kind, account, ref); err != nil {
			return Confirmation{}, err
		}
	}
	ids := append([]string{keepID(id)}, p.delivers...)
	if p.deleteSubmitted || v.live[id] != nil {
		ids = append(ids, deleteID(id))
	}
	_, held, err := s.Journal.Erase(ids)
	if err != nil {
		return Confirmation{}, err
	}
	if len(held) > 0 {
		return c, fmt.Errorf("%w: erasing %v waits for their outcome", ErrNotDone, held)
	}
	return c, nil
}

// Sweep deletes the photos past their time, by the trusted clock's earliest
// reading so none goes early. It deletes nothing while the clock is not
// trusted (CH-26).
func (s *Store) Sweep(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweep(ctx)
}

func (s *Store) sweep(ctx context.Context) (int, error) {
	if s.Clock == nil {
		return 0, ErrUntrustedClock
	}
	t, st := s.Clock.Earliest(ctx)
	if !trusted(st) {
		return 0, ErrUntrustedClock
	}
	v, err := s.view()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range v.entries() {
		if e.Expires.After(t) {
			continue
		}
		if _, err := s.delete(ctx, e.ID, "expired"); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Run sweeps now and then every interval until ctx ends.
func (s *Store) Run(ctx context.Context, every time.Duration) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		s.Sweep(ctx) //nolint:errcheck // an untrusted clock retries next tick
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// Execute performs a photo intent (journal.Executor). It runs inside Keep,
// Deliver or Delete, which hold mu.
func (s *Store) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	switch {
	case strings.HasPrefix(in.Action, Kind):
		id, hash := str(in.Params["photo"]), str(in.Params["hash"])
		stage := s.stagePath(id)
		if _, err := os.Stat(stage); err != nil {
			return journal.Outcome{Result: journal.ResultNotApplied}
		}
		// The thumbnail goes first: the image's rename is the commit.
		if err := s.doRename(stage+thumbSuffix, s.thumbPath(hash)); err != nil {
			return journal.Outcome{Result: journal.ResultUnknown}
		}
		if err := s.doRename(stage, s.imagePath(hash)); err != nil {
			return journal.Outcome{Result: journal.ResultUnknown}
		}
		return journal.Outcome{Result: journal.ResultSucceeded}
	case in.Action == ActionDeliver:
		return journal.Outcome{Result: journal.ResultSucceeded}
	case in.Action == ActionDelete:
		if in.Params["last"] == true {
			hash := str(in.Params["hash"])
			for _, p := range []string{s.imagePath(hash), s.thumbPath(hash)} {
				if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
					return journal.Outcome{Result: journal.ResultUnknown}
				}
			}
			if err := durable.SyncDir(s.Dir); err != nil {
				return journal.Outcome{Result: journal.ResultUnknown}
			}
		}
		return journal.Outcome{Result: journal.ResultSucceeded}
	}
	return journal.Outcome{Result: journal.ResultNotApplied}
}

// Reconcile settles an attempt a crash or an error left unknown
// (journal.Executor). A receipt went if both its files are there; if the
// image is not, it never will be, and a thumbnail no other photo holds is
// removed. A deletion went if the bytes are gone or were not its to remove.
func (s *Store) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	hash := str(in.Params["hash"])
	switch {
	case strings.HasPrefix(in.Action, Kind):
		_, ierr := os.Stat(s.imagePath(hash))
		_, terr := os.Stat(s.thumbPath(hash))
		if ierr == nil && terr == nil {
			return journal.Outcome{Result: journal.ResultSucceeded}
		}
		if ierr == nil || !os.IsNotExist(ierr) {
			return journal.Outcome{Result: journal.ResultUnknown}
		}
		v, err := s.view()
		if err != nil {
			return journal.Outcome{Result: journal.ResultUnknown}
		}
		if !v.held(hash, str(in.Params["photo"])) {
			if err := os.Remove(s.thumbPath(hash)); err != nil && !os.IsNotExist(err) {
				return journal.Outcome{Result: journal.ResultUnknown}
			}
		}
		return journal.Outcome{Result: journal.ResultNotApplied}
	case in.Action == ActionDeliver:
		return journal.Outcome{Result: journal.ResultSucceeded}
	case in.Action == ActionDelete:
		if in.Params["last"] != true {
			return journal.Outcome{Result: journal.ResultSucceeded}
		}
		_, ierr := os.Stat(s.imagePath(hash))
		_, terr := os.Stat(s.thumbPath(hash))
		if os.IsNotExist(ierr) && os.IsNotExist(terr) {
			return journal.Outcome{Result: journal.ResultSucceeded}
		}
		return journal.Outcome{Result: journal.ResultNotApplied}
	}
	return journal.Outcome{Result: journal.ResultNotApplied}
}

// view is the store's state folded from the journal.
type view struct {
	records []journal.Record
	photos  map[string]*photoFacts
	live    map[string]*Entry
	// unsettled holds the hashes of receipts dispatched with no outcome
	// yet, which may still own their files.
	unsettled map[string]map[string]bool // hash -> photo IDs
	next      int
}

type photoFacts struct {
	deleteSubmitted bool
	delivers        []string
}

type intentFacts struct {
	in        journal.Intent
	dispatch  bool
	result    journal.Result
	succeeded bool
}

func (s *Store) view() (*view, error) {
	recs, err := s.Journal.ReadTrail()
	if err != nil {
		return nil, err
	}
	facts := map[string]*intentFacts{}
	var order []string
	for _, r := range recs {
		switch r.Type {
		case journal.RecSubmitted:
			if r.Intent != nil && r.Intent.Executor == Executor && facts[r.ID] == nil {
				facts[r.ID] = &intentFacts{in: *r.Intent}
				order = append(order, r.ID)
			}
		case journal.RecDispatched:
			if f := facts[r.ID]; f != nil {
				f.dispatch, f.result = true, ""
			}
		case journal.RecObserved:
			if f := facts[r.ID]; f != nil {
				f.result = r.Result
				f.succeeded = f.succeeded || r.Result == journal.ResultSucceeded
			}
		}
	}
	v := &view{records: recs, photos: map[string]*photoFacts{}, live: map[string]*Entry{},
		unsettled: map[string]map[string]bool{}, next: 1}
	photo := func(id string) *photoFacts {
		p := v.photos[id]
		if p == nil {
			p = &photoFacts{}
			v.photos[id] = p
		}
		return p
	}
	for _, id := range order {
		f := facts[id]
		rest, ok := strings.CutPrefix(id, "photo:keep:")
		if !ok || !strings.HasPrefix(f.in.Action, Kind) {
			continue
		}
		photo(rest)
		if n, err := strconv.Atoi(strings.TrimPrefix(rest, "P")); err == nil && n >= v.next {
			v.next = n + 1
		}
		p := f.in.Params
		if p == nil {
			continue
		}
		if f.dispatch && !f.succeeded && (f.result == "" || f.result == journal.ResultUnknown) {
			h := str(p["hash"])
			if v.unsettled[h] == nil {
				v.unsettled[h] = map[string]bool{}
			}
			v.unsettled[h][rest] = true
		}
		if !f.succeeded {
			continue
		}
		v.live[rest] = &Entry{ID: rest, Hash: str(p["hash"]), thumb: str(p["thumb"]), Source: str(p["source"]),
			Task: str(p["task"]), Width: int(num(p["width"])), Height: int(num(p["height"])), Bytes: num(p["bytes"]),
			Received: time.Unix(num(p["received"]), 0).UTC(), Expires: time.Unix(num(p["expires"]), 0).UTC()}
	}
	for _, id := range order {
		f := facts[id]
		switch f.in.Action {
		case ActionDeliver:
			pid := strings.TrimPrefix(id, "photo:deliver:")
			pid, machine, _ := strings.Cut(pid, ":")
			if v.photos[pid] == nil {
				continue
			}
			v.photos[pid].delivers = append(v.photos[pid].delivers, id)
			if e := v.live[pid]; e != nil && f.succeeded {
				e.Machines = append(e.Machines, machine)
			}
		case ActionDelete:
			pid := strings.TrimPrefix(id, "photo:delete:")
			if v.photos[pid] == nil {
				continue
			}
			v.photos[pid].deleteSubmitted = true
			if f.succeeded {
				delete(v.live, pid)
			}
		}
	}
	for _, e := range v.live {
		sort.Strings(e.Machines)
	}
	return v, nil
}

// held reports whether a live photo or an unsettled receipt other than
// except names hash.
func (v *view) held(hash, except string) bool {
	for id, e := range v.live {
		if id != except && e.Hash == hash {
			return true
		}
	}
	for id := range v.unsettled[hash] {
		if id != except {
			return true
		}
	}
	return false
}

func (v *view) entries() []Entry {
	out := make([]Entry, 0, len(v.live))
	for _, e := range v.live {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return idNum(out[i].ID) < idNum(out[j].ID) })
	return out
}

func idNum(id string) int { n, _ := strconv.Atoi(strings.TrimPrefix(id, "P")); return n }

func str(v any) string { s, _ := v.(string); return s }

// num reads a number param as the journal returns it (json.Number or
// float64).
func num(v any) int64 {
	switch t := v.(type) {
	case json.Number:
		n, _ := t.Int64()
		return n
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	}
	return 0
}
