package vision

import (
	"errors"
	"math"
	"slices"
	"sync"
	"time"
)

// Tracking (part b, VIS-track; brief points 2 and 5, DEV-7, DEV-8,
// VIS-A22). The tracker runs here in the client, never in the service, and
// numbers its own tracks, so the service chooses no number. It is
// ByteTrack-class: detections at or above HighConf match the confirmed
// tracks first by nearness to each track's predicted box, then the
// remaining low-confidence detections match the confirmed tracks left, then
// the remaining high ones match tentative tracks or start new ones. A
// tentative track is confirmed once it has been matched in Confirm frames
// in a row, or in two frames ConfirmSpan apart (so at the floor rate a car
// seen twice is a track), and dies at its first miss. A detection that
// joins no confirmed track is dropped and counted. A confident detection
// that joins no second frame is inconsistent, and a sustained rate of
// those on one camera marks the service as faulty, which its caller
// answers by restarting it.
//
// What leaves the tracker is a confirmed track's class and box, for the
// site's ground plane and the owner's page only, plate events through
// Plates (VIS-A19), and evidence references for the owner's page. A track
// carries no face: an enrolled id or "unknown" decides only whether a
// visit leaves an evidence reference, so nothing that counts or fuses
// tracks can reach a face.

// Tracker defaults.
const (
	// DefaultHighConf is the confidence, in percent, at or above which a
	// detection may start a track or join one in the first pass.
	DefaultHighConf = 50
	// DefaultConfirm is the frames in a row a tentative track must be
	// matched in before it is confirmed.
	DefaultConfirm = 3
	// DefaultConfirmSpan is how long a tentative track matched in at
	// least two frames must have lived to be confirmed before Confirm
	// frames, so a car in view for two frames at the floor rate is
	// still a track.
	DefaultConfirmSpan = time.Second
	// DefaultLost is how long a confirmed track lives unmatched.
	DefaultLost = 3 * time.Second
	// DefaultDropWindow, DefaultDropMin and DefaultDropRate are the
	// faulty rule: in one camera's window of at least DropMin confident
	// detections, more than DropRate percent of them inconsistent (in
	// no second frame). The constants follow:
	// DropRate percent dropped.
	DefaultDropWindow = time.Minute
	DefaultDropMin    = 120
	DefaultDropRate   = 50
	// MaxTracks bounds one camera's tracks, tentative and confirmed; a
	// detection that would start one more is dropped.
	MaxTracks = 128
	// boxSpeed is the most of its own longer side a thing moves in a
	// second, and boxSlack the jitter allowed at once.
	boxSpeed = 3.0
	boxSlack = 0.5
)

// FrameRef is a frame's place in capture: when it was taken, its format
// and size, and the CAM-clerk segment that holds it, which an evidence
// reference names. The frame's pixels never reach the tracker.
type FrameRef struct {
	At            time.Time
	Format        string
	Width, Height int
	Segment       string
}

// TrackState is a confirmed track as one frame left it. It has no face:
// counting and fusion see classes and boxes only.
type TrackState struct {
	Key   TrackKey
	Class Class
	Box   Box
	At    time.Time
}

// Evidence is a reference to the clearest frame of a visit by someone not
// enrolled (brief point 4, VIS-A18): the segment and frame time to fetch
// from CAM-clerk's store, and the box. It goes to the owner's own page
// only, never to a planner or the bus. Clearest is the largest box at the
// highest confidence, until part (e) gives a sharpness score.
type Evidence struct {
	Camera  string
	Track   uint64
	Segment string
	At      time.Time
	Box     Box
	Conf    int
}

// Update is what one frame, or an Expire, did.
type Update struct {
	// Camera is the camera the update is for; empty for an Expire's.
	Camera string
	// Tracks are the confirmed tracks matched in this frame.
	Tracks []TrackState
	// Ended are the confirmed tracks that ended.
	Ended []TrackKey
	// Plates are the plate events this frame settled (VIS-A19).
	Plates []PlateEvent
	// Evidence holds, for each ended track whose faces were only ever
	// unknown, its clearest frame: for the owner's page only.
	Evidence []Evidence
	// Dropped is the detections dropped by this call.
	Dropped int
	// lone is the confident detections among Dropped that joined no
	// second frame: what the faulty rule counts.
	lone int
}

// ErrFrameOrder is Observe's answer to a frame older than its camera's
// last.
var ErrFrameOrder = errors.New("vision: frame older than the camera's last")

// Tracker tracks each camera's detections. The zero value is not ready;
// use NewTracker.
type Tracker struct {
	HighConf    int
	Confirm     int
	ConfirmSpan time.Duration
	Lost        time.Duration
	// DropWindow, DropMin and DropRate (percent) are the faulty rule,
	// applied to each camera's own window.
	DropWindow time.Duration
	DropMin    int
	DropRate   int
	// Faulty is called, outside the tracker's lock, when the drop rate
	// marks the service as faulty; the caller restarts it
	// (vision/supervise's Supervisor.Restart). Nil does nothing.
	Faulty func()
	// Plates, if set, takes each vehicle detection on a confirmed track,
	// and is told when the track ends.
	Plates *Plates

	mu   sync.Mutex
	cams map[string]*camTracks
	// drops counts every dropped detection.
	drops int
}

// dropWindow counts one camera's confident detections and the
// inconsistent ones among them: those that joined no second frame.
type dropWindow struct {
	start       time.Time
	total, lone int
}

type camTracks struct {
	next   uint64
	last   time.Time
	tracks []*track
	win    dropWindow
}

type track struct {
	id        uint64 // 0 while tentative
	class     Class
	box, prev Box
	at        time.Time
	prevAt    time.Time
	first     time.Time
	hits      int
	hit       bool      // matched in the current frame
	det       Detection // the detection matched last
	unknown   bool      // an unknown face was seen
	enrolled  bool      // an enrolled face was seen
	best      Evidence
	bestScore int
}

// NewTracker returns a Tracker with the default rule.
func NewTracker() *Tracker {
	return &Tracker{
		HighConf: DefaultHighConf, Confirm: DefaultConfirm, ConfirmSpan: DefaultConfirmSpan, Lost: DefaultLost,
		DropWindow: DefaultDropWindow, DropMin: DefaultDropMin, DropRate: DefaultDropRate,
	}
}

// Drops is how many detections the tracker has dropped.
func (t *Tracker) Drops() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.drops
}

// Observe takes one frame's detections from camera, an id from
// [a-z0-9-], and returns what they did. The detections are checked again
// against the frame, so a caller that skipped the client's checks cannot
// put a box outside it into a track.
func (t *Tracker) Observe(camera string, f FrameRef, ds []Detection) (Update, error) {
	if !ValidEnrolledID(camera) {
		return Update{}, badRequest("camera id outside its alphabet")
	}
	if f.Width < 1 || f.Width > MaxWidth || f.Height < 1 || f.Height > MaxHeight {
		return Update{}, badRequest("frame outside its bounds")
	}
	if err := CheckDetections(ds, f.Format, f.Width, f.Height, ValidEnrolledID); err != nil {
		return Update{}, err
	}
	t.mu.Lock()
	if t.cams == nil {
		t.cams = map[string]*camTracks{}
	}
	c := t.cams[camera]
	if c == nil {
		c = &camTracks{}
		t.cams[camera] = c
	}
	if f.At.Before(c.last) {
		t.mu.Unlock()
		return Update{}, ErrFrameOrder
	}
	c.last = f.At
	u := Update{Camera: camera}
	t.match(c, camera, f, ds, &u)
	t.endStale(c, camera, f.At, &u)
	confident := 0
	for _, d := range ds {
		if d.Conf >= max(t.HighConf, 1) {
			confident++
		}
	}
	faulty := t.count(c, f.At, confident, u)
	t.mu.Unlock()
	if faulty && t.Faulty != nil {
		t.Faulty()
	}
	return u, nil
}

// Expire ends, on every camera, the tracks unmatched for longer than Lost
// at now: for a camera that stopped sending frames.
func (t *Tracker) Expire(now time.Time) Update {
	t.mu.Lock()
	defer t.mu.Unlock()
	var u Update
	for id, c := range t.cams {
		lone := u.lone
		t.endStale(c, id, now, &u)
		c.win.lone += u.lone - lone
		if len(c.tracks) == 0 && now.Sub(c.last) > time.Hour {
			delete(t.cams, id)
		}
	}
	t.drops += u.Dropped
	return u
}

// match joins ds to c's tracks. The caller holds mu.
func (t *Tracker) match(c *camTracks, camera string, f FrameRef, ds []Detection, u *Update) {
	high := max(t.HighConf, 1)
	for _, tr := range c.tracks {
		tr.hit = false
	}
	pred := make([]Box, len(c.tracks))
	for i, tr := range c.tracks {
		pred[i] = tr.predict(f.At)
	}
	used := make([]bool, len(ds))
	confirmed := func(tr *track) bool { return tr.id != 0 }
	tentative := func(tr *track) bool { return tr.id == 0 }
	isHigh := func(d Detection) bool { return d.Conf >= high }
	isLow := func(d Detection) bool { return d.Conf < high }
	assign(c, pred, ds, used, confirmed, isHigh, f)
	assign(c, pred, ds, used, confirmed, isLow, f)
	assign(c, pred, ds, used, tentative, isHigh, f)
	// Tentative tracks missed in this frame die before new ones start,
	// so their room is free.
	keep := c.tracks[:0]
	for _, tr := range c.tracks {
		if tr.id == 0 && !tr.hit {
			u.drop(tr)
			continue
		}
		keep = append(keep, tr)
	}
	clear(c.tracks[len(keep):])
	c.tracks = keep
	for j, d := range ds {
		if used[j] {
			continue
		}
		if d.Conf < high {
			u.Dropped++
			continue
		}
		if len(c.tracks) >= MaxTracks {
			u.Dropped++
			u.lone++
			continue
		}
		tr := &track{class: d.Class, box: d.Box, at: f.At, first: f.At, hit: true, det: d}
		tr.see(f, d)
		c.tracks = append(c.tracks, tr)
	}
	confirm := max(t.Confirm, 1)
	span := t.ConfirmSpan
	if span <= 0 {
		span = DefaultConfirmSpan
	}
	for _, tr := range c.tracks {
		if !tr.hit {
			continue
		}
		if tr.id == 0 && (tr.hits >= confirm || tr.hits >= 2 && tr.at.Sub(tr.first) >= span) {
			c.next++
			tr.id = c.next
		}
		if tr.id == 0 {
			continue
		}
		k := TrackKey{Camera: camera, Track: tr.id}
		u.Tracks = append(u.Tracks, TrackState{Key: k, Class: tr.class, Box: tr.box, At: tr.at})
		if t.Plates != nil && tr.class == Vehicle {
			if e, ok := t.Plates.Read(k, tr.det); ok {
				u.Plates = append(u.Plates, e)
			}
		}
	}
}

// assign joins the unused detections ds that pass which to c's tracks that
// pass among, greedily by nearness to each track's predicted box, a
// detection only to a track of its own class. The caller holds mu.
func assign(c *camTracks, pred []Box, ds []Detection, used []bool, among func(*track) bool, which func(Detection) bool, f FrameRef) {
	type pair struct {
		i, j int
		cost float64
	}
	var ps []pair
	for i, tr := range c.tracks {
		if tr.hit || !among(tr) {
			continue
		}
		dt := f.At.Sub(tr.at).Seconds()
		for j, d := range ds {
			if used[j] || !which(d) || d.Class != tr.class {
				continue
			}
			if v, ok := near(pred[i], d.Box, dt); ok {
				ps = append(ps, pair{i, j, v})
			}
		}
	}
	slices.SortStableFunc(ps, func(a, b pair) int {
		switch {
		case a.cost < b.cost:
			return -1
		case a.cost > b.cost:
			return 1
		}
		return 0
	})
	for _, p := range ps {
		tr := c.tracks[p.i]
		if tr.hit || used[p.j] {
			continue
		}
		used[p.j] = true
		d := ds[p.j]
		tr.prev, tr.prevAt = tr.box, tr.at
		tr.box, tr.at, tr.hit, tr.det = d.Box, f.At, true, d
		tr.see(f, d)
	}
}

// see records d, just matched to tr in frame f: the hit, the faces seen,
// and the clearest unknown face.
func (tr *track) see(f FrameRef, d Detection) {
	tr.hits++
	switch {
	case d.Face == FaceUnknown:
		tr.unknown = true
		if s := d.Box.area() * d.Conf; s > tr.bestScore {
			tr.bestScore = s
			tr.best = Evidence{Segment: f.Segment, At: f.At, Box: d.Box, Conf: d.Conf}
		}
	case d.Face != "":
		tr.enrolled = true
	}
}

// predict is tr's box moved on to at by its last motion: the shift between
// its last two boxes, scaled by the time, at most three of its last
// steps.
func (tr *track) predict(at time.Time) Box {
	step := tr.at.Sub(tr.prevAt)
	if tr.prevAt.IsZero() || step <= 0 {
		return tr.box
	}
	k := min(float64(at.Sub(tr.at))/float64(step), 3)
	dx := float64((tr.box.X0+tr.box.X1)-(tr.prev.X0+tr.prev.X1)) / 2 * k
	dy := float64((tr.box.Y0+tr.box.Y1)-(tr.prev.Y0+tr.prev.Y1)) / 2 * k
	mx, my := int(math.Round(dx)), int(math.Round(dy))
	return Box{X0: tr.box.X0 + mx, Y0: tr.box.Y0 + my, X1: tr.box.X1 + mx, Y1: tr.box.Y1 + my}
}

// endStale ends c's confirmed tracks unmatched for longer than Lost at
// now, and drops its tentative tracks as old. The caller holds mu.
func (t *Tracker) endStale(c *camTracks, camera string, now time.Time, u *Update) {
	lost := t.Lost
	if lost <= 0 {
		lost = DefaultLost
	}
	keep := c.tracks[:0]
	for _, tr := range c.tracks {
		if now.Sub(tr.at) <= lost {
			keep = append(keep, tr)
			continue
		}
		if tr.id == 0 {
			u.drop(tr)
			continue
		}
		k := TrackKey{Camera: camera, Track: tr.id}
		u.Ended = append(u.Ended, k)
		if t.Plates != nil {
			t.Plates.End(k)
		}
		if tr.unknown && !tr.enrolled {
			e := tr.best
			e.Camera, e.Track = camera, tr.id
			u.Evidence = append(u.Evidence, e)
		}
	}
	clear(c.tracks[len(keep):])
	c.tracks = keep
}

// drop counts dead tentative track tr's detections as dropped, and as
// inconsistent when it joined no second frame.
func (u *Update) drop(tr *track) {
	u.Dropped += tr.hits
	if tr.hits == 1 {
		u.lone++
	}
}

// count adds a frame's confident detections and u's inconsistent ones to
// camera c's window and reports whether the window just closed over the
// faulty rate. Each camera has its own window, so honest short tracks on
// several busy cameras never add up to one. The caller holds mu.
func (t *Tracker) count(c *camTracks, now time.Time, confident int, u Update) bool {
	t.drops += u.Dropped
	w := &c.win
	if w.start.IsZero() || now.Before(w.start) {
		*w = dropWindow{start: now}
	}
	w.total += confident
	w.lone += u.lone
	span := t.DropWindow
	if span <= 0 {
		span = DefaultDropWindow
	}
	if now.Sub(w.start) < span {
		return false
	}
	faulty := w.total >= max(t.DropMin, 1) && w.lone*100 > t.DropRate*w.total
	*w = dropWindow{start: now}
	return faulty
}

func (b Box) area() int { return (b.X1 - b.X0) * (b.Y1 - b.Y0) }

// near reports whether box d can be the same thing as predicted box p,
// dt seconds on, and its cost, lower for a closer match: d's sides are
// within half to twice p's, and its middle within gate of p's, where gate
// grows with p's longer side and the time, as a thing moves at most
// boxSpeed of its own lengths a second. A gate in time, not overlap,
// keeps a walker tracked at the floor rate, where it moves more than its
// width between frames.
func near(p, d Box, dt float64) (float64, bool) {
	pw, ph := float64(p.X1-p.X0), float64(p.Y1-p.Y0)
	dw, dh := float64(d.X1-d.X0), float64(d.Y1-d.Y0)
	if dw < pw/2 || dw > pw*2 || dh < ph/2 || dh > ph*2 {
		return 0, false
	}
	gate := max(pw, ph) * (boxSlack + boxSpeed*max(dt, 0))
	dist := math.Hypot(float64(d.X0+d.X1-p.X0-p.X1)/2, float64(d.Y0+d.Y1-p.Y0-p.Y1)/2)
	if dist > gate {
		return 0, false
	}
	return dist / gate, true
}
