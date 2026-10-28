package camera

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// The decoder's device events (DEV-8), each under the clerk's limit.
const (
	// DecoderFault: a camera's decoder sandbox broke a rule (a frame of
	// the wrong shape or length, more frames than were fed, a stall, an
	// exit or its memory cap) and was stopped.
	DecoderFault Kind = "decoder-fault"
	// DecoderRecovered: a restarted decoder sent a good frame.
	DecoderRecovered Kind = "decoder-recovered"
)

// Report raises a decoder event for camera id under the clerk's DEV-8
// limit. It is the decoder's Report hook; any other kind is ignored.
func (c *Clerk) Report(id string, k Kind) {
	if k == DecoderFault || k == DecoderRecovered {
		c.event(id, k)
	}
}

// Defaults for the zero values of DecodeConfig.
const (
	// DefaultDecodeMem caps one camera's decoder sandbox, gVisor's own
	// share included.
	DefaultDecodeMem = 512 << 20
	// DefaultStall is how long a decoder may hold a frame it was fed
	// with no output before it is stopped.
	DefaultStall = 5 * time.Second
	// DefaultIdle is how long a decoder runs with no frame fed before it
	// is stopped, which is not a fault (a stream that ended).
	DefaultIdle = time.Minute
	// DefaultQueue is the frames held for a decoder that has not taken
	// them yet; past it, frames are dropped and counted.
	DefaultQueue = 8
)

// The output frame format agentos-camdecode writes (package
// cmd/agentos-camdecode/camdecode, which this package must not import:
// part b2 links libavcodec into it). TestDecodeFormatMatchesDecoder keeps
// the two in step.
const (
	outHeaderLen  = 12
	outVideo      = 1 // I420
	outThermal    = 2 // big-endian 16-bit samples
	maxVideoSide  = 4096
	decoderBinary = "/agentos-camdecode"
)

func outLen(kind byte, s camwire.Shape) int {
	w, h := int(s.Width), int(s.Height)
	if kind == outVideo {
		return w*h + 2*((w+1)/2)*((h+1)/2)
	}
	return 2 * w * h
}

// Decoded is one frame out of a camera's decoder sandbox, checked against
// the shapes the node's bundle declares. It is capture (DEV-7): never
// logged, put in an event or STATUS, or recalled (LOG-4).
type Decoded struct {
	Camera string
	// Thermal is true for a thermal frame (Pixels holds 16-bit samples)
	// and false for a picture (Pixels holds I420 planes).
	Thermal       bool
	Width, Height uint16
	Counter       uint32
	Pixels        []byte
}

// Proc is a running decoder sandbox; *gvisor.StreamRun is one.
type Proc interface {
	In() io.Writer
	Out() io.Reader
	Done() <-chan struct{}
	Stop()
}

// StartFunc starts a decoder sandbox.
type StartFunc func(context.Context, gvisor.Stream) (Proc, error)

// GVisor is the StartFunc that runs decoders under rt.
func GVisor(rt *gvisor.Runtime) StartFunc {
	return func(ctx context.Context, s gvisor.Stream) (Proc, error) {
		run, err := rt.StartStream(ctx, s)
		if err != nil {
			return nil, err
		}
		return run, nil
	}
}

// DecodeConfig is the decoder's wiring.
type DecodeConfig struct {
	Start StartFunc
	// Root is the sandbox's read-only root, holding /agentos-camdecode.
	Root string
	// Cgroup is the cgroup v2 group each sandbox's own group is made
	// under; it is required, since gVisor enforces no memory cap.
	Cgroup   string
	MemBytes int64
	Stall    time.Duration
	Idle     time.Duration
	Queue    int
	// Backoff bounds the wait before a faulted decoder is restarted.
	Backoff Backoff
	// Out takes each checked frame: the consumers' feed (the ring of part
	// c, VIS-core). It must not block for long.
	Out func(Decoded)
	// Report raises a decoder event (Clerk.Report).
	Report func(camera string, k Kind)
	// Log, if set, gets the decoder's fixed lines, which name only the
	// camera.
	Log func(string)
}

// The decoder's errors. Each is fixed text and carries nothing from the
// node or the sandbox.
var (
	ErrDecodeConfig = errors.New("camera: decoder config needs a start, a root, a cgroup, an output and a report")
	ErrShapes       = errors.New("camera: declared shapes out of bounds")
	ErrNotDecoding  = errors.New("camera: no decoder for this camera")
	errIdle         = errors.New("idle")
	errFault        = errors.New("fault")
)

// Decoder is the clerk's FrameSink: it runs each streaming camera's
// frames through that camera's own long-running sandbox and checks what
// comes back (design point 4). A sandbox starts with a camera's first
// frame and stops after Idle with none; one that breaks a rule is
// stopped, raises a DecoderFault, and is restarted on a later frame
// after a backoff that doubles up to Backoff.Max, with a DecoderRecovered
// on its first good frame.
type Decoder struct {
	cfg DecodeConfig

	mu   sync.Mutex
	cams map[string]*decodeCam
	wg   sync.WaitGroup
}

type decodeCam struct {
	id             string
	video, thermal camwire.Shape
	q              chan camwire.Frame
	ctx            context.Context
	cancel         context.CancelFunc
	// done is closed when the loop ends; nil until a frame starts it.
	done chan struct{}

	smu     sync.Mutex
	dropped int
	faults  int
}

// NewDecoder checks cfg and fills its defaults.
func NewDecoder(cfg DecodeConfig) (*Decoder, error) {
	if cfg.Start == nil || cfg.Root == "" || cfg.Cgroup == "" || cfg.Out == nil || cfg.Report == nil {
		return nil, ErrDecodeConfig
	}
	if cfg.MemBytes <= 0 {
		cfg.MemBytes = DefaultDecodeMem
	}
	if cfg.Stall <= 0 {
		cfg.Stall = DefaultStall
	}
	if cfg.Idle <= 0 {
		cfg.Idle = DefaultIdle
	}
	if cfg.Queue <= 0 {
		cfg.Queue = DefaultQueue
	}
	if cfg.Backoff.Min <= 0 || cfg.Backoff.Max < cfg.Backoff.Min {
		cfg.Backoff = DefaultBackoff
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	return &Decoder{cfg: cfg, cams: map[string]*decodeCam{}}, nil
}

// Add declares camera id's shapes, from its node's bundle: the video
// picture's, and the thermal core's (zero for none). Output frames are
// checked against these, never against anything the stream says. Adding
// a camera again replaces its shapes and stops its sandbox.
func (d *Decoder) Add(id string, video, thermal camwire.Shape) error {
	if !idRe.MatchString(id) {
		return ErrNode
	}
	if video.Width == 0 || video.Height == 0 || video.Width > maxVideoSide || video.Height > maxVideoSide {
		return ErrShapes
	}
	if thermal != (camwire.Shape{}) && (thermal.Width == 0 || thermal.Height == 0 ||
		camwire.ThermalHeaderLen+outLen(outThermal, thermal) > camwire.MaxThermal) {
		return ErrShapes
	}
	d.Remove(id)
	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	d.cams[id] = &decodeCam{id: id, video: video, thermal: thermal, q: make(chan camwire.Frame, d.cfg.Queue), ctx: ctx, cancel: cancel}
	d.mu.Unlock()
	return nil
}

// Remove stops camera id's sandbox and forgets it. It returns once no
// frame of it can reach Out.
func (d *Decoder) Remove(id string) {
	d.mu.Lock()
	c := d.cams[id]
	delete(d.cams, id)
	d.mu.Unlock()
	if c == nil {
		return
	}
	c.cancel()
	// No loop starts once c is out of the map, so done is final here.
	d.mu.Lock()
	done := c.done
	d.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Close removes every camera.
func (d *Decoder) Close() {
	d.mu.Lock()
	ids := make([]string, 0, len(d.cams))
	for id := range d.cams {
		ids = append(ids, id)
	}
	d.mu.Unlock()
	for _, id := range ids {
		d.Remove(id)
	}
	d.wg.Wait()
}

// Frame queues a video or thermal frame for camera id's sandbox,
// starting it if none runs. A frame that finds the queue full is dropped
// and counted: a decoder that falls behind loses frames, never stalls the
// stream. A camera never added is an error, which ends its stream.
func (d *Decoder) Frame(id string, f camwire.Frame) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.cams[id]
	if c == nil {
		return ErrNotDecoding
	}
	if f.Type != camwire.TypeVideo && f.Type != camwire.TypeThermal {
		return ErrStream
	}
	if c.done == nil {
		c.done = make(chan struct{})
		d.wg.Add(1)
		go d.loop(c)
	}
	select {
	case c.q <- f:
	default:
		c.smu.Lock()
		c.dropped++
		c.smu.Unlock()
	}
	return nil
}

// Dropped is how many of camera id's frames were dropped at a full queue
// or while its decoder was down, and how many faults it has had.
func (d *Decoder) Dropped(id string) (dropped, faults int) {
	d.mu.Lock()
	c := d.cams[id]
	d.mu.Unlock()
	if c == nil {
		return 0, 0
	}
	c.smu.Lock()
	defer c.smu.Unlock()
	return c.dropped, c.faults
}

// loop runs c's sandboxes, one at a time, until c is removed.
func (d *Decoder) loop(c *decodeCam) {
	defer d.wg.Done()
	defer close(c.done)
	fails := 0
	for c.ctx.Err() == nil {
		var first camwire.Frame
		select {
		case <-c.ctx.Done():
			return
		case first = <-c.q:
		}
		err := d.session(c, first, fails > 0)
		if c.ctx.Err() != nil {
			return
		}
		if err == nil || errors.Is(err, errIdle) {
			fails = 0
			continue
		}
		fails++
		c.smu.Lock()
		c.faults++
		c.smu.Unlock()
		d.cfg.Log("camera " + c.id + ": decoder stopped on a fault; restarting after a backoff")
		d.cfg.Report(c.id, DecoderFault)
		wait := d.cfg.Backoff.Min << min(fails-1, 20)
		if wait > d.cfg.Backoff.Max || wait <= 0 {
			wait = d.cfg.Backoff.Max
		}
		t := time.NewTimer(wait)
		select {
		case <-c.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		d.drain(c)
	}
}

// drain drops the frames that queued while c's decoder was down: they
// are stale, and a restarted decoder starts from the next.
func (d *Decoder) drain(c *decodeCam) {
	for {
		select {
		case <-c.q:
			c.smu.Lock()
			c.dropped++
			c.smu.Unlock()
		default:
			return
		}
	}
}

// session runs one sandbox from first until it idles, faults or c is
// removed. recovering reports a fault before it, so its first good frame
// raises DecoderRecovered.
func (d *Decoder) session(c *decodeCam, first camwire.Frame, recovering bool) error {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	argv := append([]string{decoderBinary}, "-video", dims(c.video), "-thermal", dims(c.thermal))
	p, err := d.cfg.Start(ctx, gvisor.Stream{Name: "camdecode-" + c.id, Root: d.cfg.Root, Argv: argv, MemBytes: d.cfg.MemBytes, Cgroup: d.cfg.Cgroup})
	if err != nil {
		return errFault
	}
	s := &decodeSession{}
	end := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); end <- d.feed(ctx, c, s, p, first) }()
	go func() { defer wg.Done(); end <- d.read(c, s, p, recovering) }()
	tick := time.NewTicker(d.cfg.Stall / 4)
	defer tick.Stop()
	var result error
	for result == nil {
		select {
		case <-ctx.Done():
			result = ctx.Err()
		case err := <-end:
			result = err
		case <-p.Done():
			result = errFault
		case now := <-tick.C:
			if s.stalled(now, d.cfg.Stall) {
				result = errFault
			}
		}
	}
	cancel()
	p.Stop()
	wg.Wait()
	return result
}

// decodeSession is one sandbox's counts: frames fed and frames out of
// each kind, and since when a fed frame has had no output.
type decodeSession struct {
	mu      sync.Mutex
	fed     [3]int
	out     [3]int
	waiting time.Time
}

func (s *decodeSession) stalled(now time.Time, stall time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.waiting.IsZero() && now.Sub(s.waiting) > stall
}

// feed writes c's frames to the sandbox until idle, a write fails, or the
// session ends.
func (d *Decoder) feed(ctx context.Context, c *decodeCam, s *decodeSession, p Proc, f camwire.Frame) error {
	idle := time.NewTimer(d.cfg.Idle)
	defer idle.Stop()
	for {
		k := kindOf(f.Type)
		s.mu.Lock()
		s.fed[k]++
		if s.waiting.IsZero() {
			s.waiting = time.Now()
		}
		s.mu.Unlock()
		if err := camwire.WriteFrame(p.In(), camwire.ToCore, c.thermal, f); err != nil {
			return errFault
		}
		idle.Reset(d.cfg.Idle)
		select {
		case <-ctx.Done():
			return nil
		case <-idle.C:
			return errIdle
		case f = <-c.q:
		}
	}
}

func kindOf(t camwire.Type) int {
	if t == camwire.TypeThermal {
		return outThermal
	}
	return outVideo
}

// read checks each output frame against c's declared shapes before any of
// it is kept: its kind, its dimensions, a count no higher than the frames
// of that kind fed, and then exactly the declared length of pixels. The
// first frame that breaks a rule ends the session as a fault.
func (d *Decoder) read(c *decodeCam, s *decodeSession, p Proc, recovering bool) error {
	var h [outHeaderLen]byte
	for {
		if _, err := io.ReadFull(p.Out(), h[:]); err != nil {
			return errFault
		}
		kind := h[0]
		var shape camwire.Shape
		switch {
		case kind == outVideo:
			shape = c.video
		case kind == outThermal && c.thermal != (camwire.Shape{}):
			shape = c.thermal
		default:
			return errFault
		}
		w, ht := binary.BigEndian.Uint16(h[4:]), binary.BigEndian.Uint16(h[6:])
		if h[1]|h[2]|h[3] != 0 || w != shape.Width || ht != shape.Height {
			return errFault
		}
		s.mu.Lock()
		over := s.out[kind] >= s.fed[kind]
		s.mu.Unlock()
		if over {
			return errFault
		}
		px := make([]byte, outLen(kind, shape))
		if _, err := io.ReadFull(p.Out(), px); err != nil {
			return errFault
		}
		s.mu.Lock()
		s.out[kind]++
		if s.out[outVideo] >= s.fed[outVideo] && s.out[outThermal] >= s.fed[outThermal] {
			s.waiting = time.Time{}
		} else {
			s.waiting = time.Now()
		}
		s.mu.Unlock()
		if recovering {
			recovering = false
			d.cfg.Log("camera " + c.id + ": decoder recovered")
			d.cfg.Report(c.id, DecoderRecovered)
		}
		d.cfg.Out(Decoded{Camera: c.id, Thermal: kind == outThermal, Width: w, Height: ht,
			Counter: binary.BigEndian.Uint32(h[8:]), Pixels: px})
	}
}

func dims(s camwire.Shape) string {
	return strconv.Itoa(int(s.Width)) + "x" + strconv.Itoa(int(s.Height))
}
