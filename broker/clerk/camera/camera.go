// Package camera is the core's camera clerk library (CAM-clerk part a,
// #3514; SPEC DEV-1, DEV-2, DEV-3, DEV-7, DEV-8, NET-2 Cameras, KRN-7, A16).
// It opens a camera node's stream on a connection the core starts, pins the
// node's TLS key, presents the core's client key from the sealed store, and
// reads camwire frames. It parses only frame headers and the node's fixed
// status record: video and thermal payloads go, unparsed, to the decoder
// (part b). Capture stays off for a node until the owner's tier-4 turn-on.
// A node that falls silent, presents another key or sends a bad frame
// raises a device event, rate-limited per camera and kind; another key also
// turns the node off until the owner re-pins it.
package camera

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Defaults for the zero values of Node and Config.
const (
	DefaultInterval = 30 * time.Second
	DefaultTimeout  = 10 * time.Second
)

// DefaultBackoff is the redial backoff when Config.Backoff is unset.
var DefaultBackoff = Backoff{Min: time.Second, Max: time.Minute}

// Mode is a node's capture setting, from the owner's tier-4 turn-on
// (DEV-7, DEV-10). The zero Mode is off.
type Mode int

const (
	Off Mode = iota
	// Continuous streams whenever the clerk runs the node.
	Continuous
	// OnRequest streams only within a task whose plan step names the node.
	OnRequest
)

// Node is one camera node as the owner connected it.
type Node struct {
	// ID names the camera in logs, events and STATUS. It is the core's
	// name, from a closed alphabet, never text from the node.
	ID string
	// Addr is the node's stream port on the home network (DEV-2).
	Addr netip.AddrPort
	// Key is the SHA-256 of the node's TLS SubjectPublicKeyInfo (DEV-3).
	Key [32]byte
	// Thermal is the thermal core the node's bundle declares; zero for none.
	Thermal camwire.Shape
	Capture Mode
	// Interval is how long the node may send nothing before it is silent;
	// zero is DefaultInterval.
	Interval time.Duration
}

// Step is a kernel-admitted plan step, as the on-request capture gate
// reads it: the task it belongs to, the camera it names and its verb.
type Step struct {
	Task   string
	Camera string
	Verb   key.Verb
}

// FrameSink takes each video and thermal frame, payload unparsed: the
// decoder's feed (part b). An error ends the connection.
type FrameSink interface {
	Frame(camera string, f camwire.Frame) error
}

// Backoff bounds the wait between dials of a node that is not streaming.
type Backoff struct{ Min, Max time.Duration }

// Config is the clerk's wiring.
type Config struct {
	// Guard is the home-network address guard (DEV-2): every dial goes
	// through it with PurposeDevice, so it reaches only an address the host
	// pinned as a netguard.PinDevice.
	Guard *netguard.Policy
	// Key is the core's camera client key (CLK-1).
	Key    *ClientKey
	Frames FrameSink
	Events EventSink
	Limit  Limit
	// Admit is the RES-2 admission check for a new camera.
	Admit   func(camera string) bool
	Backoff Backoff
	// Timeout bounds each dial and handshake; zero is DefaultTimeout.
	Timeout time.Duration
	// Now, if set, is the clock events and the limit read.
	Now func() time.Time
	// Log, if set, gets the clerk's fixed lines, which name only the camera.
	Log func(string)
}

// The clerk's errors. Each is fixed text and carries nothing from the node.
var (
	ErrConfig     = errors.New("camera: config needs a guard, a client key, a frame sink, an event sink, a limit and admission")
	ErrNode       = errors.New("camera: node refused")
	ErrAddress    = errors.New("camera: node address is not a home-network ip:port")
	ErrAdmission  = errors.New("camera: not admitted (RES-2)")
	ErrUnknown    = errors.New("camera: no such camera")
	ErrOff        = errors.New("camera: off until the owner re-pins it")
	ErrCaptureOff = errors.New("camera: capture is not turned on for this")
	ErrStep       = errors.New("camera: the step does not name this camera's capture")
	ErrBusy       = errors.New("camera: already streaming")
	ErrDial       = errors.New("camera: dial refused or failed")
	ErrHandshake  = errors.New("camera: handshake failed")
	ErrSilent     = errors.New("camera: node silent")
	ErrStream     = errors.New("camera: stream fault")
	errMismatch   = errors.New("camera: node key does not match its pin")
	errRepinned   = errors.New("camera: re-pinned since this stream was dialed")
)

var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// Clerk runs the core's camera nodes, one stream each.
type Clerk struct {
	cfg Config

	mu    sync.Mutex
	nodes map[string]*node

	lmu   sync.Mutex
	win   map[wkey]*window
	order []wkey
}

type node struct {
	// deliver is held across a frame's check and its hand-off to the sink,
	// and by every owner change, so no frame reaches the sink once
	// SetCapture, Repin or Remove has returned. Taken before c.mu.
	deliver sync.Mutex
	pin     Node
	off     bool
	busy    bool
	cancel  context.CancelFunc // ends the running attempt
	last    time.Time          // the last frame, or the start of the run
	silent  bool
	frames  uint64
	status  camwire.Status
	has     bool
}

// New checks cfg and returns a clerk with no cameras.
func New(cfg Config) (*Clerk, error) {
	if cfg.Guard == nil || cfg.Key == nil || cfg.Frames == nil || cfg.Events == nil ||
		cfg.Admit == nil || cfg.Limit.Burst < 1 || cfg.Limit.Window <= 0 {
		return nil, ErrConfig
	}
	if cfg.Backoff == (Backoff{}) {
		cfg.Backoff = DefaultBackoff
	}
	if cfg.Backoff.Min <= 0 || cfg.Backoff.Max < cfg.Backoff.Min {
		return nil, ErrConfig
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Clerk{cfg: cfg, nodes: map[string]*node{}, win: map[wkey]*window{}}, nil
}

// Format prints no field, whatever the verb.
func (c *Clerk) Format(f fmt.State, _ rune) { fmt.Fprint(f, "camera.Clerk{}") }

func (c *Clerk) log(id, line string) {
	if c.cfg.Log != nil {
		c.cfg.Log("camera " + id + ": " + line)
	}
}

// Add connects a node: checked, then admitted under RES-2. It dials
// nothing.
func (c *Clerk) Add(n Node) error {
	if !idRe.MatchString(n.ID) || n.Key == ([32]byte{}) || n.Interval < 0 ||
		n.Capture < Off || n.Capture > OnRequest {
		return ErrNode
	}
	if !homeAddr(n.Addr) {
		return ErrAddress
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodes[n.ID] != nil {
		return ErrNode
	}
	if !c.cfg.Admit(n.ID) {
		c.log(n.ID, "not admitted (RES-2)")
		return ErrAdmission
	}
	if n.Interval == 0 {
		n.Interval = DefaultInterval
	}
	c.nodes[n.ID] = &node{pin: n}
	return nil
}

// Remove disconnects a camera: its stream ends and it is dialed no more.
func (c *Clerk) Remove(id string) {
	c.change(id, func(*node) { delete(c.nodes, id) })
	c.lmu.Lock()
	c.order = slices.DeleteFunc(c.order, func(k wkey) bool {
		if k.camera == id {
			delete(c.win, k)
			return true
		}
		return false
	})
	c.lmu.Unlock()
}

// SetCapture records the owner's tier-4 capture setting. A stream the new
// setting does not allow ends at once.
func (c *Clerk) SetCapture(id string, m Mode) error {
	if m < Off || m > OnRequest {
		return ErrNode
	}
	return c.change(id, func(n *node) { n.pin.Capture = m })
}

// Repin is the owner's tier-4 re-pin (DEV-3): the node's new key is pinned,
// the old one is refused, and a node turned off is on again.
func (c *Clerk) Repin(id string, k [32]byte) error {
	if k == ([32]byte{}) {
		return ErrNode
	}
	if err := c.change(id, func(n *node) { n.pin.Key, n.off = k, false }); err != nil {
		return err
	}
	c.log(id, "re-pinned by the owner")
	return nil
}

func (c *Clerk) change(id string, fn func(*node)) error {
	c.mu.Lock()
	n := c.nodes[id]
	c.mu.Unlock()
	if n == nil {
		return ErrUnknown
	}
	n.deliver.Lock()
	defer n.deliver.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodes[id] != n {
		return ErrUnknown
	}
	fn(n)
	if n.cancel != nil {
		n.cancel()
	}
	return nil
}

// Run streams a continuous camera until ctx ends, redialing with backoff.
// With capture not turned on as continuous it opens no connection.
func (c *Clerk) Run(ctx context.Context, id string) error {
	return c.loop(ctx, id, Continuous)
}

// Capture streams an on-request camera for one step, until ctx (the task)
// ends. Only a read step of a task that names the camera opens a stream
// (DEV-7: capture is a read, as the clerk reads the response type).
func (c *Clerk) Capture(ctx context.Context, s Step) error {
	if s.Task == "" || s.Verb != key.Read || !idRe.MatchString(s.Camera) {
		return ErrStep
	}
	return c.loop(ctx, s.Camera, OnRequest)
}

// ready is whether n may stream under want; held under c.mu.
func (c *Clerk) ready(id string, n *node, want Mode) error {
	switch {
	case n == nil || c.nodes[id] != n:
		return ErrUnknown
	case n.off:
		return ErrOff
	case n.pin.Capture != want:
		return ErrCaptureOff
	}
	return nil
}

func (c *Clerk) loop(ctx context.Context, id string, want Mode) error {
	c.mu.Lock()
	n := c.nodes[id]
	if err := c.ready(id, n, want); err != nil {
		c.mu.Unlock()
		return err
	}
	if n.busy {
		c.mu.Unlock()
		return ErrBusy
	}
	n.busy, n.last, n.silent = true, c.cfg.Now(), false
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		n.busy, n.cancel = false, nil
		c.mu.Unlock()
	}()
	wait := c.cfg.Backoff.Min
	for {
		actx, cancel := context.WithCancel(ctx)
		c.mu.Lock()
		err := c.ready(id, n, want)
		pin := n.pin
		n.cancel = cancel
		c.mu.Unlock()
		if err != nil {
			cancel()
			return err
		}
		got, err := c.stream(actx, n, pin)
		if ctx.Err() != nil {
			cancel()
			return ctx.Err()
		}
		if errors.Is(err, ErrOff) {
			cancel()
			return ErrOff
		}
		if got {
			wait = c.cfg.Backoff.Min
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-actx.Done():
		}
		t.Stop()
		cancel()
		wait = min(2*wait, c.cfg.Backoff.Max)
	}
}

// stream is one connection: dial, pin, then frames until it ends. got is
// whether any frame arrived.
func (c *Clerk) stream(ctx context.Context, n *node, pin Node) (got bool, err error) {
	conn, err := c.dial(ctx, pin)
	if errors.Is(err, errMismatch) {
		if c.turnOff(n, pin) {
			return false, ErrOff
		}
		return false, errRepinned
	}
	if err != nil {
		c.gap(n, pin)
		return false, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	return c.serve(n, conn, pin)
}

// deadliner is a connection whose reads can be bounded.
type deadliner interface{ SetReadDeadline(time.Time) error }

// tracked keeps the transport's own error, which camwire folds into
// ErrShort, so a stall or a close tells apart from a bad frame.
type tracked struct {
	r   io.Reader
	err error
}

func (t *tracked) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil {
		t.err = err
	}
	return n, err
}

// serve reads frames from r until one fails. Only headers and the status
// record are parsed here; video and thermal payloads go to the sink as
// they came.
func (c *Clerk) serve(n *node, r io.Reader, pin Node) (got bool, err error) {
	tr := &tracked{r: r}
	dl, _ := r.(deadliner)
	for {
		if dl != nil {
			dl.SetReadDeadline(time.Now().Add(pin.Interval))
		}
		f, err := camwire.ReadFrame(tr, camwire.ToCore, pin.Thermal)
		if err != nil {
			var ne net.Error
			switch {
			case errors.As(tr.err, &ne) && ne.Timeout():
				c.markSilent(n, pin.ID)
				return got, ErrSilent
			case tr.err != nil:
				// The node closed or the connection broke: silence decides.
				c.gap(n, pin)
				return got, ErrStream
			}
			c.log(pin.ID, "stream ended: a frame broke the camera wire")
			c.event(pin.ID, StreamFault)
			return got, ErrStream
		}
		got = true
		c.mu.Lock()
		n.last = c.cfg.Now()
		n.frames++
		recovered := n.silent
		n.silent = false
		if f.Type == camwire.TypeStatus {
			// ReadFrame has checked the payload; this only copies it out.
			n.status, _ = camwire.ParseStatus(f.Payload)
			n.has = true
		}
		c.mu.Unlock()
		if recovered {
			c.log(pin.ID, "streaming again")
			c.event(pin.ID, Recovered)
		}
		if f.Type == camwire.TypeVideo || f.Type == camwire.TypeThermal {
			if err := c.hand(n, pin, f); err != nil {
				return got, err
			}
		}
	}
}

// hand passes f to the sink only while the owner's settings still allow
// the stream it came on: the same node, not off, the same capture mode and
// the pin it was dialed with. A frame read before a revocation is dropped.
func (c *Clerk) hand(n *node, pin Node, f camwire.Frame) error {
	n.deliver.Lock()
	defer n.deliver.Unlock()
	c.mu.Lock()
	err := c.ready(pin.ID, n, pin.Capture)
	if err == nil && n.pin.Key != pin.Key {
		err = errRepinned
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.cfg.Frames.Frame(pin.ID, f); err != nil {
		c.log(pin.ID, "stream ended: the decoder refused a frame")
		return ErrStream
	}
	return nil
}

// gap is a stream that ended or never started: the node is silent once
// nothing has arrived for its interval.
func (c *Clerk) gap(n *node, pin Node) {
	c.mu.Lock()
	quiet := c.cfg.Now().Sub(n.last) >= pin.Interval
	c.mu.Unlock()
	if quiet {
		c.markSilent(n, pin.ID)
	}
}

func (c *Clerk) markSilent(n *node, id string) {
	c.mu.Lock()
	was := n.silent
	n.silent = true
	c.mu.Unlock()
	if !was {
		c.log(id, "silent past its interval")
		c.event(id, Silent)
	}
}

// turnOff is DEV-3's refusal: the node is off and dialed no more until
// the owner re-pins it, and the loss is logged and in STATUS (KRN-7). It
// reports false, and changes nothing, when the owner re-pinned the node
// after pin was dialed.
func (c *Clerk) turnOff(n *node, pin Node) bool {
	id := pin.ID
	c.mu.Lock()
	// A re-pin that landed after this handshake is the owner's newer word.
	stale := n.pin.Key != pin.Key
	if !stale {
		n.off = true
	}
	c.mu.Unlock()
	if stale {
		return false
	}
	c.log(id, "off: its key does not match the pin; re-pin it on the local page (KRN-7)")
	c.event(id, KeyRefused)
	return true
}

func (c *Clerk) event(id string, k Kind) {
	if err := c.emit(Event{Camera: id, Kind: k, Label: Label, Verified: true, Time: c.cfg.Now().UTC()}); err != nil {
		c.log(id, "event not delivered (KRN-7)")
	}
}

// LastStatus is the node's last status record, if one arrived.
func (c *Clerk) LastStatus(id string) (camwire.Status, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.nodes[id]
	if n == nil {
		return camwire.Status{}, false
	}
	return n.status, n.has
}

// Status is one STATUS line per camera, by ID: the camera, its state and a
// frame count, never anything the node sent.
func (c *Clerk) Status() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.nodes))
	for id := range c.nodes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		n := c.nodes[id]
		var s string
		switch {
		case n.off:
			s = "off: its key does not match the pin; re-pin it on the local page"
		case n.pin.Capture == Off:
			s = "capture off"
		case n.silent:
			s = "silent"
		case n.busy:
			s = fmt.Sprintf("streaming, %d frames", n.frames)
		default:
			s = "not streaming"
		}
		out = append(out, "camera "+id+": "+s)
	}
	return out
}
