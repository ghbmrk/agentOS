// Package camera is the core's camera clerk as a library (CAM-clerk part a,
// #3514; SPEC DEV-1, DEV-2, DEV-3, DEV-7, DEV-8, DEV-10, CLK-1, KRN-7, NET-2
// Cameras and microphones, LOG-4, A16). It dials only a camera node's pinned
// address through the device guard, proves the core's client key over TLS
// 1.3 and checks the node's key against its pin before any frame is read,
// opens no stream until the owner turned capture on, reads only camwire
// frame headers and the fixed status record, and hands video and thermal
// payloads on unparsed (to the decoder sandbox, part b). A node that goes
// silent, presents another key or breaks the framing raises a device event
// through a per-camera DEV-8 limit; another key also turns the node off
// with a KRN-7 line until the owner re-pins it.
//
// No payload byte enters a log line, an event, an error or STATUS: those
// carry the camera's id, fixed phrases and counts only.
package camera

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// ClerkName is the clerk a plan step names to capture (key.Step.Clerk).
const ClerkName = "camera"

// CameraArg is the plan step's argument that names the camera.
const CameraArg = "camera"

// ClientSlot is the sealed store's slot for the core's camera client key,
// a 32-byte P-256 scalar, lent through clerk.Secrets.DeviceKey (CLK-1).
const ClientSlot = "device/camera-client"

// Defaults.
const (
	DefaultSilence    = 30 * time.Second
	DefaultTimeout    = 10 * time.Second
	DefaultMinBackoff = time.Second
	DefaultMaxBackoff = time.Minute
)

// Capture is the owner's tier-4 turn-on record for one camera (DEV-7,
// DEV-10).
type Capture uint8

const (
	// CaptureOff opens no stream.
	CaptureOff Capture = iota
	// Continuous streams whenever the host runs the camera.
	Continuous
	// OnRequest streams only inside a task whose plan step names the
	// camera with the read verb.
	OnRequest
)

// Camera is one connected node as the owner pinned it.
type Camera struct {
	// ID is the camera's name in events and log lines: lower-case letters,
	// digits and hyphens, so no device text reaches either.
	ID string
	// Addr is the node's stream port on the home network; the clerk dials
	// nothing else for it.
	Addr netip.AddrPort
	// Key is the node's device key, an uncompressed P-256 point, as the
	// enforcer listed it and the owner compared with the case label.
	Key [camwire.PointLen]byte
	// Thermal is the thermal core the node's bundle declares (the zero
	// Shape for none), never one read from the stream.
	Thermal camwire.Shape
	Capture Capture
	// Silence is the longest gap between frames before the node counts as
	// silent; 0 is DefaultSilence.
	Silence time.Duration
}

// GuardPin is the device guard's pin for the camera (DEV-2): its address,
// keyed by the SHA-256 of its SubjectPublicKeyInfo. The host sets it on the
// Guard.
func (c Camera) GuardPin() (netguard.Pin, error) {
	h, err := SPKIHash(c.Key)
	if err != nil {
		return netguard.Pin{}, err
	}
	return netguard.Pin{Kind: netguard.PinDevice, Addr: c.Addr, Key: h}, nil
}

// Loss is one KRN-7 line: a capability lost, for the log and STATUS. Its
// reason is a fixed phrase.
type Loss struct {
	Camera string
	Reason string
}

// ReasonKey is the loss when a node presents a key other than its pin.
const ReasonKey = "camera presented another key; turned off until re-pinned"

// Event kinds (devslot.Reading.Kind). Value is the number of seconds since
// the node's last frame for KindSilent, and 0 otherwise.
const (
	KindSilent    = "camera-silent"
	KindKey       = "camera-key"
	KindFault     = "camera-fault"
	KindRecovered = "camera-recovered"
)

// Op is every event's operation name.
const Op = "stream"

// Config is what the host gives the clerk.
type Config struct {
	// Guard is the home-network dial guard (DEV-2); every dial goes
	// through it with PurposeDevice, so it reaches only an address the
	// host pinned as a PinDevice (Camera.GuardPin).
	Guard *netguard.Policy
	// Lend lends the client key for one call: clerk.Secrets.DeviceKey
	// (ClientSlot).
	Lend func(fn func(key []byte) error) error
	// Sink takes device events: the kernel's device-report entry.
	Sink devhost.Sink
	// Limit is each camera's DEV-8 limit, per event kind.
	Limit devhost.Limit
	// Frames takes each video and thermal frame, unparsed: the decoder
	// sandbox's feed (part b) and the memory ring (part c). It must not
	// block, and it is the only place a payload goes.
	Frames func(camera string, f camwire.Frame)
	// Lost records a KRN-7 line. The node is off whether or not it
	// succeeds.
	Lost func(Loss) error
	// Admit is the RES-2 admission check for a new camera.
	Admit func(camera string) bool
	// Log, if set, gets fixed phrases naming a camera id only.
	Log func(msg string)
	// Now, if set, is the clock the limit and silence read.
	Now func() time.Time
	// Timeout bounds each dial and handshake; 0 is DefaultTimeout.
	Timeout time.Duration
	// MinBackoff and MaxBackoff bound the wait between dials; 0 is the
	// default.
	MinBackoff, MaxBackoff time.Duration
}

// Errors. None carries text from a node or the key.
var (
	ErrConfig    = errors.New("camera: config needs a guard, a key lender, a sink, frames, a loss recorder, admission and a limit")
	ErrCamera    = errors.New("camera: camera refused")
	ErrAddress   = errors.New("camera: address is not on the home network")
	ErrAdmission = errors.New("camera: admission refused a new camera")
	ErrUnknown   = errors.New("camera: no such camera")
	ErrOff       = errors.New("camera: node is off until re-pinned")
	ErrCapture   = errors.New("camera: capture is not turned on for this")
	ErrStep      = errors.New("camera: plan step does not name this camera to read in a task")
	ErrBusy      = errors.New("camera: camera already streaming")
	ErrSpoofed   = errors.New("camera: node presented another key")
	ErrRemoved   = errors.New("camera: camera disconnected or changed")
)

var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// Clerk runs the core's camera streams, one connection per camera.
type Clerk struct {
	cfg Config
	lim *limiter

	mu   sync.Mutex
	cams map[string]*cam
}

// cam is one camera's state.
type cam struct {
	Camera
	off    bool
	status camwire.Status
	seen   bool // a status frame has arrived
	// run is the running stream, nil when none runs.
	run *slot
}

// slot is one running stream: its cancel and, on request, its task.
type slot struct {
	cancel context.CancelCauseFunc
	task   string
}

// New checks cfg and returns the clerk.
func New(cfg Config) (*Clerk, error) {
	if cfg.Guard == nil || cfg.Lend == nil || cfg.Sink == nil || cfg.Frames == nil ||
		cfg.Lost == nil || cfg.Admit == nil || cfg.Limit.Burst < 1 || cfg.Limit.Window <= 0 {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = DefaultMinBackoff
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(DefaultMaxBackoff, cfg.MinBackoff)
	}
	c := &Clerk{cfg: cfg, cams: map[string]*cam{}}
	c.lim = &limiter{limit: cfg.Limit, now: cfg.Now, sink: cfg.Sink, win: map[string]*window{}}
	return c, nil
}

// Format prints no field, whatever the verb.
func (c *Clerk) Format(f fmt.State, _ rune) { fmt.Fprint(f, "camera.Clerk{}") }

func (c *Clerk) log(msg, id string) {
	if c.cfg.Log != nil {
		c.cfg.Log(msg + ": " + id)
	}
}

// homeAddr admits a unicast address on the home network only: private or
// link-local IPv4, unique-local or link-local IPv6 (DEV-2, NET-2).
func homeAddr(ap netip.AddrPort) bool {
	a := ap.Addr().Unmap()
	if !ap.IsValid() || ap.Port() == 0 || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() && a.As4()[3] == 255 {
		return false
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}

func check(cm Camera) error {
	if !idRe.MatchString(cm.ID) {
		return ErrCamera
	}
	if !homeAddr(cm.Addr) {
		return ErrAddress
	}
	if _, err := SPKIHash(cm.Key); err != nil {
		return ErrCamera
	}
	if cm.Thermal != (camwire.Shape{}) && (cm.Thermal.Width == 0 || cm.Thermal.Height == 0 ||
		camwire.ThermalHeaderLen+2*uint64(cm.Thermal.Width)*uint64(cm.Thermal.Height) > camwire.MaxThermal) {
		return ErrCamera
	}
	if cm.Capture > OnRequest || cm.Silence < 0 {
		return ErrCamera
	}
	return nil
}

// Set connects a camera or changes its settings (the tier-4 connect and
// turn-on, DEV-10). A new camera passes admission first (RES-2). It keeps
// the camera's off mark and, for a camera already known, its key: a key
// changes only through Repin. Any change ends a running stream.
func (c *Clerk) Set(cm Camera) error {
	if err := check(cm); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.cams[cm.ID]
	if old == nil {
		if !c.cfg.Admit(cm.ID) {
			c.log("admission refused a camera", cm.ID)
			return ErrAdmission
		}
		c.cams[cm.ID] = &cam{Camera: cm}
		c.log("camera connected", cm.ID)
		return nil
	}
	if cm.Key != old.Key {
		return ErrCamera
	}
	old.stop(ErrRemoved)
	old.Camera = cm
	return nil
}

// Repin replaces a camera's pinned key (tier 4) and clears its off mark;
// the old key is refused from then on.
func (c *Clerk) Repin(id string, k [camwire.PointLen]byte) error {
	if _, err := SPKIHash(k); err != nil {
		return ErrCamera
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cm := c.cams[id]
	if cm == nil {
		return ErrUnknown
	}
	cm.stop(ErrRemoved)
	cm.Key, cm.off = k, false
	c.log("camera re-pinned", id)
	return nil
}

// Remove disconnects a camera: its stream ends and the clerk forgets it
// (part c erases its segments).
func (c *Clerk) Remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cm := c.cams[id]; cm != nil {
		cm.stop(ErrRemoved)
		delete(c.cams, id)
		c.log("camera disconnected", id)
	}
}

// Off reports whether a camera is off until re-pinned.
func (c *Clerk) Off(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cm := c.cams[id]
	return cm != nil && cm.off
}

// Status is the camera's last status record, if one has arrived. It holds
// numbers only.
func (c *Clerk) Status(id string) (camwire.Status, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cm := c.cams[id]
	if cm == nil {
		return camwire.Status{}, false
	}
	return cm.status, cm.seen
}

// Flush emits the coalesced events of windows that have ended; the host
// calls it on a timer (DEV-8).
func (c *Clerk) Flush() error { return c.lim.flush() }

func (cm *cam) stop(cause error) {
	if cm.run != nil {
		cm.run.cancel(cause)
		cm.run = nil
	}
}

// Run streams a camera whose capture is continuous until ctx ends, the
// camera changes, or its node presents another key (ErrSpoofed). It
// redials with backoff after silence or a fault.
func (c *Clerk) Run(ctx context.Context, id string) error {
	ctx, s, cm, err := c.begin(ctx, id, func(cm *cam) error {
		if cm.Capture != Continuous {
			return ErrCapture
		}
		return nil
	}, "")
	if err != nil {
		return err
	}
	defer c.end(id, s)
	return c.loop(ctx, cm)
}

// Capture streams a camera whose capture is on request for one plan step:
// the read verb, this clerk, a task, and the camera named by its argument.
// The stream ends with ctx or EndTask(step.Task). The step is one the
// kernel admitted; this checks only that it names this camera.
func (c *Clerk) Capture(ctx context.Context, id string, step key.Step) error {
	if step.Verb != key.Read || step.Clerk != ClerkName || step.Task == "" || step.Args[CameraArg].Value != id {
		return ErrStep
	}
	ctx, s, cm, err := c.begin(ctx, id, func(cm *cam) error {
		if cm.Capture != OnRequest {
			return ErrCapture
		}
		return nil
	}, step.Task)
	if err != nil {
		return err
	}
	defer c.end(id, s)
	return c.loop(ctx, cm)
}

// EndTask ends the on-request streams of a task.
func (c *Clerk) EndTask(task string) {
	if task == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cm := range c.cams {
		if cm.run != nil && cm.run.task == task {
			cm.stop(ErrRemoved)
		}
	}
}

// begin claims a camera's one stream slot.
func (c *Clerk) begin(ctx context.Context, id string, gate func(*cam) error, task string) (context.Context, *slot, Camera, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cm := c.cams[id]
	switch {
	case cm == nil:
		return nil, nil, Camera{}, ErrUnknown
	case cm.off:
		return nil, nil, Camera{}, ErrOff
	case cm.run != nil:
		return nil, nil, Camera{}, ErrBusy
	}
	if err := gate(cm); err != nil {
		return nil, nil, Camera{}, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	cm.run = &slot{cancel: cancel, task: task}
	return ctx, cm.run, cm.Camera, nil
}

// end releases the camera's slot if s still holds it; a stop may already
// have cleared it, and a newer stream may hold it since.
func (c *Clerk) end(id string, s *slot) {
	s.cancel(nil)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cm := c.cams[id]; cm != nil && cm.run == s {
		cm.run = nil
	}
}

// loop is one camera's dial, read and redial cycle.
func (c *Clerk) loop(ctx context.Context, cm Camera) error {
	silence := cm.Silence
	if silence == 0 {
		silence = DefaultSilence
	}
	last := c.cfg.Now()
	silent := false
	backoff := c.cfg.MinBackoff
	for {
		if err := ctx.Err(); err != nil {
			return cause(ctx)
		}
		conn, err := c.dial(ctx, cm)
		switch {
		case errors.Is(err, ErrSpoofed):
			c.turnOff(cm)
			return ErrSpoofed
		case err == nil:
			n, rerr := c.read(ctx, conn, cm, silence, &last, &silent)
			conn.Close()
			if ctx.Err() != nil {
				return cause(ctx)
			}
			fault := !errors.Is(rerr, errSilent) && !errors.Is(rerr, io.EOF)
			if fault {
				c.log("camera stream ended on a framing fault", cm.ID)
				c.event(cm.ID, KindFault, 0)
			} else if n > 0 {
				// Only a stream that ended cleanly resets the wait, so a
				// node that faults after each good frame keeps backing off.
				backoff = c.cfg.MinBackoff
			}
		default:
			if ctx.Err() != nil {
				return cause(ctx)
			}
			c.log("camera dial failed", cm.ID)
		}
		if gap := c.cfg.Now().Sub(last); !silent && gap >= silence {
			silent = true
			c.log("camera silent", cm.ID)
			c.event(cm.ID, KindSilent, int64(gap/time.Second))
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return cause(ctx)
		case <-t.C:
		}
		backoff = min(backoff*2, c.cfg.MaxBackoff)
	}
}

func cause(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return ctx.Err()
}

var errSilent = errors.New("camera: silent past the interval")

// read reads frames until the stream fails, ctx ends, or no frame arrives
// within silence. It returns how many frames it read.
func (c *Clerk) read(ctx context.Context, conn net.Conn, cm Camera, silence time.Duration, last *time.Time, silent *bool) (int, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	r := &lastErr{r: conn}
	n := 0
	for {
		if err := conn.SetReadDeadline(time.Now().Add(silence)); err != nil {
			return n, err
		}
		f, st, err := readOne(r, cm.Thermal)
		if err != nil {
			// The codec reports a read cut by the deadline as a short
			// frame; the transport's own error tells silence apart.
			var ne net.Error
			if errors.As(r.err, &ne) && ne.Timeout() {
				return n, errSilent
			}
			return n, err
		}
		n++
		*last = c.cfg.Now()
		if *silent {
			*silent = false
			c.log("camera recovered", cm.ID)
			c.event(cm.ID, KindRecovered, 0)
		}
		if st != nil {
			c.setStatus(cm.ID, *st)
			continue
		}
		c.cfg.Frames(cm.ID, f)
	}
}

// readOne reads one frame as the core's stream channel takes it: video and
// thermal frames come back unparsed past camwire's header and shape checks,
// and a status frame comes back decoded instead. Anything else is an error
// that ends the connection.
func readOne(r io.Reader, thermal camwire.Shape) (camwire.Frame, *camwire.Status, error) {
	f, err := camwire.ReadFrame(r, camwire.ToCore, thermal)
	if err != nil {
		return camwire.Frame{}, nil, err
	}
	switch f.Type {
	case camwire.TypeStatus:
		st, err := camwire.ParseStatus(f.Payload)
		if err != nil {
			return camwire.Frame{}, nil, err
		}
		return camwire.Frame{}, &st, nil
	case camwire.TypeVideo, camwire.TypeThermal:
		return f, nil, nil
	}
	return camwire.Frame{}, nil, camwire.ErrType
}

// lastErr keeps the transport's last read error.
type lastErr struct {
	r   io.Reader
	err error
}

func (l *lastErr) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if err != nil {
		l.err = err
	}
	return n, err
}

func (c *Clerk) setStatus(id string, st camwire.Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cm := c.cams[id]; cm != nil {
		cm.status, cm.seen = st, true
	}
}

// turnOff marks the node off, writes the KRN-7 line and raises the key
// event (brief question 3). A camera re-pinned since the dial is left on:
// the key refused was not its pin any more.
func (c *Clerk) turnOff(dialed Camera) {
	id := dialed.ID
	c.mu.Lock()
	cm := c.cams[id]
	if cm == nil || cm.Key != dialed.Key {
		c.mu.Unlock()
		return
	}
	cm.off = true
	c.mu.Unlock()
	c.log("camera presented another key; turned off", id)
	if err := c.cfg.Lost(Loss{Camera: id, Reason: ReasonKey}); err != nil {
		c.log("camera loss line not recorded", id)
	}
	c.event(id, KindKey, 0)
}

func (c *Clerk) event(id, kind string, v int64) {
	if err := c.lim.emit(id, kind, v); err != nil {
		c.log("camera event not delivered", id)
	}
}
