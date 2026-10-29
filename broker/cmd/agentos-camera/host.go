package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// stateName is the connected cameras' file in the clerk's directory: the
// owner's tier-4 settings only (pin, address, shapes, capture, retention),
// never a frame or a key.
const stateName = "cameras.json"

// maxState bounds the state file read; maxCameras is the RES-2 admission
// (CAM-host-4).
const (
	maxState   = 64 << 10
	maxCameras = 8
)

// sweepEvery is how often expired capture is deleted, after the first
// sweep at start.
var sweepEvery = time.Minute

// shape is a camwire.Shape on the wire.
type shape struct {
	Width  uint16 `json:"width"`
	Height uint16 `json:"height"`
}

func (s shape) cam() camwire.Shape { return camwire.Shape{Width: s.Width, Height: s.Height} }

// record is one connected camera as the owner set it at tier 4.
type record struct {
	ID      string `json:"id"`
	Addr    string `json:"addr"`
	Key     string `json:"key"` // hex SHA-256 of the node's SubjectPublicKeyInfo (DEV-3)
	Video   shape  `json:"video"`
	Thermal shape  `json:"thermal"`
	// Capture is "off", "continuous" or "on-request" (DEV-7).
	Capture string `json:"capture"`
	// IntervalSec is the silence interval; 0 is the clerk's default.
	IntervalSec int64 `json:"interval_sec,omitempty"`
	// RetentionSec is the owner's retention; 0 keeps capture in memory only.
	RetentionSec int64 `json:"retention_sec,omitempty"`
}

// state is the file's form.
type state struct {
	Cameras []record `json:"cameras"`
	// Stopped is the last STOP the owner side relayed (KRN-7), kept so a
	// restart during a STOP opens no stream.
	Stopped bool `json:"stopped,omitempty"`
}

// listed is a node the enforcer's channel lists that is not connected
// (CAM-clerk question 4): a STATUS line, never a dial.
type listed struct {
	Addr string `json:"addr"`
	Key  string `json:"key"`
}

var modes = map[string]camera.Mode{"off": camera.Off, "continuous": camera.Continuous, "on-request": camera.OnRequest}

// The host's errors, fixed text naming nothing the node sent.
var (
	errRecord  = errors.New("camera: the camera's settings are refused")
	errExists  = errors.New("camera: a camera with that name is connected")
	errUnknown = errors.New("camera: no camera with that name is connected")
	errState   = errors.New("camera: the cameras file does not load")
)

// node reads and checks a record: the clerk's Node, pin included.
func (r record) node() (camera.Node, error) {
	ap, err := netip.ParseAddrPort(r.Addr)
	if err != nil {
		return camera.Node{}, errRecord
	}
	k, err := hex.DecodeString(r.Key)
	m, ok := modes[r.Capture]
	if err != nil || len(k) != 32 || !ok || r.IntervalSec < 0 || r.RetentionSec < 0 ||
		time.Duration(r.RetentionSec) > camera.MaxRetention/time.Second ||
		r.Video.Width == 0 || r.Video.Height == 0 {
		return camera.Node{}, errRecord
	}
	n := camera.Node{ID: r.ID, Addr: ap, Thermal: r.Thermal.cam(), Capture: m,
		Interval: time.Duration(r.IntervalSec) * time.Second}
	copy(n.Key[:], k)
	return n, nil
}

func (r record) retention() time.Duration { return time.Duration(r.RetentionSec) * time.Second }

// decoder is the decoder sandbox's feed as the host uses it
// (*camera.Decoder).
type decoder interface {
	camera.FrameSink
	Add(id string, video, thermal camwire.Shape) error
	Remove(id string)
}

// tee hands each frame to the capture store (DEV-7 retention and the ring)
// and to the decoder sandbox, in that order. A store fault ends the
// connection too: capture the owner's retention cannot keep is not taken.
type tee struct {
	store *camera.Store
	dec   decoder
}

func (t tee) Frame(id string, f camwire.Frame) error {
	if err := t.store.Frame(id, f); err != nil {
		return err
	}
	return t.dec.Frame(id, f)
}

func (t tee) Cut(id string) { t.dec.Cut(id) }

// host is the camera clerk's process state: the clerk, the store, the
// decoder, the address guard, the owner's settings file and one stream
// runner per continuous camera.
type host struct {
	dir   string
	clerk *camera.Clerk
	store *camera.Store
	dec   decoder
	guard *netguard.Policy
	log   func(string)
	// point is the core's camera client public key, for STATUS.
	point [camwire.PointLen]byte

	mu      sync.Mutex
	st      state
	listed  []listed
	ctx     context.Context
	runs    map[string]context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

// load reads the settings file: missing is no camera; any malformed
// record refuses the whole file, so a torn edit never drops a camera
// (whose capture the first sweep would then erase).
func load(dir string) (state, error) {
	f, err := os.OpenFile(filepath.Join(dir, stateName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, nil
	}
	if err != nil {
		return state{}, errState
	}
	defer f.Close()
	if privfile.CheckFile(f) != nil {
		return state{}, errState
	}
	b, err := io.ReadAll(io.LimitReader(f, maxState+1))
	if err != nil || len(b) > maxState {
		return state{}, errState
	}
	var st state
	if json.Unmarshal(b, &st) != nil {
		return state{}, errState
	}
	seen := map[string]bool{}
	for _, r := range st.Cameras {
		if _, err := r.node(); err != nil || seen[r.ID] {
			return state{}, errState
		}
		seen[r.ID] = true
	}
	return st, nil
}

// save writes the settings whole (privfile.WriteAtomic); held under h.mu.
func (h *host) save() error {
	b, err := json.Marshal(h.st)
	if err != nil {
		return err
	}
	return privfile.WriteAtomic(h.dir, stateName, b, nil)
}

// start loads the settings and adds every camera to the capture store,
// then runs the first sweep, then connects each camera to the clerk and
// its decoder and opens the continuous streams (#3625: the sweep erases
// every camera directory the store has not taken, so it runs only once
// every connected camera is in the store). A camera the clerk or the
// decoder refuses now is logged and left in the file and the store, so its
// retained capture is kept and still expires on time, and every other
// camera's sweep goes on. A camera the store refuses (its sealed key
// slot failing) refuses the start: no sweep could then run safely.
func (h *host) start(ctx context.Context) error {
	st, err := load(h.dir)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ctx, h.st, h.runs = ctx, st, map[string]context.CancelFunc{}
	for _, r := range st.Cameras {
		if err := h.store.Add(r.ID, r.retention()); err != nil {
			return fmt.Errorf("camera %s: its capture store did not open: %w", r.ID, err)
		}
	}
	if err := h.store.Sweep(); err != nil {
		h.log("camera: the first sweep failed: " + err.Error())
	}
	for _, r := range st.Cameras {
		if err := h.live(r); err != nil {
			h.log("camera " + r.ID + ": not connected at start: " + err.Error())
		}
	}
	h.pins()
	h.started = true
	for _, r := range st.Cameras {
		h.run(r)
	}
	return nil
}

// live connects r to the clerk and the decoder, undoing what it did on a
// refusal; held under h.mu.
func (h *host) live(r record) error {
	n, err := r.node()
	if err != nil {
		return err
	}
	if err := h.clerk.Add(n); err != nil {
		return err
	}
	if err := h.dec.Add(r.ID, r.Video.cam(), r.Thermal.cam()); err != nil {
		h.clerk.Remove(r.ID)
		return errRecord
	}
	return nil
}

// add connects a new camera r to the store, the clerk and the decoder,
// undoing what it did on a refusal; held under h.mu.
func (h *host) add(r record) error {
	if _, err := r.node(); err != nil {
		return err
	}
	if err := h.store.Add(r.ID, r.retention()); err != nil {
		return err
	}
	if err := h.live(r); err != nil {
		h.store.Erase(r.ID)
		return err
	}
	return nil
}

// pins hands the guard every connected camera's address and key (DEV-2,
// DEV-3), so the clerk reaches those and nothing else; held under h.mu.
func (h *host) pins() {
	var ps []netguard.Pin
	for _, r := range h.st.Cameras {
		if n, err := r.node(); err == nil {
			ps = append(ps, netguard.Pin{Kind: netguard.PinDevice, Addr: n.Addr, Key: n.Key})
		}
	}
	if err := h.guard.SetPins(ps); err != nil {
		h.log("camera: the address guard refused the cameras' pins: " + err.Error())
	}
}

// run starts r's stream runner when r is continuous and no STOP holds;
// held under h.mu.
func (h *host) run(r record) {
	if !h.started || h.st.Stopped || r.Capture != "continuous" || h.runs[r.ID] != nil {
		return
	}
	ctx, cancel := context.WithCancel(h.ctx)
	h.runs[r.ID] = cancel
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		// Run returns at once for a node turned off; its STATUS line says
		// so. A runner just ended (an owner change) may still hold the
		// node: wait for it rather than leave the camera with none.
		for {
			err := h.clerk.Run(ctx, r.ID)
			if !errors.Is(err, camera.ErrBusy) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff.Min):
			}
		}
	}()
}

// halt ends r's runner; held under h.mu.
func (h *host) halt(id string) {
	if cancel := h.runs[id]; cancel != nil {
		cancel()
		delete(h.runs, id)
	}
}

func (h *host) find(id string) int {
	return slices.IndexFunc(h.st.Cameras, func(r record) bool { return r.ID == id })
}

// connect is the owner's tier-4 connect (DEV-10): the pin, the shapes, the
// capture setting and the retention. The settings are saved before any
// stream opens.
func (h *host) connect(r record) error {
	if _, err := r.node(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.find(r.ID) >= 0 {
		return errExists
	}
	if len(h.st.Cameras) >= maxCameras {
		return camera.ErrAdmission
	}
	if err := h.add(r); err != nil {
		return err
	}
	h.st.Cameras = append(h.st.Cameras, r)
	if err := h.save(); err != nil {
		h.st.Cameras = h.st.Cameras[:len(h.st.Cameras)-1]
		h.remove(r.ID)
		return err
	}
	h.listed = slices.DeleteFunc(h.listed, func(l listed) bool { return l.Addr == r.Addr })
	h.pins()
	h.log("camera " + r.ID + ": connected by the owner, capture " + r.Capture)
	h.run(r)
	return nil
}

// remove takes id out of the clerk, the decoder and the store, erasing its
// capture; held under h.mu.
func (h *host) remove(id string) error {
	h.halt(id)
	h.clerk.Remove(id)
	h.dec.Remove(id)
	return h.store.Erase(id)
}

// disconnect is the owner's disconnect: the camera is dropped from the
// file first, so a crash before its capture is erased leaves a directory
// the next start's sweep erases (CAM-clerk-12); then its stream ends and
// its pin, key and segments go.
func (h *host) disconnect(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.find(id)
	if i < 0 {
		return errUnknown
	}
	old := slices.Clone(h.st.Cameras)
	h.st.Cameras = slices.Delete(h.st.Cameras, i, i+1)
	if err := h.save(); err != nil {
		h.st.Cameras = old
		return err
	}
	h.pins()
	err := h.remove(id)
	h.log("camera " + id + ": disconnected by the owner")
	return err
}

// update changes one camera's record with fn, saves it, and only then
// applies it with apply, so no stream opens on a setting the file does not
// hold. A failed save applies nothing. A failed apply restores the old
// record, saves it, and applies it again; apply reads only its record
// arguments, so the rollback closes what the change opened.
func (h *host) update(id string, fn func(*record), apply func(old, new record) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.find(id)
	if i < 0 {
		return errUnknown
	}
	old := h.st.Cameras[i]
	r := old
	fn(&r)
	if _, err := r.node(); err != nil {
		return err
	}
	h.st.Cameras[i] = r
	if err := h.save(); err != nil {
		h.st.Cameras[i] = old
		return err
	}
	if err := apply(old, r); err != nil {
		h.st.Cameras[i] = old
		if serr := h.save(); serr != nil {
			h.log("camera " + id + ": the old settings were not saved back: " + serr.Error())
		}
		if rerr := apply(r, old); rerr != nil {
			h.log("camera " + id + ": the old settings were not applied back: " + rerr.Error())
		}
		return err
	}
	return nil
}

// setCapture is the owner's tier-4 capture turn-on or turn-off (DEV-7). A
// stream the new setting does not allow ends at once (Clerk.SetCapture),
// and turning capture away from a mode drops that camera's memory ring.
func (h *host) setCapture(id, mode string) error {
	if _, ok := modes[mode]; !ok {
		return errRecord
	}
	// apply reads the mode from r, never from mode: a failed save
	// re-applies the old record, which must close the gate again.
	return h.update(id, func(r *record) { r.Capture = mode }, func(old, r record) error {
		if err := h.clerk.SetCapture(id, modes[r.Capture]); err != nil {
			return err
		}
		if old.Capture != r.Capture {
			h.halt(id)
			if err := h.store.EndTask(id); err != nil {
				h.log("camera " + id + ": the ring was not dropped: " + err.Error())
			}
		}
		h.log("camera " + id + ": capture " + r.Capture + " by the owner")
		h.run(r)
		return nil
	})
}

// setRetention is the owner's retention change (DEV-7); zero keeps capture
// in memory only and erases what was kept.
func (h *host) setRetention(id string, sec int64) error {
	return h.update(id, func(r *record) { r.RetentionSec = sec }, func(_, r record) error {
		return h.store.SetRetention(id, r.retention())
	})
}

// repin is the owner's tier-4 re-pin (DEV-3): the new key is pinned, the
// old one is refused, and a node turned off by a mismatch runs again.
func (h *host) repin(id, addr, key string) error {
	k, err := hex.DecodeString(key)
	if err != nil || len(k) != 32 {
		return errRecord
	}
	// A node that came back at another address is pinned there: the
	// listed node's address and key go together.
	return h.update(id, func(r *record) {
		r.Key = key
		if addr != "" {
			r.Addr = addr
		}
	}, func(old, r record) error {
		n, err := r.node()
		if err != nil {
			return err
		}
		h.halt(id)
		if old.Addr != r.Addr {
			h.clerk.Remove(id)
			if err := h.clerk.Add(n); err != nil {
				return err
			}
		} else if err := h.clerk.Repin(id, n.Key); err != nil {
			return err
		}
		h.pins()
		h.run(r)
		return nil
	})
}

// stop is the owner side's STOP relay (KRN-7): every stream ends with
// every other clerk step, and none opens until resume. It is saved first,
// so a restart during a STOP opens nothing.
func (h *host) stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.Stopped = true
	err := h.save()
	for id := range h.runs {
		h.halt(id)
	}
	h.log("camera: every stream stopped (STOP)")
	return err
}

func (h *host) resume() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.Stopped = false
	if err := h.save(); err != nil {
		h.st.Stopped = true
		return err
	}
	for _, r := range h.st.Cameras {
		h.run(r)
	}
	h.log("camera: streams resumed")
	return nil
}

// setListed replaces the nodes the enforcer's channel lists (question 4).
// A listed node is only a STATUS line: it is never dialed until the owner
// connects it on the local page.
func (h *host) setListed(ls []listed) error {
	if len(ls) > 4*maxCameras {
		return errRecord
	}
	// Each entry is put back in canonical form, so no text the enforcer's
	// channel sent reaches a STATUS line: a zone, or anything but a home
	// address, is refused.
	out := make([]listed, 0, len(ls))
	for _, l := range ls {
		ap, err := netip.ParseAddrPort(l.Addr)
		a := ap.Addr()
		if err != nil || a.Zone() != "" || !(a.IsPrivate() || a.IsLinkLocalUnicast()) {
			return errRecord
		}
		k, err := hex.DecodeString(l.Key)
		if err != nil || len(k) != 32 {
			return errRecord
		}
		out = append(out, listed{Addr: ap.String(), Key: hex.EncodeToString(k)})
	}
	h.mu.Lock()
	h.listed = out
	h.mu.Unlock()
	return nil
}

// status is the clerk's STATUS lines: the clerk's per camera, each
// camera's capture and retention, a STOP, and each listed node waiting to
// be connected, with the fingerprint's first 8 characters for the case
// label. Nothing the node sent appears.
func (h *host) status() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	if h.st.Stopped {
		out = append(out, "cameras: stopped (STOP); no stream opens until RESUME")
	}
	for _, r := range h.st.Cameras {
		ret := "memory only"
		if r.RetentionSec > 0 {
			ret = "kept " + r.retention().String()
		}
		out = append(out, fmt.Sprintf("camera %s: capture %s, %s", r.ID, r.Capture, ret))
	}
	out = append(out, h.clerk.Status()...)
	for _, l := range h.listed {
		if slices.ContainsFunc(h.st.Cameras, func(r record) bool { return r.Addr == l.Addr }) {
			continue
		}
		out = append(out, "camera node at "+l.Addr+": listed by the enforcer, key "+l.Key[:8]+"; connect it on the local page")
	}
	return out
}

// tick runs the periodic sweep and the DEV-8 flushes until ctx ends; then
// it stops every runner and writes the open segments.
func (h *host) tick(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for id := range h.runs {
				h.halt(id)
			}
			h.mu.Unlock()
			h.wg.Wait()
			if err := h.store.Flush(); err != nil {
				h.log("camera: open segments not written at stop: " + err.Error())
			}
			return
		case <-t.C:
			h.clerk.Flush()
			if err := h.store.Sweep(); err != nil {
				h.log("camera: sweep failed: " + err.Error())
			}
		}
	}
}
