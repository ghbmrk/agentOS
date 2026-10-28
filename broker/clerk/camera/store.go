package camera

// The camera clerk's capture store (CAM-clerk part c, CAM-retain, #3514;
// DEV-7, LOG-4). Raw capture is kept in a bounded memory ring per camera
// for consumers and live view. Nothing is written for a camera unless the
// owner set a retention for it; then its frames are sealed into segments
// under the camera's own key from the sealed store and deleted when the
// retention runs out. Disconnecting a camera destroys its key, then its
// segments and its ring. On-request capture ends with its task: the ring
// is dropped, and only a retention keeps what was written.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// Defaults for the zero values of StoreConfig.
const (
	DefaultRingFrames   = 300      // about ten seconds of video
	DefaultRingBytes    = 32 << 20 // per camera
	DefaultSegmentBytes = 8 << 20  // a segment closes at this size
	DefaultSegmentSpan  = 10 * time.Second
	DefaultWriteRate    = 4 << 20 // bytes a second, averaged over a minute
)

// MaxRetention guards the expiry arithmetic; it is not a policy limit.
const MaxRetention = 100 * 365 * 24 * time.Hour

const (
	segMagic  = "AOSCSEG1"
	saltLen   = 32
	recHead   = 1 + 8 + 4 // type, time in Unix nanoseconds, length
	segExt    = ".seg"
	tmpExt    = ".tmp" // privfile.WriteAtomic's temporary
	rateSpan  = time.Minute
	maxSegKey = 32
)

// maxSegFile bounds a segment file read back: the largest segment the
// store closes (a full buffer plus one frame) sealed, with its header.
func maxSegFile(segBytes int) int64 {
	return int64(len(segMagic)+saltLen+16+recHead+MaxFramePayload) + int64(segBytes)
}

// MaxFramePayload is the largest frame payload the store keeps.
const MaxFramePayload = camwire.MaxVideo

// SegmentSlots prefixes a camera's segment key slot in the sealed store.
// It is a device slot, so clerk.Secrets.DeviceKey lends it to one call and
// wipes it after (CLK-1).
const SegmentSlots = clerk.DeviceSlots + "camera-segments/"

// SegmentKeys holds each camera's segment key (DEV-7, CLK-1).
type SegmentKeys interface {
	// Make seals a fresh 32-byte key for camera unless it has one.
	Make(camera string) error
	// Lend lends camera's key to fn for one call and wipes it after.
	Lend(camera string, fn func(key []byte) error) error
	// Erase destroys camera's key, so its segments open no more; an
	// absent key is erased already.
	Erase(camera string) error
}

// SecretsKeys keeps segment keys in the sealed store, one static device
// slot per camera under SegmentSlots.
func SecretsKeys(s *clerk.Secrets) SegmentKeys { return secretsKeys{s} }

type secretsKeys struct{ s *clerk.Secrets }

func (k secretsKeys) Make(camera string) error {
	if k.s.Has(SegmentSlots + camera) {
		return nil
	}
	key := make([]byte, maxSegKey)
	defer clear(key)
	rand.Read(key)
	return k.s.Put(SegmentSlots+camera, clerk.KindStatic, key)
}

func (k secretsKeys) Lend(camera string, fn func(key []byte) error) error {
	return k.s.DeviceKey(SegmentSlots + camera)(fn)
}

func (k secretsKeys) Erase(camera string) error { return k.s.Remove(SegmentSlots + camera) }

// StoreConfig is the store's wiring.
type StoreConfig struct {
	// Dir holds one directory per retained camera. It must be this uid's
	// alone (privfile.Check); it is made 0700 if missing.
	Dir  string
	Keys SegmentKeys
	// RingFrames and RingBytes bound each camera's memory ring.
	RingFrames int
	RingBytes  int
	// SegmentBytes and SegmentSpan close a segment: whichever comes first.
	SegmentBytes int
	SegmentSpan  time.Duration
	// WriteRate caps the bytes a camera writes, a second, averaged over a
	// minute (design point 8). Frames past it are kept in the ring only.
	WriteRate int
	// Now, if set, is the clock frames are stamped and segments expire by.
	Now func() time.Time
	// Log, if set, gets the store's fixed lines, which name only the
	// camera, a segment and counts.
	Log func(string)
}

// The store's errors. Each is fixed text and carries nothing captured.
var (
	ErrStoreConfig = errors.New("camera: store config needs a private directory and segment keys")
	ErrRetention   = errors.New("camera: retention is zero (none) or a positive duration")
	ErrFrame       = errors.New("camera: only video and thermal frames are capture")
	ErrWrite       = errors.New("camera: segment not written")
	ErrSegment     = errors.New("camera: segment does not open")
)

// Record is one stored frame and the time the store took it.
type Record struct {
	Time  time.Time
	Frame camwire.Frame
}

// Segment names one written segment by its first and last frame's time.
type Segment struct {
	Name     string
	From, To time.Time
}

// Store keeps capture for the cameras added to it.
type Store struct {
	cfg StoreConfig

	mu   sync.Mutex
	cams map[string]*held
}

// held is one camera's capture. mu orders its frames, writes and erase;
// it is taken before Store.mu.
type held struct {
	mu        sync.Mutex
	gone      bool
	retention time.Duration
	ring      []Record
	ringBytes int
	pend      []byte // records not yet sealed
	pendFrom  time.Time
	pendTo    time.Time
	winStart  time.Time
	winBytes  int
	dropped   int // frames over the write rate since the last segment
}

// NewStore checks cfg and opens the store with no cameras. Nothing on
// disk is read or deleted until Sweep.
func NewStore(cfg StoreConfig) (*Store, error) {
	if cfg.Dir == "" || cfg.Keys == nil || cfg.RingFrames < 0 || cfg.RingBytes < 0 ||
		cfg.SegmentBytes < 0 || cfg.SegmentSpan < 0 || cfg.WriteRate < 0 {
		return nil, ErrStoreConfig
	}
	if err := os.Mkdir(cfg.Dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := privfile.Check(cfg.Dir, true); err != nil {
		return nil, err
	}
	if cfg.RingFrames == 0 {
		cfg.RingFrames = DefaultRingFrames
	}
	if cfg.RingBytes == 0 {
		cfg.RingBytes = DefaultRingBytes
	}
	if cfg.SegmentBytes == 0 {
		cfg.SegmentBytes = DefaultSegmentBytes
	}
	if cfg.SegmentSpan == 0 {
		cfg.SegmentSpan = DefaultSegmentSpan
	}
	if cfg.WriteRate == 0 {
		cfg.WriteRate = DefaultWriteRate
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Store{cfg: cfg, cams: map[string]*held{}}, nil
}

// Format prints no field, whatever the verb.
func (s *Store) Format(f fmt.State, _ rune) { fmt.Fprint(f, "camera.Store{}") }

func (s *Store) log(id, line string) {
	if s.cfg.Log != nil {
		s.cfg.Log("camera " + id + ": " + line)
	}
}

// Add takes a connected camera with the owner's retention: zero is none,
// so its capture stays in memory.
func (s *Store) Add(camera string, retention time.Duration) error {
	if !idRe.MatchString(camera) {
		return ErrNode
	}
	s.mu.Lock()
	if s.cams[camera] != nil {
		s.mu.Unlock()
		return ErrNode
	}
	h := &held{}
	s.cams[camera] = h
	s.mu.Unlock()
	if err := s.setRetention(camera, h, retention); err != nil {
		s.mu.Lock()
		delete(s.cams, camera)
		s.mu.Unlock()
		return err
	}
	return nil
}

// SetRetention records the owner's retention for camera. Zero is none:
// what is written for it is deleted now. A shorter one takes effect now.
func (s *Store) SetRetention(camera string, retention time.Duration) error {
	h, err := s.held(camera)
	if err != nil {
		return err
	}
	return s.setRetention(camera, h, retention)
}

func (s *Store) setRetention(camera string, h *held, retention time.Duration) error {
	if retention < 0 || retention > MaxRetention {
		return ErrRetention
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gone {
		return ErrUnknown
	}
	if retention > 0 {
		if err := s.cfg.Keys.Make(camera); err != nil {
			return ErrWrite
		}
	}
	h.retention = retention
	if _, err := s.sweepCamera(camera, retention, s.cfg.Now()); err != nil {
		return ErrWrite
	}
	if retention == 0 {
		// Nothing is kept, so no key is either.
		h.dropPending()
		if err := s.cfg.Keys.Erase(camera); err != nil {
			return ErrWrite
		}
	}
	return nil
}

func (s *Store) held(camera string) (*held, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.cams[camera]
	if h == nil {
		return nil, ErrUnknown
	}
	return h, nil
}

// Frame takes one frame of camera's capture: into the ring, and, with a
// retention, into the open segment. It is the clerk's FrameSink shape, so
// part (d) can hand the clerk's frames here beside the decoder.
func (s *Store) Frame(camera string, f camwire.Frame) error {
	if f.Type != camwire.TypeVideo && f.Type != camwire.TypeThermal {
		return ErrFrame
	}
	if len(f.Payload) > MaxFramePayload {
		return ErrFrame
	}
	h, err := s.held(camera)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gone {
		return ErrUnknown
	}
	now := s.cfg.Now()
	r := Record{Time: now, Frame: camwire.Frame{Type: f.Type, Payload: slices.Clone(f.Payload)}}
	h.ring = append(h.ring, r)
	h.ringBytes += len(r.Frame.Payload)
	for len(h.ring) > s.cfg.RingFrames || h.ringBytes > s.cfg.RingBytes {
		h.ringBytes -= len(h.ring[0].Frame.Payload)
		clear(h.ring[0].Frame.Payload)
		h.ring[0] = Record{}
		h.ring = h.ring[1:]
	}
	if h.retention == 0 {
		return nil
	}
	if now.Sub(h.winStart) >= rateSpan || now.Before(h.winStart) {
		h.winStart, h.winBytes = now, 0
	}
	n := recHead + len(f.Payload)
	if h.winBytes+n > s.cfg.WriteRate*int(rateSpan/time.Second) {
		h.dropped++
		return nil
	}
	h.winBytes += n
	if len(h.pend) > 0 && now.Sub(h.pendFrom) >= s.cfg.SegmentSpan {
		if err := s.seal(camera, h); err != nil {
			return err
		}
	}
	if len(h.pend) == 0 {
		h.pendFrom = now
	}
	h.pendTo = now
	h.pend = binary.BigEndian.AppendUint64(append(h.pend, byte(f.Type)), uint64(now.UnixNano()))
	h.pend = binary.BigEndian.AppendUint32(h.pend, uint32(len(f.Payload)))
	h.pend = append(h.pend, f.Payload...)
	if len(h.pend) >= s.cfg.SegmentBytes {
		return s.seal(camera, h)
	}
	return nil
}

// Recent copies camera's memory ring, oldest first: what consumers and
// live view read.
func (s *Store) Recent(camera string) ([]Record, error) {
	h, err := s.held(camera)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Record, len(h.ring))
	for i, r := range h.ring {
		out[i] = Record{Time: r.Time, Frame: camwire.Frame{Type: r.Frame.Type, Payload: slices.Clone(r.Frame.Payload)}}
	}
	return out, nil
}

// EndTask ends an on-request capture's task (DEV-7): camera's ring is
// dropped, and its open segment is written only under a retention.
func (s *Store) EndTask(camera string) error {
	h, err := s.held(camera)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropRing()
	if h.retention == 0 || len(h.pend) == 0 {
		return nil
	}
	return s.seal(camera, h)
}

// Erase is a disconnect: camera's key is destroyed first, so nothing it
// wrote opens again, then its segments, its open segment and its ring.
// The camera is forgotten; a frame for it is refused.
func (s *Store) Erase(camera string) error {
	if !idRe.MatchString(camera) {
		return ErrNode
	}
	s.mu.Lock()
	h := s.cams[camera]
	delete(s.cams, camera)
	s.mu.Unlock()
	if h != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.gone = true
		h.dropRing()
		h.dropPending()
	}
	return s.erase(camera)
}

// erase destroys camera's key and directory, whether or not it is held.
func (s *Store) erase(camera string) error {
	kerr := s.cfg.Keys.Erase(camera)
	derr := os.RemoveAll(filepath.Join(s.cfg.Dir, camera))
	if derr == nil {
		derr = privfile.SyncDir(s.cfg.Dir)
	}
	if kerr != nil || derr != nil {
		s.log(camera, "erase incomplete")
		return ErrWrite
	}
	s.log(camera, "capture erased")
	return nil
}

// Flush writes every retained camera's open segment, as before a stop.
func (s *Store) Flush() error {
	var first error
	for _, id := range s.ids() {
		h, err := s.held(id)
		if err != nil {
			continue
		}
		h.mu.Lock()
		if !h.gone && h.retention > 0 && len(h.pend) > 0 {
			if err := s.seal(id, h); err != nil && first == nil {
				first = err
			}
		}
		h.mu.Unlock()
	}
	return first
}

func (s *Store) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.cams))
	for id := range s.cams {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Sweep is the retention sweep: an open segment past its span is written;
// a segment past its camera's retention is deleted; a camera with no
// retention, or not added, keeps nothing on disk, and one not added loses
// its key too (a camera disconnected while the store was down). Run it
// after Add has taken every connected camera, then on a timer.
func (s *Store) Sweep() error {
	now := s.cfg.Now()
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for _, id := range s.ids() {
		h, err := s.held(id)
		if err != nil {
			continue
		}
		h.mu.Lock()
		if !h.gone {
			if h.retention > 0 && len(h.pend) > 0 && now.Sub(h.pendFrom) >= s.cfg.SegmentSpan {
				keep(s.seal(id, h))
			}
			n, err := s.sweepCamera(id, h.retention, now)
			keep(err)
			if n > 0 {
				s.log(id, strconv.Itoa(n)+" segments deleted at the end of their retention")
			}
		}
		h.mu.Unlock()
	}
	des, err := os.ReadDir(s.cfg.Dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		id := de.Name()
		// Under s.mu, so an Add cannot land between the check and the
		// erase and lose its new key.
		s.mu.Lock()
		switch {
		case s.cams[id] != nil:
		case !idRe.MatchString(id):
			keep(os.RemoveAll(filepath.Join(s.cfg.Dir, id)))
		default:
			keep(s.erase(id))
		}
		s.mu.Unlock()
	}
	if first != nil {
		return ErrWrite
	}
	return nil
}

var segName = regexp.MustCompile(`^([0-9a-f]{16})-([0-9a-f]{16})-([0-9a-f]{8})\` + segExt + `$`)

func parseSegment(name string) (Segment, bool) {
	m := segName.FindStringSubmatch(name)
	if m == nil {
		return Segment{}, false
	}
	from, _ := strconv.ParseUint(m[1], 16, 64)
	to, _ := strconv.ParseUint(m[2], 16, 64)
	if from > to || to > 1<<63-1 {
		return Segment{}, false
	}
	return Segment{Name: name, From: time.Unix(0, int64(from)), To: time.Unix(0, int64(to))}, true
}

// sweepCamera deletes camera's segments that retention no longer keeps,
// and any file the store did not write whole; it reports the segments
// deleted. Held under the camera's lock.
func (s *Store) sweepCamera(camera string, retention time.Duration, now time.Time) (int, error) {
	dir := filepath.Join(s.cfg.Dir, camera)
	des, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, changed := 0, false
	var first error
	for _, de := range des {
		seg, ok := parseSegment(de.Name())
		if ok && de.Type().IsRegular() && retention > 0 && now.Sub(seg.To) < retention {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, de.Name())); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		changed = true
		if ok {
			n++
		}
	}
	if changed {
		if err := privfile.SyncDir(dir); err != nil && first == nil {
			first = err
		}
	}
	if retention == 0 && first == nil {
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			first = err
		} else if err := privfile.SyncDir(s.cfg.Dir); err != nil {
			first = err
		}
	}
	return n, first
}

// Segments lists camera's written segments, oldest first.
func (s *Store) Segments(camera string) ([]Segment, error) {
	if _, err := s.held(camera); err != nil {
		return nil, err
	}
	des, err := os.ReadDir(filepath.Join(s.cfg.Dir, camera))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Segment
	for _, de := range des {
		if seg, ok := parseSegment(de.Name()); ok && de.Type().IsRegular() {
			out = append(out, seg)
		}
	}
	return out, nil
}

// segAAD binds a segment to its camera and name, so a segment moved to
// another camera or renamed to change its expiry does not open.
func segAAD(camera, name string) []byte {
	return []byte("agentos/camera/segment/v1/" + camera + "/" + name)
}

// segAEAD lends camera's key and derives the segment's own AES-256-GCM key
// from it and the segment's salt, so each segment key seals one message.
func (s *Store) segAEAD(camera string, salt []byte, fn func(cipher.AEAD) error) error {
	return s.cfg.Keys.Lend(camera, func(key []byte) error {
		if len(key) != maxSegKey {
			return ErrSegment
		}
		k, err := hkdf.Key(sha256.New, key, salt, "agentos/camera/segment/v1", 32)
		if err != nil {
			return err
		}
		defer clear(k)
		b, err := aes.NewCipher(k)
		if err != nil {
			return err
		}
		g, err := cipher.NewGCM(b)
		if err != nil {
			return err
		}
		return fn(g)
	})
}

// seal writes h's open segment and empties it, whether or not the write
// succeeds: an unwritten segment is not kept in memory past its span.
// Held under h.mu.
func (s *Store) seal(camera string, h *held) error {
	plain := h.pend
	defer func() {
		clear(plain)
		h.pend = nil
	}()
	dropped := h.dropped
	h.dropped = 0
	var tag [4]byte
	rand.Read(tag[:])
	name := fmt.Sprintf("%016x-%016x-%x%s", uint64(h.pendFrom.UnixNano()), uint64(h.pendTo.UnixNano()), tag, segExt)
	salt := make([]byte, saltLen)
	rand.Read(salt)
	var file []byte
	err := s.segAEAD(camera, salt, func(g cipher.AEAD) error {
		file = append(append([]byte(segMagic), salt...), g.Seal(nil, make([]byte, g.NonceSize()), plain, segAAD(camera, name))...)
		return nil
	})
	dir := filepath.Join(s.cfg.Dir, camera)
	if err == nil {
		switch err = os.Mkdir(dir, 0o700); {
		case errors.Is(err, os.ErrExist):
			err = privfile.Check(dir, true)
		case err == nil:
			err = privfile.SyncDir(s.cfg.Dir)
		}
	}
	if err == nil {
		err = privfile.WriteAtomic(dir, name, file, nil)
	}
	if err != nil && !errors.Is(err, privfile.ErrUnsynced) {
		s.log(camera, "segment not written")
		return ErrWrite
	}
	line := "segment " + name + " written"
	if dropped > 0 {
		line += "; " + strconv.Itoa(dropped) + " frames over the write rate kept in memory only"
	}
	s.log(camera, line)
	return nil
}

// Open reads one of camera's segments back.
func (s *Store) Open(camera string, seg Segment) ([]Record, error) {
	if _, err := s.held(camera); err != nil {
		return nil, err
	}
	if _, ok := parseSegment(seg.Name); !ok {
		return nil, ErrSegment
	}
	f, err := os.OpenFile(filepath.Join(s.cfg.Dir, camera, seg.Name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrSegment
	}
	defer f.Close()
	if err := privfile.CheckFile(f); err != nil {
		return nil, ErrSegment
	}
	fi, err := f.Stat()
	if err != nil || fi.Size() > maxSegFile(s.cfg.SegmentBytes) || fi.Size() < int64(len(segMagic)+saltLen) {
		return nil, ErrSegment
	}
	file := make([]byte, fi.Size())
	if _, err := f.ReadAt(file, 0); err != nil {
		return nil, ErrSegment
	}
	if string(file[:len(segMagic)]) != segMagic {
		return nil, ErrSegment
	}
	salt, ct := file[len(segMagic):len(segMagic)+saltLen], file[len(segMagic)+saltLen:]
	var plain []byte
	err = s.segAEAD(camera, salt, func(g cipher.AEAD) error {
		var err error
		plain, err = g.Open(nil, make([]byte, g.NonceSize()), ct, segAAD(camera, seg.Name))
		return err
	})
	if err != nil {
		return nil, ErrSegment
	}
	defer clear(plain)
	var out []Record
	for len(plain) > 0 {
		if len(plain) < recHead {
			return nil, ErrSegment
		}
		t := camwire.Type(plain[0])
		at := int64(binary.BigEndian.Uint64(plain[1:]))
		n := int(binary.BigEndian.Uint32(plain[9:]))
		plain = plain[recHead:]
		if (t != camwire.TypeVideo && t != camwire.TypeThermal) || n > len(plain) {
			return nil, ErrSegment
		}
		out = append(out, Record{Time: time.Unix(0, at), Frame: camwire.Frame{Type: t, Payload: slices.Clone(plain[:n])}})
		plain = plain[n:]
	}
	return out, nil
}

func (h *held) dropRing() {
	for i := range h.ring {
		clear(h.ring[i].Frame.Payload)
	}
	h.ring, h.ringBytes = nil, 0
}

func (h *held) dropPending() {
	clear(h.pend)
	h.pend, h.dropped = nil, 0
}
