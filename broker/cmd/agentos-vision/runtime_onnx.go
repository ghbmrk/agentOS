//go:build vision_onnx

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/ghbmrk/agentos/broker/vision"
)

// The runtime adapter of this build: ONNX Runtime (MIT), loaded from the
// pinned shared library in -models, runs the pinned YOLOX-Tiny on visible
// and infrared frames on the CPU; thermal frames go to heatBlobs, which
// needs no model (VIS-A27 to A29). On a frame with a person it also runs
// the pinned YuNet face detector and encodes each person's face with the
// pinned SFace (VIS-A31); Encode is SFace on an enrolment frame's one
// clear face. There is no sound model yet (part e3), so Sound answers
// ErrNoModel.
const (
	ortLibrary   = "libonnxruntime.so.1.29.0"
	detectorFile = "yolox_tiny.onnx"
	yunetFile    = "face_detection_yunet_2023mar.onnx"
	sfaceFile    = "face_recognition_sface_2021dec.onnx"
	modelsName   = "yolox-tiny-416.yunet-2023mar.sface-2021dec"
)

// modelsHash is what hello reports as the models' SHA-256: the hash of the
// pins this build was made with, the same on every box running it, so the
// trusted side can check it against the image's (part f) and the service
// chooses none of its bits.
var modelsHash = func() string {
	s := sha256.Sum256([]byte(modelPins))
	return hex.EncodeToString(s[:])
}()

var errNotLoaded = errors.New("no detector loaded")

func newRuntime(dir string, threads int) Runtime {
	return &onnxRuntime{dir: dir, threads: threads}
}

type onnxRuntime struct {
	dir     string
	threads int

	env sync.Mutex // the process's one ONNX Runtime environment

	mu  sync.Mutex
	cur *onnxLoad
}

// onnxLoad is one load's sessions (the detector, the face detector and
// the face encoder) and the runs in flight on them, so a reload can stop
// them (Runtime: a Load makes a call still running on the old load
// return).
type onnxLoad struct {
	sess, yunet, sface *ort.DynamicAdvancedSession
	mu                 sync.Mutex
	runs               map[*ort.RunOptions]bool
	gone               bool
	wg                 sync.WaitGroup
	// encodes counts the face encoder's runs, so a test can see that
	// Detect told not to encode runs none (#3792; D-207).
	encodes atomic.Int64
}

// environment starts ONNX Runtime from the pinned library once; a failed
// start is tried again at the next load.
func (r *onnxRuntime) environment() error {
	r.env.Lock()
	defer r.env.Unlock()
	if ort.IsInitialized() {
		return nil
	}
	if _, err := readPinned(r.dir, ortLibrary); err != nil {
		return err
	}
	ort.SetSharedLibraryPath(filepath.Join(r.dir, ortLibrary))
	if err := ort.InitializeEnvironment(ort.WithLogLevelFatal()); err != nil {
		return fmt.Errorf("%w: the runtime library did not start", ErrRefused)
	}
	return nil
}

func (r *onnxRuntime) Load() (Model, error) {
	if err := r.environment(); err != nil {
		return Model{}, err
	}
	var files [3][]byte
	for i, name := range []string{detectorFile, yunetFile, sfaceFile} {
		b, err := readPinned(r.dir, name)
		if err != nil {
			return Model{}, err
		}
		files[i] = b
	}
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return Model{}, errNotLoaded
	}
	defer opts.Destroy()
	if opts.SetIntraOpNumThreads(r.threads) != nil || opts.SetInterOpNumThreads(1) != nil {
		return Model{}, errNotLoaded
	}
	next := &onnxLoad{runs: map[*ort.RunOptions]bool{}}
	for _, m := range []struct {
		to      **ort.DynamicAdvancedSession
		b       []byte
		in, out []string
	}{
		{&next.sess, files[0], []string{"images"}, []string{"output"}},
		{&next.yunet, files[1], []string{"input"}, yunetOutputs},
		{&next.sface, files[2], []string{"data"}, []string{"fc1"}},
	} {
		sess, err := ort.NewDynamicAdvancedSessionWithONNXData(m.b, m.in, m.out, opts)
		if err != nil {
			next.destroy()
			return Model{}, fmt.Errorf("%w: a model did not load", ErrRefused)
		}
		*m.to = sess
	}
	r.mu.Lock()
	old := r.cur
	r.cur = next
	r.mu.Unlock()
	if old != nil {
		old.retire()
	}
	return Model{Name: modelsName, SHA256: modelsHash}, nil
}

// destroy frees the load's sessions.
func (l *onnxLoad) destroy() {
	for _, s := range []*ort.DynamicAdvancedSession{l.sess, l.yunet, l.sface} {
		if s != nil {
			s.Destroy()
		}
	}
}

// retire stops every run on l and frees its session once they return.
func (l *onnxLoad) retire() {
	l.mu.Lock()
	l.gone = true
	for ro := range l.runs {
		ro.Terminate()
	}
	l.mu.Unlock()
	go func() {
		l.wg.Wait()
		l.destroy()
	}()
}

func (l *onnxLoad) begin() (*ort.RunOptions, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gone {
		return nil, false
	}
	ro, err := ort.NewRunOptions()
	if err != nil {
		return nil, false
	}
	l.runs[ro] = true
	l.wg.Add(1)
	return ro, true
}

func (l *onnxLoad) end(ro *ort.RunOptions) {
	l.mu.Lock()
	delete(l.runs, ro)
	l.mu.Unlock()
	ro.Destroy()
	l.wg.Done()
}

// current is the load runs start on, or false before a load.
func (r *onnxRuntime) current() (*onnxLoad, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur, r.cur != nil
}

func (r *onnxRuntime) Detect(f vision.Frame, encode bool) ([]Seen, error) {
	if f.Format == vision.FormatY16 {
		return heatBlobs(f), nil
	}
	l, ok := r.current()
	if !ok {
		return nil, errNotLoaded
	}
	ro, ok := l.begin()
	if !ok {
		return nil, errNotLoaded
	}
	defer l.end(ro)
	seen, err := l.detect(f, ro)
	if err != nil {
		return nil, err
	}
	people := false
	for _, d := range seen {
		people = people || d.Class == vision.Person
	}
	if !people {
		return seen, nil
	}
	fs, err := l.faces(f, ro, yunetMinScore)
	if err != nil {
		return nil, err
	}
	enc := func(fc face) ([]float32, error) { return l.encode(f, fc, ro) }
	if !encode {
		enc = func(face) ([]float32, error) { return []float32{}, nil }
	}
	if err := encodeFaces(seen, fs, enc); err != nil {
		return nil, err
	}
	return seen, nil
}

// detect is the detector's answer on a visible or infrared frame.
func (l *onnxLoad) detect(f vision.Frame, ro *ort.RunOptions) ([]Seen, error) {
	// The input is a scaled copy of the frame: zeroed once the run is
	// over, as the service zeroes the frame (VIS-A7).
	in := make([]float32, 3*yoloxSize*yoloxSize)
	defer clear(in)
	lb := yoloxInput(f, yoloxSize, in)
	it, err := ort.NewTensor(ort.NewShape(1, 3, yoloxSize, yoloxSize), in)
	if err != nil {
		return nil, errNotLoaded
	}
	defer it.Destroy()
	ot, err := ort.NewEmptyTensor[float32](ort.NewShape(1, int64(yoloxAnchors(yoloxSize)), yoloxRow))
	if err != nil {
		return nil, errNotLoaded
	}
	defer ot.Destroy()
	if err := l.sess.RunWithOptions([]ort.Value{it}, []ort.Value{ot}, ro); err != nil {
		return nil, errors.New("detector run failed")
	}
	return yoloxDecode(ot.GetData(), yoloxSize, lb, f.Width, f.Height), nil
}

// faces is the face detector's answer on f: the faces scoring at least
// min. Its input copy and its outputs, which hold where the faces are,
// are zeroed on return.
func (l *onnxLoad) faces(f vision.Frame, ro *ort.RunOptions, min float64) ([]face, error) {
	in := make([]float32, 3*yunetSize*yunetSize)
	defer clear(in)
	lb := yunetInput(f, in)
	it, err := ort.NewTensor(ort.NewShape(1, 3, yunetSize, yunetSize), in)
	if err != nil {
		return nil, errNotLoaded
	}
	defer it.Destroy()
	outs := make([]ort.Value, len(yunetOutputs))
	data := make([][]float32, len(yunetOutputs))
	defer func() {
		for i, o := range outs {
			if o != nil {
				clear(data[i])
				o.Destroy()
			}
		}
	}()
	for i := range yunetOutputs {
		g := yunetSize / yunetStrides[i%3]
		t, err := ort.NewEmptyTensor[float32](ort.NewShape(1, int64(g*g), int64(yunetWidth[i])))
		if err != nil {
			return nil, errNotLoaded
		}
		outs[i], data[i] = t, t.GetData()
	}
	if err := l.yunet.RunWithOptions([]ort.Value{it}, outs, ro); err != nil {
		return nil, errors.New("face detector run failed")
	}
	return yunetDecode(data, lb, f.Width, f.Height, min), nil
}

// encode is SFace's encoding of the face fc of f. The aligned crop and
// the output tensor are zeroed on return; the caller owns, and zeroes,
// the copy returned (Runtime: the runtime keeps no copy).
func (l *onnxLoad) encode(f vision.Frame, fc face, ro *ort.RunOptions) ([]float32, error) {
	in := make([]float32, 3*sfaceSize*sfaceSize)
	defer clear(in)
	if !sfaceInput(f, fc, in) {
		return []float32{}, nil // no transform: an unknown face
	}
	it, err := ort.NewTensor(ort.NewShape(1, 3, sfaceSize, sfaceSize), in)
	if err != nil {
		return nil, errNotLoaded
	}
	defer it.Destroy()
	ot, err := ort.NewEmptyTensor[float32](ort.NewShape(1, sfaceDim))
	if err != nil {
		return nil, errNotLoaded
	}
	defer ot.Destroy()
	out := ot.GetData()
	defer clear(out)
	l.encodes.Add(1)
	if err := l.sface.RunWithOptions([]ort.Value{it}, []ort.Value{ot}, ro); err != nil {
		return nil, errors.New("face encoder run failed")
	}
	return append([]float32(nil), out...), nil
}

// Encode is SFace's encoding of the enrolment frame's one clear face;
// ErrNoFace when it has none, or more than one, or it is a thermal frame.
func (r *onnxRuntime) Encode(f vision.Frame) ([]float32, error) {
	if f.Format == vision.FormatY16 {
		return nil, ErrNoFace
	}
	l, ok := r.current()
	if !ok {
		return nil, errNotLoaded
	}
	ro, ok := l.begin()
	if !ok {
		return nil, errNotLoaded
	}
	defer l.end(ro)
	fs, err := l.faces(f, ro, yunetMinScore)
	if err != nil {
		return nil, err
	}
	fc, ok := clearFace(fs)
	if !ok {
		return nil, ErrNoFace
	}
	v, err := l.encode(f, fc, ro)
	if err == nil && len(v) == 0 {
		return nil, ErrNoFace
	}
	return v, err
}

// Sound has no sound model in this build (part e3).
func (r *onnxRuntime) Sound([]byte) ([]vision.Sound, error) { return nil, ErrNoModel }
