//go:build vision_onnx

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/ghbmrk/agentos/broker/vision"
)

// The runtime adapter of this build: ONNX Runtime (MIT), loaded from the
// pinned shared library in -models, runs the pinned YOLOX-Tiny on visible
// and infrared frames on the CPU; thermal frames go to heatBlobs, which
// needs no model (VIS-A27 to A29). There is no face or sound model yet
// (parts e2 and e3), so Encode and Sound answer ErrNoModel.
const (
	ortLibrary   = "libonnxruntime.so.1.29.0"
	detectorFile = "yolox_tiny.onnx"
	detectorName = "yolox-tiny-416"
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

// onnxLoad is one loaded detector session and the runs in flight on it,
// so a reload can stop them (Runtime: a Load makes a call still running
// on the old load return).
type onnxLoad struct {
	sess *ort.DynamicAdvancedSession
	mu   sync.Mutex
	runs map[*ort.RunOptions]bool
	gone bool
	wg   sync.WaitGroup
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
	b, err := readPinned(r.dir, detectorFile)
	if err != nil {
		return Model{}, err
	}
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return Model{}, errNotLoaded
	}
	defer opts.Destroy()
	if opts.SetIntraOpNumThreads(r.threads) != nil || opts.SetInterOpNumThreads(1) != nil {
		return Model{}, errNotLoaded
	}
	sess, err := ort.NewDynamicAdvancedSessionWithONNXData(b, []string{"images"}, []string{"output"}, opts)
	if err != nil {
		return Model{}, fmt.Errorf("%w: the detector did not load", ErrRefused)
	}
	next := &onnxLoad{sess: sess, runs: map[*ort.RunOptions]bool{}}
	r.mu.Lock()
	old := r.cur
	r.cur = next
	r.mu.Unlock()
	if old != nil {
		old.retire()
	}
	return Model{Name: detectorName, SHA256: modelsHash}, nil
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
		l.sess.Destroy()
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

func (r *onnxRuntime) Detect(f vision.Frame) ([]Seen, error) {
	if f.Format == vision.FormatY16 {
		return heatBlobs(f), nil
	}
	r.mu.Lock()
	l := r.cur
	r.mu.Unlock()
	if l == nil {
		return nil, errNotLoaded
	}
	ro, ok := l.begin()
	if !ok {
		return nil, errNotLoaded
	}
	defer l.end(ro)
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

// Encode has no face model in this build (part e2).
func (r *onnxRuntime) Encode(vision.Frame) ([]float32, error) { return nil, ErrNoModel }

// Sound has no sound model in this build (part e3).
func (r *onnxRuntime) Sound([]byte) ([]vision.Sound, error) { return nil, ErrNoModel }
