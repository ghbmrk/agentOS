// Package codecheck is the CH-4 checker on the new core (MIG-4-exit-c2,
// D-226): the one process that holds the owner's code-generator seed (CLK-1
// exceptions). The seed comes only from the unlock step's sealed hand-off,
// opened under the key the kernel hands the checker at each start
// (handoff.OpenCodeSeed), so a checker started without it verifies nothing.
// A verified code spends its step, on disk before the answer, and signs one
// approval of the exact held steps the caller named (kernel.SignCode),
// which the kernel admits against the checker's key it pinned at boot
// (kernel.ApproveCode). It keeps no approvals and redeems nothing: the
// kernel's log is where an approval is spent.
//
// One socket, verify.sock, admits only the owner channel's uid (agentosd):
// POST /verify. Nothing reads the seed back.
package codecheck

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/codecheck/totp"
	"github.com/ghbmrk/agentos/broker/clerk/codecheck/wire"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// VerifySocket is the socket's name in the checker's run directory.
const VerifySocket = "verify.sock"

// The lockout (CH-4), as the old checker kept it: wrong codes are counted
// per bucket over a sliding Window, and a full bucket pauses that bucket's
// checks until its oldest wrong code leaves the window. Counted codes are
// the owner's own answers; silent ones are those the owner channel did not
// ask for (a stray number in a text), so they cannot pause the owner.
const (
	MaxWrongCounted = 20
	MaxWrongSilent  = 10
	Window          = 10 * time.Minute
)

var (
	ErrNoSeed = wire.ErrNoSeed
	errSteps  = fmt.Errorf("codecheck: at most %d steps", kernel.MaxCodeSteps)
	errState  = errors.New("codecheck: internal error")
)

// PausedError refuses a check until the oldest wrong code in its bucket
// leaves the window.
type PausedError = wire.PausedError

// Config configures a Checker.
type Config struct {
	// StatePath holds the last spent step, never the seed.
	StatePath string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

type persisted struct {
	LastStep int64 `json:"last_step"`
}

// Checker holds the seed, its signing key and the last spent step.
type Checker struct {
	dir, name string
	now       func() time.Time

	mu      sync.Mutex
	seed    []byte
	sign    ed25519.PrivateKey
	last    int64
	counted []time.Time
	silent  []time.Time
}

// New reads the state file, if there is one, and returns a checker that
// holds no seed.
func New(cfg Config) (*Checker, error) {
	if !filepath.IsAbs(cfg.StatePath) {
		return nil, errors.New("codecheck: the state file is an absolute path")
	}
	c := &Checker{dir: filepath.Dir(cfg.StatePath), name: filepath.Base(cfg.StatePath), now: cfg.Now}
	if c.now == nil {
		c.now = time.Now
	}
	raw, err := os.ReadFile(cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(raw, &p); err != nil || p.LastStep < 0 {
		return nil, fmt.Errorf("codecheck: the state file %s does not read", cfg.StatePath)
	}
	c.last = p.LastStep
	return c, nil
}

// Open gives the checker its seed from blob, the unlock step's sealed
// hand-off, under the checker's clerk key k: k's sealer opens the seed and
// k's signer signs approvals. The step the seed carries (its confirming
// code's) is spent here too. k is the caller's to wipe.
func (c *Checker) Open(sealer []byte, sign ed25519.PrivateKey, blob []byte) error {
	s, err := handoff.OpenCodeSeed(sealer, blob)
	if err != nil {
		return err
	}
	if len(sign) != ed25519.PrivateKeySize {
		s.Wipe()
		return errors.New("codecheck: no signing key")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.seed)
	clear(c.sign)
	c.seed, c.sign = s.Seed, append(ed25519.PrivateKey(nil), sign...)
	c.last = max(c.last, s.Step)
	return nil
}

// Held reports whether the checker holds a seed.
func (c *Checker) Held() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seed) > 0
}

// Public is the key the checker signs approvals with; nil while it holds
// no seed.
func (c *Checker) Public() ed25519.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sign) == 0 {
		return nil
	}
	return c.sign.Public().(ed25519.PublicKey)
}

func within(ts []time.Time, cut time.Time) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	return kept
}

// Verify checks an owner code (CH-4): the current 30-second step or the one
// before, after both after and the last spent step. A match spends the step,
// on disk before the answer, and with steps signs one approval of exactly
// them (CH-10's one code per batch); with none it approves nothing, as for
// a session's code (CH-14). counted picks the bucket a wrong code is
// charged to.
func (c *Checker) Verify(code string, after int64, counted bool, steps []kernel.CodeStep) (wire.Result, error) {
	if len(steps) > kernel.MaxCodeSteps {
		return wire.Result{}, errSteps
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seed) == 0 {
		return wire.Result{}, ErrNoSeed
	}
	bucket, limit := &c.silent, MaxWrongSilent
	if counted {
		bucket, limit = &c.counted, MaxWrongCounted
	}
	now := c.now()
	*bucket = within(*bucket, now.Add(-Window))
	if len(*bucket) >= limit {
		return wire.Result{}, &PausedError{Until: (*bucket)[0].Add(Window)}
	}
	step, ok := totp.Match(c.seed, code, now, max(after, c.last))
	if !ok {
		*bucket = append(*bucket, now)
		return wire.Result{}, nil
	}
	raw, _ := json.Marshal(persisted{LastStep: step})
	if err := privfile.WriteAtomic(c.dir, c.name, raw, nil); err != nil {
		return wire.Result{}, errState
	}
	c.last = step
	r := wire.Result{Step: step, OK: true}
	if len(steps) > 0 {
		a := kernel.SignCode(c.sign, steps)
		r.Approval = &a
	}
	return r, nil
}

// Handler serves verify.sock: POST /verify alone.
func (c *Checker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		var req wire.Request
		if err := json.NewDecoder(io.LimitReader(r.Body, wire.MaxBody)).Decode(&req); err != nil {
			http.Error(w, "codecheck: bad request", http.StatusBadRequest)
			return
		}
		res, err := c.Verify(req.Code, req.After, req.Counted, req.Steps)
		var p *PausedError
		switch {
		case errors.As(err, &p):
			w.Header().Set(wire.PausedHeader, strconv.FormatInt(p.Until.Unix(), 10))
			http.Error(w, p.Error(), http.StatusTooManyRequests)
		case errors.Is(err, ErrNoSeed):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		case errors.Is(err, errState):
			http.Error(w, err.Error(), http.StatusInternalServerError)
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(res)
		}
	})
	return mux
}

// Serve serves ln until it fails.
func (c *Checker) Serve(ln net.Listener) error {
	s := &http.Server{Handler: c.Handler(), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, IdleTimeout: 2 * time.Minute}
	return s.Serve(ln)
}

// Listen opens verify.sock at path for uid alone; every other connection is
// closed unread.
func Listen(path string, uid int) (net.Listener, error) { return sockets.ListenPeers(path, uid) }
