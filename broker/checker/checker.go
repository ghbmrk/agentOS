// Package checker is the CH-4 checker process (SIM-split): it holds the
// owner's code-generator seed apart from the broker, the vault process and
// every key holder. The broker asks it to verify an owner code for a batch
// of high-risk acts; a verified code records one approval per act, and a
// key holder serves an irreversible act only once it redeems that act's
// approval here. So neither a compromised broker nor a compromised holder
// can approve a high-risk act alone.
//
// Three sockets, each with its own closed set and its own peer uid:
// the hand socket (the unlock step: GET /state, PUT and DELETE /secret, as
// holders, and POST /verify for the unlock's own code, which approves no
// acts), the verify socket (the broker: POST /verify; POST /revoke,
// which only withdraws approvals, as an UNDO does; POST /release, which
// lets a held approval be spent; and POST /allow, which records an
// allowed approval for an act the broker's own tier or a grid answer let
// through, one that serves an irreversible act but never a secret one)
// and the redeem socket (the key holders: POST /redeem). None reads the
// seed back.
package checker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Socket names inside the checker's run directory.
const (
	HandSocket   = "hand.sock"
	VerifySocket = "verify.sock"
	RedeemSocket = "redeem.sock"
)

// Verify limits, the same as the vault process's (CH-4): wrong codes are
// counted per bucket over a sliding VerifyWindow, and a full bucket pauses
// that bucket's checks until its oldest wrong code leaves the window.
const (
	MaxWrongCounted = 20
	MaxWrongSilent  = 10
	VerifyWindow    = 10 * time.Minute
)

// ApprovalTTL is how long an approval waits to be redeemed: the lifetime
// of a CH-10 code.
const ApprovalTTL = 15 * time.Minute

// MaxActs bounds the acts one code approves or one allow records,
// MaxAllowed the allowed approvals outstanding at once, MaxHold how long a
// held approval waits for its release before it lapses, and maxSeed the
// seed's size.
const (
	MaxActs    = 64
	MaxAllowed = 16 * MaxActs
	MaxHold    = 7 * 24 * time.Hour
	maxSeed    = 4 << 10
)

// ErrNoSeed means the unlock step has not handed the seed yet.
var ErrNoSeed = checkersock.ErrNoSeed

// errInternal hides a state-file failure from the caller.
var errInternal = errors.New("checker: internal error")

// PausedError refuses a verify until the oldest wrong code in its bucket
// leaves the window.
type PausedError = checkersock.PausedError

// Act names one request a holder sends upstream: the digest of the account
// whose login sends it (its credential name), and the request's host,
// method, path and body, each length-prefixed so no split of one field
// into the next gives the same act. Every holder shares one redeem socket,
// so the account is what keeps one account's approval from being spent by
// another's holder for the same bytes.
func Act(account, host, method, path string, body []byte) string {
	h := sha256.New()
	for _, f := range [][]byte{[]byte(account), []byte(host), []byte(method), []byte(path), body} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validAct(a string) bool {
	if len(a) != 2*sha256.Size {
		return false
	}
	_, err := hex.DecodeString(a)
	return err == nil
}

// Config configures a Checker.
type Config struct {
	// StatePath is the durable file holding the last spent step. It never
	// holds the seed.
	StatePath string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

type persisted struct {
	LastStep int64 `json:"last_step"`
}

// Checker holds the seed, the last spent step and the open approvals.
type Checker struct {
	statePath string
	now       func() time.Time

	mu           sync.Mutex
	seed         []byte
	st           persisted
	wrongCounted []time.Time
	wrongSilent  []time.Time
	approvals    map[string]window // memory only
}

// window is when an approval lapses, held while it waits for its
// release and cannot be spent, and allowed when the broker recorded it
// (Allow) rather than an owner's code: it then serves no secret act.
type window struct {
	until   time.Time
	held    bool
	allowed bool
}

// New loads the state file, if there is one, and returns a checker that
// holds no seed.
func New(cfg Config) (*Checker, error) {
	if cfg.StatePath == "" {
		return nil, errors.New("checker: no state path")
	}
	c := &Checker{statePath: cfg.StatePath, now: cfg.Now, approvals: map[string]window{}}
	if c.now == nil {
		c.now = time.Now
	}
	raw, err := os.ReadFile(cfg.StatePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &c.st); err != nil {
			return nil, fmt.Errorf("checker: state file: %w", err)
		}
	}
	return c, nil
}

// Hand gives the checker its seed, replacing any it held. b is copied.
func (c *Checker) Hand(b []byte) {
	s := append([]byte(nil), b...)
	c.mu.Lock()
	old := c.seed
	c.seed = s
	c.mu.Unlock()
	for i := range old {
		old[i] = 0
	}
}

// Drop takes the seed back, as the unlock step does at a lock, and every
// open approval with it: an approval outlives no lock (CRED-1).
func (c *Checker) Drop() {
	c.mu.Lock()
	old := c.seed
	c.seed = nil
	clear(c.approvals)
	c.mu.Unlock()
	for i := range old {
		old[i] = 0
	}
}

// Held reports whether the checker holds a seed.
func (c *Checker) Held() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seed) > 0
}

func since(ts []time.Time, cut time.Time) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	return kept
}

// Verify checks an owner code-generator code (CH-4): the current step or
// the one before, after both after and the durable last step. A match
// spends the step (on disk before the answer) and records one approval
// per act, each redeemable once within ApprovalTTL, a held act's only
// after its release (CH-10, REV-3). counted picks the bucket a wrong code is charged to.
func (c *Checker) Verify(code string, after int64, counted bool, acts []checkersock.Act) (int64, bool, error) {
	if counted {
		return c.verify(code, after, &c.wrongCounted, MaxWrongCounted, acts)
	}
	return c.verify(code, after, &c.wrongSilent, MaxWrongSilent, acts)
}

// verifyHand is the hand socket's check: the unlock's and the enrolment's
// own code. It spends the step as Verify does but charges no bucket here,
// so the broker's wrong codes never pause the owner's unlock; the vault
// process limits these codes itself (its durable cap, CH-18, and its
// enrolment bucket), and it holds the seed it handed, so a bucket here
// would bound nothing.
func (c *Checker) verifyHand(code string, after int64) (int64, bool, error) {
	return c.verify(code, after, nil, 0, nil)
}

// verify checks code; a nil bucket charges and pauses nothing.
func (c *Checker) verify(code string, after int64, bucket *[]time.Time, limit int, acts []checkersock.Act) (int64, bool, error) {
	if len(acts) > MaxActs {
		return 0, false, fmt.Errorf("checker: more than %d acts", MaxActs)
	}
	for _, a := range acts {
		if !validAct(a.Act) {
			return 0, false, errors.New("checker: malformed act")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seed) == 0 {
		return 0, false, ErrNoSeed
	}
	now := c.now()
	if bucket != nil {
		*bucket = since(*bucket, now.Add(-VerifyWindow))
		if len(*bucket) >= limit {
			return 0, false, &PausedError{Until: (*bucket)[0].Add(VerifyWindow)}
		}
	}
	step, ok := owner.MatchTOTP(c.seed, code, now, max(after, c.st.LastStep))
	if !ok {
		if bucket != nil {
			*bucket = append(*bucket, now)
		}
		return 0, false, nil
	}
	next := c.st
	next.LastStep = step
	raw, err := json.Marshal(next)
	if err != nil {
		return 0, false, errInternal
	}
	if err := durable.WriteFile(c.statePath, raw, 0o600); err != nil {
		return 0, false, errInternal
	}
	c.st = next
	c.sweepLocked(now)
	for _, a := range acts {
		if a.Held {
			c.approvals[a.Act] = window{until: now.Add(MaxHold), held: true}
		} else {
			c.approvals[a.Act] = window{until: now.Add(ApprovalTTL)}
		}
	}
	return step, true, nil
}

func (c *Checker) sweepLocked(now time.Time) {
	for a, w := range c.approvals {
		if !now.Before(w.until) {
			delete(c.approvals, a)
		}
	}
}

// Allow records an allowed approval per act, as a verified code would but
// with no code: the broker's record that its own tier, or an owner's grid
// answer, let a high-risk act through (ADP-9). It needs the seed held, so
// it outlives no lock; it never replaces an approval already open, a
// code's or another allow's; and an allowed approval serves an
// irreversible act but never a secret one (Redeem), so a broker taken over
// can let an irreversible act through but reveals no secret.
func (c *Checker) Allow(acts []checkersock.Act) error {
	if len(acts) > MaxActs {
		return fmt.Errorf("checker: more than %d acts", MaxActs)
	}
	for _, a := range acts {
		if !validAct(a.Act) {
			return errors.New("checker: malformed act")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seed) == 0 {
		return ErrNoSeed
	}
	now := c.now()
	c.sweepLocked(now)
	n := 0
	for _, w := range c.approvals {
		if w.allowed {
			n++
		}
	}
	fresh := map[string]bool{}
	for _, a := range acts {
		if _, ok := c.approvals[a.Act]; !ok {
			fresh[a.Act] = true
		}
	}
	if n+len(fresh) > MaxAllowed {
		return errTooMany
	}
	for _, a := range acts {
		if !fresh[a.Act] {
			continue
		}
		if a.Held {
			c.approvals[a.Act] = window{until: now.Add(MaxHold), held: true, allowed: true}
		} else {
			c.approvals[a.Act] = window{until: now.Add(ApprovalTTL), allowed: true}
		}
	}
	return nil
}

// errTooMany refuses an allow past MaxAllowed.
var errTooMany = fmt.Errorf("checker: more than %d allowed approvals open", MaxAllowed)

// Redeem spends act's approval: true at most once per approval, and only
// before it lapses. A try on a held approval spends nothing, and neither
// does a secret act's try on an allowed one, which it never serves.
func (c *Checker) Redeem(act string, secret bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.approvals[act]
	now := c.now()
	if !ok || w.held || (secret && w.allowed) {
		return false
	}
	delete(c.approvals, act)
	return now.Before(w.until)
}

// Revoke withdraws acts' approvals, as the owner's UNDO of a held act
// does: withdrawing only ever denies, so the broker may ask it alone.
func (c *Checker) Revoke(acts []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range acts {
		delete(c.approvals, a)
	}
}

// Release lets held approvals be spent, each within ApprovalTTL from now.
// It opens only an approval already recorded, a code's or an allow's, and
// keeps its kind, so the broker gains nothing it could not have asked for
// unheld; it asks once the item's UNDO is closed.
func (c *Checker) Release(acts []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweepLocked(now)
	for _, a := range acts {
		if w, ok := c.approvals[a]; ok && w.held {
			c.approvals[a] = window{until: now.Add(ApprovalTTL), allowed: w.allowed}
		}
	}
}

type state struct {
	Held bool `json:"held"`
}

type redeemReq struct {
	Act    string `json:"act"`
	Secret bool   `json:"secret,omitempty"`
}

const maxReq = checkersock.MaxBody

// handHandler serves the hand socket, in the holders' protocol so the
// unlock step's holder.Keeper hands the seed unchanged.
func (c *Checker) handHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state{Held: c.Held()})
	})
	mux.HandleFunc("PUT /secret", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxSeed+1))
		if err != nil || len(b) == 0 || len(b) > maxSeed {
			http.Error(w, "checker: bad seed", http.StatusBadRequest)
			return
		}
		c.Hand(b)
		for i := range b {
			b[i] = 0
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /secret", func(w http.ResponseWriter, r *http.Request) {
		c.Drop()
		w.WriteHeader(http.StatusNoContent)
	})
	// The unlock step's own code check: the step it spends is the one the
	// broker's checks spend after (CH-4), it approves nothing, and it is
	// charged to no bucket of the broker's (verifyHand).
	mux.HandleFunc("POST /verify", c.serveVerify(false))
	return mux
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, maxReq)).Decode(v)
}

// verifyHandler serves the broker's verify socket.
func (c *Checker) verifyHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", c.serveVerify(true))
	mux.HandleFunc("POST /revoke", c.serveActs(c.Revoke))
	mux.HandleFunc("POST /release", c.serveActs(c.Release))
	mux.HandleFunc("POST /allow", func(w http.ResponseWriter, r *http.Request) {
		var req checkersock.AllowRequest
		if err := decode(r, &req); err != nil {
			http.Error(w, "checker: bad request", http.StatusBadRequest)
			return
		}
		switch err := c.Allow(req.Acts); {
		case errors.Is(err, ErrNoSeed):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		case errors.Is(err, errTooMany):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case err != nil:
			http.Error(w, "checker: bad request", http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	return mux
}

// serveActs answers POST /revoke or /release with do.
func (c *Checker) serveActs(do func([]string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req checkersock.ActsRequest
		if err := decode(r, &req); err != nil || len(req.Acts) > MaxActs {
			http.Error(w, "checker: bad request", http.StatusBadRequest)
			return
		}
		for _, a := range req.Acts {
			if !validAct(a) {
				http.Error(w, "checker: bad request", http.StatusBadRequest)
				return
			}
		}
		do(req.Acts)
		w.WriteHeader(http.StatusNoContent)
	}
}

// serveVerify answers POST /verify; withActs false (the hand socket)
// refuses any act and charges no bucket.
func (c *Checker) serveVerify(withActs bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req checkersock.VerifyRequest
		if err := decode(r, &req); err != nil || (!withActs && len(req.Acts) > 0) {
			http.Error(w, "checker: bad request", http.StatusBadRequest)
			return
		}
		var step int64
		var ok bool
		var err error
		if withActs {
			step, ok, err = c.Verify(req.Code, req.After, req.Counted, req.Acts)
		} else {
			step, ok, err = c.verifyHand(req.Code, req.After)
		}
		var p *PausedError
		switch {
		case errors.As(err, &p):
			w.Header().Set(checkersock.PausedHeader, strconv.FormatInt(p.Until.Unix(), 10))
			http.Error(w, p.Error(), http.StatusTooManyRequests)
			return
		case errors.Is(err, ErrNoSeed):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		case errors.Is(err, errInternal):
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(checkersock.VerifyResponse{Step: step, OK: ok})
	}
}

// redeemHandler serves the holders' redeem socket: 204 spends an
// approval, 403 means none.
func (c *Checker) redeemHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /redeem", func(w http.ResponseWriter, r *http.Request) {
		var req redeemReq
		if err := decode(r, &req); err != nil || !validAct(req.Act) {
			http.Error(w, "checker: bad request", http.StatusBadRequest)
			return
		}
		if !c.Redeem(req.Act, req.Secret) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// Serve serves the three sockets until one listener fails; it closes all
// of them and returns the first error.
func (c *Checker) Serve(hand, verify, redeem net.Listener) error {
	lns := []net.Listener{hand, verify, redeem}
	hds := []http.Handler{c.handHandler(), c.verifyHandler(), c.redeemHandler()}
	errs := make(chan error, len(lns))
	var servers []*http.Server
	for i := range lns {
		s := &http.Server{Handler: hds[i], ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, IdleTimeout: 2 * time.Minute}
		servers = append(servers, s)
		go func(s *http.Server, ln net.Listener) { errs <- s.Serve(ln) }(s, lns[i])
	}
	err := <-errs
	for _, s := range servers {
		s.Close()
	}
	for range len(lns) - 1 {
		<-errs
	}
	return err
}

// Listen opens a unix socket at path that admits only the peer uids;
// every other connection is closed unread.
func Listen(path string, uids ...int) (net.Listener, error) {
	return sockets.ListenPeers(path, uids...)
}

// Redeemer returns a key holder's client for the redeem socket: true means
// the act's approval was spent for this request; secret marks a request
// that reveals a secret, which no allowed approval serves. Only 204 is a
// yes and only 403 a no; any other answer is an error, which the holder
// refuses.
func Redeemer(socket string) func(ctx context.Context, act string, secret bool) (bool, error) {
	hc := checkersock.UnixClient(socket)
	return func(ctx context.Context, act string, secret bool) (bool, error) {
		b, _ := json.Marshal(redeemReq{Act: act, Secret: secret})
		req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/redeem", bytes.NewReader(b))
		if err != nil {
			return false, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return false, fmt.Errorf("checker: %w", err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxReq))
		switch resp.StatusCode {
		case http.StatusNoContent:
			return true, nil
		case http.StatusForbidden:
			return false, nil
		default:
			return false, fmt.Errorf("checker: redeem: %s", resp.Status)
		}
	}
}
