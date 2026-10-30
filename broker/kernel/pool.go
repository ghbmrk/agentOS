package kernel

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Usage pools (RES-5, RES-5a). A plan's provider meters it in windows (a
// 5-hour limit, a week), each with its own share used and its own reset
// time. The log holds every window's figure, the owner's reserve, and a
// lowering of the reserve still in its hold. Names stay in the image's
// declaration: the log names a pool and its windows by ID only.

// PoolWindowMS is the window a pool is declared to reset over (RES-5): the
// cooldown of a full window whose reading gave no usable reset time.
const PoolWindowMS = 5 * 3600 * 1000

// PoolFull is a whole pool, in per mille.
const PoolFull = 1000

// SpentKeepMS is how far back State.Spent answers: two days, so a day's
// figure in any time zone is whole, and state does not grow with the log.
const SpentKeepMS = 2 * key.DayMS

// ErrReserveSig refuses a lowering of the reserve no live passkey signed over
// ReserveHash: it is a widening (KEY-4, KEY-6). It also tells the owner side
// that the change is well formed and the challenge is next.
var ErrReserveSig = errors.New("kernel: lowering what is kept for you needs your passkey")

// Window is what the log knows of one of a pool's windows.
type Window struct{ Used, ResetAt int64 }

// WindowReading is the provider's figure for one window: per mille used and
// the reset time in ms.
type WindowReading struct {
	Window  string `json:"window"`
	Used    int64  `json:"used"`
	ResetAt int64  `json:"reset_at"`
}

// Lowering is a signed lowering of the reserve, live from Live (its entry's
// time plus GrantHold) unless a raise cancels it first.
type Lowering struct{ To, Live int64 }

// Pool is what the log knows of one usage pool: each window, the owner's
// reserve, a lowering in its hold, and how many times the reserve changed,
// which a lowering's signature names.
type Pool struct {
	Windows  map[string]Window
	Reserve  int64
	Lowering *Lowering
	Changes  int
}

// PendingReserve is a lowering still in its hold, for the owner's notice.
type PendingReserve struct {
	Pool     string
	From, To int64
	Live     int64
}

type (
	poolRead struct {
		Pool    string          `json:"pool"`
		Windows []WindowReading `json:"windows"`
	}
	// poolReset reopens one window at the reset time the provider gave: it
	// clears the reading, so it widens and needs an anchor (RES-5, KRN-7).
	poolReset struct {
		Pool   string `json:"pool"`
		Window string `json:"window"`
	}
	poolReserve struct {
		Pool    string `json:"pool"`
		Reserve int64  `json:"reserve"` // per mille of the pool kept for the owner
	}
	poolLowered struct {
		Pool    string       `json:"pool"`
		Reserve int64        `json:"reserve"`
		Cosigns []key.Cosign `json:"cosigns"`
	}
	spentRec struct {
		At     int64
		Route  string
		Amount int64
	}
)

// ReserveHash names lowering pool's reserve from from to to as its n-th
// reserve change (Pool.Changes), so a signature never replays.
func ReserveHash(n int, pool string, from, to int64) [32]byte {
	return sha256.Sum256(fmt.Appendf([]byte("agentos.reserve.v1\x00"), "%d\x00%q\x00%d\x00%d", n, pool, from, to))
}

// live is the pool as it stands at t: a lowering past its hold is the reserve.
func (p Pool) live(t int64) Pool {
	if p.Lowering != nil && t >= p.Lowering.Live {
		p.Reserve, p.Lowering = p.Lowering.To, nil
	}
	return p
}

// closed reports whether window w of p, at reserve, admits no work.
func closed(w Window, reserve int64) bool { return w.Used+reserve >= PoolFull }

// PoolOpen reports whether work may draw on a pool at now: every window
// below the owner's reserve.
func (s *State) PoolOpen(now int64, name string) bool {
	p := s.Pools[name].live(now)
	if p.Reserve >= PoolFull {
		return false
	}
	for _, w := range p.Windows {
		if closed(w, p.Reserve) {
			return false
		}
	}
	return true
}

// WindowDue reports whether a window at the reserve has passed the reset
// time the provider gave, which is its cooldown. The reopening is a logged
// widening.
func (s *State) WindowDue(now int64, name, window string) bool {
	p := s.Pools[name].live(now)
	w, ok := p.Windows[window]
	return ok && closed(w, p.Reserve) && w.ResetAt > 0 && now >= w.ResetAt
}

// PendingReserves lists the lowerings still in their hold, by pool.
func (s *State) PendingReserves(now int64) []PendingReserve {
	var out []PendingReserve
	for name, p := range s.Pools {
		if l := p.Lowering; l != nil && now < l.Live {
			out = append(out, PendingReserve{name, p.Reserve, l.To, l.Live})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pool < out[j].Pool })
	return out
}

// Spent is metered spend per route, in minor units, from model.used entries
// at or after since. It answers for the last SpentKeepMS only.
func (s *State) Spent(since int64) map[string]int64 {
	out := map[string]int64{}
	for _, r := range s.spent {
		if r.At >= since {
			out[r.Route] += r.Amount
		}
	}
	return out
}

func (s *State) spend(at int64, route string, amount int64) {
	s.spent = append(s.spent, spentRec{at, route, amount})
	i := slices.IndexFunc(s.spent, func(r spentRec) bool { return r.At >= at-SpentKeepMS })
	if i < 0 { // the span's start wrapped: a time near the int64 floor keeps nothing
		i = len(s.spent)
	}
	s.spent = s.spent[i:]
}

// lowerOK is the check a lowering passes at at, live and on replay: a live
// passkey's signature over ReserveHash, and two, one an anchor, when the
// box's usable share grows past the owner's line (KEY-4, D-146).
func (s *State) lowerOK(at int64, b poolLowered) error {
	p := s.Pools[b.Pool].live(at)
	if b.Reserve < 0 || b.Reserve >= p.Reserve {
		return errors.New("kernel: not a lowering of the reserve")
	}
	h := ReserveHash(p.Changes, b.Pool, p.Reserve, b.Reserve)
	owners := s.Passkeys()
	signed := false
	for _, c := range b.Cosigns {
		signed = signed || key.In(owners, c.By) && c.Over(h)
	}
	if !signed {
		return ErrReserveSig
	}
	if over(PoolFull-b.Reserve, PoolFull-p.Reserve, s.line()) && !key.Approved(owners, s.Anchors, h, nil, b.Cosigns) {
		return ErrNeedsCosign
	}
	return nil
}

// applyPool folds a pool entry. One that fails its check, written past the
// kernel, changes nothing.
func (s *State) applyPool(e Entry) error {
	switch e.Type {
	case TPoolRead:
		b, err := body[poolRead](e)
		if err != nil {
			return err
		}
		p := s.Pools[b.Pool].live(e.At)
		ws := map[string]Window{}
		for id, w := range p.Windows {
			ws[id] = w
		}
		for _, r := range b.Windows {
			if r.Used < 0 || r.Used > PoolFull {
				continue
			}
			old, ok := ws[r.Window]
			if ok && closed(old, p.Reserve) {
				// A reading can only narrow a window at the reserve: it
				// reopens at its reset time.
				ws[r.Window] = Window{max(old.Used, r.Used), max(old.ResetAt, r.ResetAt)}
				continue
			}
			ws[r.Window] = Window{r.Used, r.ResetAt}
		}
		p.Windows = ws
		s.Pools[b.Pool] = p
	case TPoolReset:
		b, err := body[poolReset](e)
		if err != nil {
			return err
		}
		p := s.Pools[b.Pool].live(e.At)
		if _, ok := p.Windows[b.Window]; ok {
			ws := map[string]Window{}
			for id, w := range p.Windows {
				ws[id] = w
			}
			ws[b.Window] = Window{}
			p.Windows = ws
		}
		s.Pools[b.Pool] = p
	case TReserveUp:
		b, err := body[poolReserve](e)
		if err != nil {
			return err
		}
		p := s.Pools[b.Pool].live(e.At)
		if b.Reserve >= p.Reserve && b.Reserve <= PoolFull {
			p.Reserve, p.Lowering, p.Changes = b.Reserve, nil, p.Changes+1
			s.Pools[b.Pool] = p
		}
	case TReserveDown:
		b, err := body[poolLowered](e)
		if err != nil {
			return err
		}
		if s.lowerOK(e.At, b) == nil {
			p := s.Pools[b.Pool].live(e.At)
			p.Lowering, p.Changes = &Lowering{b.Reserve, e.At + GrantHold}, p.Changes+1
			s.Pools[b.Pool] = p
		}
	}
	return nil
}

// resetIfDue logs the reopening of each window at the reserve whose reset
// time the provider gave has passed, so a restart that loses it closes the
// window again (RES-5, KRN-7).
func (k *Kernel) resetIfDue(now int64, pool string) error {
	var due []string
	for id := range k.s.Pools[pool].Windows {
		if k.s.WindowDue(now, pool, id) {
			due = append(due, id)
		}
	}
	sort.Strings(due)
	for _, id := range due {
		if _, err := k.emit(now, TPoolReset, poolReset{pool, id}); err != nil {
			return err
		}
	}
	return nil
}

// ReadPool records the provider's figures for a pool's windows (RES-5). A
// window at the owner's reserve reopens only at its reset time, never on a
// reading, so a reading of it can only narrow; a window the reading leaves
// out keeps its last figure. A reset time that is missing or already past is
// replaced by PoolWindowMS from now (the clerk gives the window's declared
// length first), so a full window always has a way back.
func (k *Kernel) ReadPool(now int64, pool string, windows []WindowReading) error {
	if len(windows) == 0 {
		return errors.New("kernel: a reading names a window")
	}
	rs := make([]WindowReading, len(windows))
	seen := map[string]bool{}
	for i, w := range windows {
		if w.Used < 0 || w.Used > PoolFull {
			return errors.New("kernel: utilization is a share of the pool")
		}
		if w.Window == "" || seen[w.Window] {
			return errors.New("kernel: a reading names each window once")
		}
		seen[w.Window] = true
		if w.ResetAt <= now {
			w.ResetAt = now + PoolWindowMS
		}
		rs[i] = w
	}
	if err := k.resetIfDue(now, pool); err != nil {
		return err
	}
	_, err := k.emit(now, TPoolRead, poolRead{pool, rs})
	return err
}

// Reserve sets the share of a pool kept for the owner. Raising narrows, so a
// text is enough; it is live at once and cancels any lowering in its hold,
// also when it raises back to the current reserve. Lowering widens (KEY-4,
// KEY-6): it needs a live passkey's signature over ReserveHash, else
// ErrReserveSig and nothing is logged, and a second, one an anchor, when it
// is big, else ErrNeedsCosign. A signed lowering is logged at once and is
// live only from now plus GrantHold; a later one replaces it.
func (k *Kernel) Reserve(now int64, pool string, reserve int64, cos ...key.Cosign) error {
	if reserve < 0 || reserve > PoolFull {
		return errors.New("kernel: a reserve is a share of the pool")
	}
	if reserve >= k.s.Pools[pool].live(now).Reserve {
		return k.owner(now, TReserveUp, poolReserve{pool, reserve})
	}
	b := poolLowered{pool, reserve, cos}
	if err := k.s.lowerOK(now, b); err != nil {
		return err
	}
	return k.owner(now, TReserveDown, b)
}

// AdmitPool refuses work on a pool with a window at the owner's reserve
// until that window resets. Past the reset time the provider gave, the
// reopening is logged as a widening.
func (k *Kernel) AdmitPool(now int64, pool string) *key.Refusal {
	if k.log.broken {
		// The pool may have been reopened by a widening whose anchor failed
		// (KRN-5, #2613 item 13).
		return &key.Refusal{Code: CBroken, Detail: ErrBroken.Error()}
	}
	if err := k.resetIfDue(now, pool); err != nil {
		return &key.Refusal{Code: CPool, Detail: pool + ": " + err.Error()}
	}
	if k.s.PoolOpen(now, pool) {
		return nil
	}
	return &key.Refusal{Code: CPool, Detail: pool}
}

// PoolsAt is every pool as it stands at now, for the owner's reads.
func (s *State) PoolsAt(now int64) map[string]Pool {
	out := make(map[string]Pool, len(s.Pools))
	for name, p := range s.Pools {
		out[name] = p.live(now)
	}
	return out
}
