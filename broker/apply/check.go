package apply

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
)

// Releaser is the part of the Applier the release check drives.
type Releaser interface {
	Schedule(v *update.Verified, adoption string) error
	FellBack(version int64) bool
}

// CheckConfig configures NewCheck. Every function field is required; Own
// may be nil (the box attests nothing); StableReady raises SoakDays and
// MinPasses to 7 and 1.
type CheckConfig struct {
	Store   *update.Store
	Applier Releaser
	// Mirrors are tried in order; the first verified answer counts.
	Mirrors func() []update.Source
	// Attestors are read once per Step; an error fails the step closed.
	Attestors func() (allow, interim []ed25519.PublicKey, err error)
	// Attestations for a release; an error counts as none.
	Attestations func(ctx context.Context, v *update.Verified) ([][]byte, error)
	// Own is this box's attestation key; its passes never count.
	Own ed25519.PublicKey
	// Channel is ChannelStable or ChannelFast; anything else, or an
	// error, is pinned.
	Channel func() (string, error)
	// Earliest and Latest are the clock guard's bounds; ok is false
	// unless the guard trusts its time.
	Earliest, Latest func(ctx context.Context) (time.Time, bool)
	// Trusted: the first-boot gate has finished (UPD-3).
	Trusted func() bool
	// Requalify is UPD-5's local requalification,
	// (*update.Requalifier).Requalify.
	Requalify func(ctx context.Context, v *update.Verified) (update.Verdict, error)
	// State persists the check's own record (not the applier's).
	State     Store
	SoakDays  int
	MinPasses int
}

// Adoption states in the check's record.
const (
	adStaged    = "staged"
	adConfirmed = "confirmed"
	adFailed    = "failed"
	adDropped   = "dropped"
)

type adoption struct {
	Ref   update.Ref `json:"ref"`
	State string     `json:"state"`
}

// checkState is the check's saved record: when each release image was
// first seen (by imageKey), and every adoption it minted, by ID.
type checkState struct {
	Seq       int                  `json:"seq"`
	Seen      map[string]time.Time `json:"seen,omitempty"`
	Adoptions map[string]adoption  `json:"adoptions,omitempty"`
}

// Check is the update clerk's release check (UPD-4, UPD-5, UPD-7, UPD-8):
// it checks the mirrors, gates the newest release with
// update.Verified.StableReady and local requalification, and schedules it
// on the Applier under an adoption it mints. It is the Applier's Stager.
type Check struct {
	cfg  CheckConfig
	step sync.Mutex // one Step at a time
	mu   sync.Mutex // st and line
	st   checkState
	line string
}

// NewCheck loads the check's record.
func NewCheck(cfg CheckConfig) (*Check, error) {
	if cfg.Store == nil || cfg.Applier == nil || cfg.Mirrors == nil || cfg.Attestors == nil || cfg.Attestations == nil ||
		cfg.Channel == nil || cfg.Earliest == nil || cfg.Latest == nil || cfg.Trusted == nil || cfg.Requalify == nil || cfg.State == nil {
		return nil, errors.New("apply: check: Store, Applier, Mirrors, Attestors, Attestations, Channel, Earliest, Latest, Trusted, Requalify and State are required")
	}
	c := &Check{cfg: cfg}
	b, err := cfg.State.Load()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &c.st); err != nil {
			return nil, fmt.Errorf("apply: check state: %w", err)
		}
	}
	return c, nil
}

// The check's STATUS lines (CH-12): one GSM-7 segment each, with the
// cause, and the step where the owner can take one.
const (
	soakLine        = "Update %d installs after %s, once early boxes have tested it. Nothing is needed from you."
	soakOpenLine    = "Update %d installs once early boxes have tested it. Nothing is needed from you."
	passesLine      = "Update %d installs once another box has tested it. Nothing is needed from you."
	noAttestorLine  = "Update %d waits because no tester box is listed to vouch for updates. Nothing is needed from you."
	securityLine    = "Security update %d installs once another box has tested it. Nothing is needed from you."
	unavailableLine = "Update %d waits until this box can test it itself. Security fixes still install. Nothing is needed from you."
	requalFailLine  = "Update %d did not pass this box's own tests, so I am holding it. Nothing is needed from you."
	checkFellBack   = "Update %d did not start cleanly before, so I will not try it again. Nothing is needed from you."
	checkPinned     = "Automatic updates are off because you pinned your update channel; unpin it to get them again."
)

// Line is the check's STATUS line, or "".
func (c *Check) Line() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.line
}

func (c *Check) setLine(s string) {
	c.mu.Lock()
	c.line = s
	c.mu.Unlock()
}

// Step runs one check. The daemon calls it daily and when the channel or
// the attestor lists change.
func (c *Check) Step(ctx context.Context) error {
	c.step.Lock()
	defer c.step.Unlock()
	if !c.cfg.Trusted() {
		return nil // first boot keeps its own path (UPD-3, A8)
	}
	channel, err := c.cfg.Channel()
	if err != nil || (channel != update.ChannelStable && channel != update.ChannelFast) {
		c.setLine(checkPinned)
		return nil
	}
	// The one read of the attestor lists for this step (SR3-6f-1).
	allow, interim, err := c.cfg.Attestors()
	if err != nil {
		return fmt.Errorf("apply: check: attestor lists: %w", err)
	}
	opts := update.Options{Channel: channel, Attestors: allow, InterimAttestors: interim}
	res, err := c.checkMirrors(opts)
	if err != nil {
		return err
	}
	sighted := []*update.Verified{res.Release}
	if channel == update.ChannelStable {
		// Note when an image first reaches fast, without taking it, so a
		// later promotion to stable is not soaked twice (UPD-5).
		opts.Channel = update.ChannelFast
		if fres, err := c.checkMirrors(opts); err == nil {
			sighted = append(sighted, fres.Release)
		}
	}
	if err := c.sight(ctx, sighted); err != nil {
		return err
	}
	rel := res.Release
	if rel == nil {
		c.setLine("")
		return nil
	}
	return c.offer(ctx, rel, channel)
}

func (c *Check) checkMirrors(o update.Options) (update.Result, error) {
	var last error = errors.New("apply: check: no update mirror configured")
	for _, m := range c.cfg.Mirrors() {
		res, err := c.cfg.Store.Check(m, o)
		if err == nil {
			return res, nil
		}
		last = err
	}
	return update.Result{}, last
}

// imageKey names a release by its image, not its version: the /usr root
// hash and a SHA-256 over its sorted file digests.
func imageKey(v *update.Verified) string {
	imgs := v.Images()
	parts := make([]string, 0, len(imgs))
	for p, d := range imgs {
		parts = append(parts, p+"="+d)
	}
	slices.Sort(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return v.Ref().UsrRootHash + ":" + hex.EncodeToString(h[:])
}

// sight records a first sighting of each release at the clock's Latest,
// never its Earliest, so an early sight cannot shorten a soak; with no
// trusted Latest it records nothing. A sighting older than twice
// update.MaxSoakDays is pruned unless its image is still offered, so a
// release held that long is not soaked again. Saved before use.
func (c *Check) sight(ctx context.Context, rels []*update.Verified) error {
	at, ok := c.cfg.Latest(ctx)
	if !ok {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := map[string]bool{}
	for _, v := range rels {
		if v.OK() {
			now[imageKey(v)] = true
		}
	}
	next := c.st
	next.Seen = map[string]time.Time{}
	keep := 2 * update.MaxSoakDays * 24 * time.Hour
	for k, t := range c.st.Seen {
		if now[k] || at.Sub(t) <= keep {
			next.Seen[k] = t
		}
	}
	for k := range now {
		if _, ok := next.Seen[k]; !ok {
			next.Seen[k] = at
		}
	}
	return c.saveLocked(next)
}

// offer gates rel and schedules it under a new adoption when ready.
func (c *Check) offer(ctx context.Context, rel *update.Verified, channel string) error {
	ref := rel.Ref()
	atts, err := c.cfg.Attestations(ctx, rel)
	if err != nil {
		atts = nil // narrows only
	}
	v := rel.WithAttestations(atts, c.cfg.Own)
	c.mu.Lock()
	seen := c.st.Seen[imageKey(rel)]
	c.mu.Unlock()
	now, ok := c.cfg.Earliest(ctx)
	if !ok {
		now = time.Time{} // no ordinary release; a security fix needs no soak
	}
	w, err := v.StableReady(atts, c.cfg.Own, channel, seen, now, c.cfg.SoakDays, c.cfg.MinPasses)
	if errors.Is(err, update.ErrNeedsAttestation) {
		c.setLine(fmt.Sprintf(securityLine, ref.Version))
		return nil
	}
	if err != nil {
		return err
	}
	if !w.Ready {
		c.setLine(c.waitLine(ref.Version, w))
		return nil
	}
	if c.cfg.Applier.FellBack(ref.Version) {
		c.setLine(fmt.Sprintf(checkFellBack, ref.Version))
		return nil
	}
	if c.adopted(ref) {
		return nil
	}
	// The ship gate (Mark's decision C, #3961): an ordinary release on a
	// stable box installs only on a Passed requalification.
	if channel == update.ChannelStable && !v.Security() {
		verdict, err := c.cfg.Requalify(ctx, v)
		switch {
		case err != nil || verdict.Reason == update.RequalUnavailable:
			c.setLine(fmt.Sprintf(unavailableLine, ref.Version))
			return nil
		case !verdict.Passed:
			c.setLine(fmt.Sprintf(requalFailLine, ref.Version))
			return nil
		}
	}
	id, err := c.mint(ref)
	if err != nil {
		return err
	}
	err = c.cfg.Applier.Schedule(v, id)
	switch {
	case errors.Is(err, ErrFellBack):
		c.setLine(fmt.Sprintf(checkFellBack, ref.Version))
		return nil
	case err == nil, errors.Is(err, ErrApplying), errors.Is(err, ErrRefused):
		// The applier's own STATUS line says what happens next; a refusal
		// settles through StageDropped and is offered again (A5).
		c.setLine("")
		return nil
	}
	c.setLine("")
	return err
}

func (c *Check) waitLine(version int64, w update.Wait) string {
	switch w.Reason {
	case update.WaitSoak:
		if w.Until.IsZero() {
			return fmt.Sprintf(soakOpenLine, version)
		}
		return fmt.Sprintf(soakLine, version, w.Until.Local().Format("2 Jan 2006"))
	case update.WaitNoAttestor:
		return fmt.Sprintf(noAttestorLine, version)
	case update.WaitPinned:
		return checkPinned
	}
	return fmt.Sprintf(passesLine, version)
}

// adopted: an adoption for exactly ref is staged, confirmed or failed.
func (c *Check) adopted(ref update.Ref) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range c.st.Adoptions {
		if a.Ref == ref && a.State != adDropped {
			return true
		}
	}
	return false
}

// mint saves a new adoption for ref as staged and returns its ID,
// upd:<version>:<n>; the save comes before any Schedule.
func (c *Check) mint(ref update.Ref) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.st
	next.Seq++
	id := fmt.Sprintf("upd:%d:%d", ref.Version, next.Seq)
	next.Adoptions = maps.Clone(c.st.Adoptions)
	if next.Adoptions == nil {
		next.Adoptions = map[string]adoption{}
	}
	next.Adoptions[id] = adoption{Ref: ref, State: adStaged}
	if err := c.saveLocked(next); err != nil {
		return "", err
	}
	return id, nil
}

// saveLocked saves next, pruning settled adoptions older than the newest
// confirmed release, and makes it the record only once saved.
func (c *Check) saveLocked(next checkState) error {
	var newest int64
	for _, a := range next.Adoptions {
		if a.State == adConfirmed {
			newest = max(newest, a.Ref.Version)
		}
	}
	next.Adoptions = maps.Clone(next.Adoptions)
	maps.DeleteFunc(next.Adoptions, func(_ string, a adoption) bool {
		return a.State != adStaged && a.Ref.Version < newest
	})
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := c.cfg.State.Save(b); err != nil {
		return err
	}
	c.st = next
	return nil
}

// errNotMinted is a Stager refusal that never changes: the adoption is
// one this check never minted (or pruned), or is confirmed. Permanent()
// lets the applier stop retrying it (A16).
type errNotMinted struct{ id, why string }

func (e errNotMinted) Error() string   { return "apply: check: adoption " + e.id + " " + e.why }
func (e errNotMinted) Permanent() bool { return true }

// settle moves adoption id from one of the states from to state to. It is
// a no-op success when the adoption is already in to or one of done.
// Saved before it returns.
func (c *Check) settle(id, to string, from, done []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.st.Adoptions[id]
	switch {
	case !ok:
		return errNotMinted{id, "is unknown"}
	case a.State == to || slices.Contains(done, a.State):
		return nil
	case !slices.Contains(from, a.State):
		if a.State == adConfirmed {
			return errNotMinted{id, "is confirmed"}
		}
		return fmt.Errorf("apply: check: adoption %s is %s, not %s", id, a.State, strings.Join(from, " or "))
	}
	next := c.st
	next.Adoptions = maps.Clone(c.st.Adoptions)
	a.State = to
	next.Adoptions[id] = a
	return c.saveLocked(next)
}

// ConfirmStaged records that the adoption's release booted and was
// committed. A dropped adoption can still be confirmed: an abandon that
// never took lets the release boot, and it is then installed (A14).
func (c *Check) ConfirmStaged(id string) error {
	return c.settle(id, adConfirmed, []string{adStaged, adDropped}, nil)
}

// StageFailed records a fallback: the release is never offered again.
func (c *Check) StageFailed(_ context.Context, id string) error {
	return c.settle(id, adFailed, []string{adStaged, adDropped}, nil)
}

// StageDropped records that the release left the applier before it was
// installed, so the next Step offers it again under a new ID (A5, A9). A
// failed adoption stays failed.
func (c *Check) StageDropped(_ context.Context, id string) error {
	return c.settle(id, adDropped, []string{adStaged}, []string{adFailed})
}
