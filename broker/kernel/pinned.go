package kernel

import (
	"errors"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// ErrPinned refuses a pinned root that is not a bare root its own owner
// signed, or whose owner is an anchor, and a setup that would anchor one.
var ErrPinned = errors.New("kernel: a pinned root is a bare root its owner signed, owned by no anchor")

// Pin adds the image's pinned roots, such as the update clerk's standing
// key for activate (UPD-3, #3677; Mark's card
// cmsg_01R91wiieBzMSvPKFsAJVvuKUCsPpUiKJNwvXkmXsdfr63). A pinned root is
// granted from the image with no owner Issue, and its owner signs plans
// under that exact root and nothing else: it is never an anchor or a
// passkey, so it signs no enrollment, cut-off, grant or co-signature, and
// no plan under any other root. Its holder ships in the image, so as an
// anchor it would let anyone with the image enroll a passkey (KEY-1, D-146).
// A revoke or pause of its ID still applies.
func (s *State) Pin(roots ...key.Key) error {
	for _, k := range roots {
		if len(k.Links) > 0 || key.In(s.Anchors, k.Root.Owner) {
			return ErrPinned
		}
		if _, err := key.Chain(k, []key.PublicKey{k.Root.Owner}); err != nil {
			return ErrPinned
		}
		if s.pinned == nil {
			s.pinned = map[key.ID]key.Key{}
		}
		s.pinned[k.Tip()] = k
	}
	return nil
}

// pinnedOwner reports whether any of anchors owns a pinned root: setup
// refuses it, live and on replay, so the image's key never anchors.
func (s *State) pinnedOwner(anchors []key.PublicKey) bool {
	for _, p := range s.pinned {
		if key.In(anchors, p.Root.Owner) {
			return true
		}
	}
	return false
}

// Pinned lists the pinned roots.
func (s *State) Pinned() []key.Key {
	out := make([]key.Key, 0, len(s.pinned))
	for _, k := range s.pinned {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b key.Key) int { a1, b1 := a.Tip(), b.Tip(); return slices.Compare(a1[:], b1[:]) })
	return out
}

// Owners is PlanOwners with the image's pinned roots: a key that is exactly
// a pinned root is verified against that root's owner alone, and every
// other key as PlanOwners verifies it, the pinned owners left out.
func Owners(v View, anchors []key.PublicKey, pinned []key.Key, k key.Key) []key.PublicKey {
	if len(k.Links) == 0 {
		for _, p := range pinned {
			if p.Tip() == k.Tip() {
				return []key.PublicKey{p.Root.Owner}
			}
		}
	}
	return PlanOwners(v, anchors, k)
}
