package camnode

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// Slots are the board's A/B root slots (brief design point 3): the running
// slot and the inactive one an update is written to. The binary implements
// them on the board's boot partition; tests in memory.
type Slots interface {
	// Stage empties the inactive slot and opens it for an image of size
	// bytes.
	Stage(size uint64) (Staged, error)
	// MarkGood makes the running slot the one the board boots by default.
	MarkGood() error
	// Reboot restarts the board, into a slot Staged.Arm set once if any.
	Reboot() error
}

// Staged is an image being written to the inactive slot.
type Staged interface {
	io.Writer
	// Arm syncs the image, stores manifest beside it as the slot's signed
	// manifest, and sets the board to boot the slot once, on the next
	// restart; a failed start then returns the board to the running slot.
	Arm(manifest []byte) error
	// Abort discards the staged image.
	Abort() error
}

// Update errors.
var (
	// ErrUpdate is an update the node will not stage or mark good: no
	// owner yet, another update in progress, an image that does not match
	// its manifest, or a trial boot of an image this node did not stage.
	ErrUpdate = errors.New("camnode: update refused")
	// ErrRollback is a running image older than the element's image
	// counter, which only an altered boot partition can start.
	ErrRollback = errors.New("camnode: running image is older than the image counter")
)

// image decides, at start, what the running image owes. The manifest it was
// installed with must be release-signed, name this node and hash to the
// running image. Its counter below the element's is a rollback; equal is a
// settled image; above is an image to settle once the server is up
// (Serve): a trial boot is marked good, then the counter raised; a boot
// after a mark-good whose raise the power cut short only raises. A trial
// also needs the owner's assertion over the manifest (NET-7), so a node
// does not keep an image its owner did not approve even if the boot
// partition was set offline to try one (ASSUMPTIONS CAM-b2-2).
func (n *Node) image() error {
	counter, err := n.cfg.Element.Image()
	if err != nil {
		return ErrElement
	}
	if n.cfg.Manifest == nil {
		if n.cfg.Trial {
			return ErrUpdate
		}
		if counter > 0 {
			return ErrRollback
		}
		return nil
	}
	s, m, err := camwire.ParseSignedManifest(n.cfg.Manifest)
	if err != nil {
		return err
	}
	if !m.Names(n.node) || m.Image != n.cfg.Image {
		return ErrUpdate
	}
	switch {
	case m.Counter < counter:
		return ErrRollback
	case m.Counter == counter && n.cfg.Trial:
		return ErrUpdate // a trial of the image already settled
	case m.Counter == counter:
		return verifyRelease(n.cfg, s)
	case n.cfg.Trial:
		if n.bundle == nil {
			return ErrUpdate
		}
		if _, err := camwire.VerifyManifest(n.cfg.Manifest, n.node, n.cfg.Release, n.bundle.Owner, counter); err != nil {
			return err
		}
	default:
		if err := verifyRelease(n.cfg, s); err != nil {
			return err
		}
	}
	n.settle = m.Counter
	return nil
}

// verifyRelease checks the release signer's signature alone: a settled
// image, or a raise the power cut short, needs no owner, since raising the
// counter only tightens (an owner since re-provisioned would otherwise
// leave the node unable to start its own image).
func verifyRelease(cfg Config, s camwire.SignedManifest) error {
	if len(cfg.Release) != ed25519.PublicKeySize || !ed25519.Verify(cfg.Release, s.Manifest, s.Release[:]) {
		return camwire.ErrRelease
	}
	return nil
}

// settleImage runs when Serve starts: the server is up, so a trial
// image is marked good, and then the image counter raised to its
// manifest's. Marking good first means a power cut between the two boots
// the new image again, which raises the counter then; the other order
// would leave the old image's slot the default under a counter it is
// below.
func (n *Node) settleImage() error {
	if n.settle == 0 {
		return nil
	}
	if n.cfg.Trial {
		if err := n.cfg.Slots.MarkGood(); err != nil {
			n.log("update not marked good")
			return ErrUpdate
		}
		n.log("update marked good")
	}
	if err := n.cfg.Element.RaiseImage(n.settle); err != nil {
		n.log("image counter not raised") // the next start raises it
	}
	n.settle = 0
	return nil
}

// update serves one image update on the enforcer's channel: the manifest p
// must verify (release signer, the pinned owner, this node, a counter above
// the element's image counter), then image chunks follow until the
// manifest's size, written to the inactive slot. A chunk past the size,
// any other frame, or an image that does not hash to the manifest ends the
// update with the slot discarded. A whole image is armed for one boot, the
// status sent, and the board restarted.
func (n *Node) update(c *tls.Conn, p []byte) error {
	n.mu.Lock()
	b, busy := n.bundle, n.staging
	if b != nil && !busy {
		n.staging = true
	}
	n.mu.Unlock()
	if b == nil || busy || n.cfg.Slots == nil {
		return ErrUpdate
	}
	defer func() {
		n.mu.Lock()
		n.staging = false
		n.mu.Unlock()
	}()
	counter, err := n.cfg.Element.Image()
	if err != nil {
		return ErrElement
	}
	m, err := camwire.VerifyManifest(p, n.node, n.cfg.Release, b.Owner, counter)
	if err != nil {
		return err
	}
	st, err := n.cfg.Slots.Stage(m.Size)
	if err != nil {
		return ErrUpdate
	}
	h := sha256.New()
	for got := uint64(0); got < m.Size; {
		c.SetDeadline(time.Now().Add(settingsIdle))
		f, err := camwire.ReadFrame(c, camwire.FromEnforcer, n.cfg.Thermal)
		if err != nil || f.Type != camwire.TypeImage || uint64(len(f.Payload)) > m.Size-got {
			st.Abort()
			return ErrUpdate
		}
		h.Write(f.Payload)
		if _, err := st.Write(f.Payload); err != nil {
			st.Abort()
			return ErrUpdate
		}
		got += uint64(len(f.Payload))
	}
	if [32]byte(h.Sum(nil)) != m.Image {
		st.Abort()
		return ErrUpdate
	}
	if err := st.Arm(p); err != nil {
		st.Abort()
		return ErrUpdate
	}
	n.log("update staged: restarting into it once")
	n.status(c)
	if err := n.cfg.Slots.Reboot(); err != nil {
		n.log("restart failed")
		return ErrUpdate
	}
	return nil
}
