package drone

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
	"github.com/bluenviron/gomavlib/v3/pkg/frame"
)

// Provision stores k on an aircraft that holds no key yet, by an unsigned
// SETUP_SIGNING on conn. It is for the first, physical set-up link only: once
// a key is stored the aircraft refuses every unsigned frame, this one
// included (ASSUMPTIONS.md, "Provisioning").
func Provision(conn io.Writer, k Key, now time.Time) error {
	if !k.valid() {
		return errNoKey
	}
	w, err := frame.NewWriter(frame.WriterConf{Writer: conn, DialectRW: dialectRW(), OutVersion: frame.V2,
		OutSystemID: holderSysID, OutComponentID: holderCompID})
	if err != nil {
		return err
	}
	m := &common.MessageSetupSigning{TargetSystem: targetSysID, TargetComponent: targetCompID,
		InitialTimestamp: uint64(now.Sub(signatureEpoch) / (10 * time.Microsecond))}
	copy(m.SecretKey[:], k.s()[:])
	defer clear(m.SecretKey[:])
	if err := w.WriteMessage(m); err != nil {
		return errors.New("drone: writing the provisioning frame failed")
	}
	return nil
}

// Holder is the key-holder: it owns the signed link, the policy in force and
// its record on disk, and decides whether the aircraft may arm.
type Holder struct {
	link  *Link
	owner ed25519.PublicKey
	state string
	log   *log.Logger

	mu     sync.Mutex
	policy *Policy
	plan   *Plan
}

const policyFile = "policy.json"

// NewHolder starts a key-holder over link. stateDir holds the policy in force
// (only this process writes it); a stored policy that no longer verifies
// under owner is refused, so a tampered state directory stops the holder.
func NewHolder(link *Link, owner ed25519.PublicKey, stateDir string, logger *log.Logger) (*Holder, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	h := &Holder{link: link, owner: append(ed25519.PublicKey(nil), owner...), state: stateDir, log: logger}
	b, err := os.ReadFile(filepath.Join(stateDir, policyFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("drone: reading the stored policy: %w", pathErr(err))
	default:
		p, err := LoadPolicy(b, h.owner, nil)
		if err != nil {
			return nil, fmt.Errorf("drone: stored policy: %w", err)
		}
		plan := Derive(p)
		h.policy, h.plan = p, &plan
	}
	return h, nil
}

// Policy returns the policy in force, or nil.
func (h *Holder) Policy() *Policy {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.policy
}

// Load verifies a signed policy, records it, uploads its fence, rally point
// and parameters, and reads them back. Nothing is uploaded from a policy that
// fails to verify; a policy that uploads but does not read back stays in
// force, so the aircraft refuses to arm until a load reads back equal.
func (h *Holder) Load(env []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, err := LoadPolicy(env, h.owner, h.policy)
	if err != nil {
		h.log.Printf("drone: policy refused: %v", err)
		return err
	}
	if err := writeAtomic(filepath.Join(h.state, policyFile), env); err != nil {
		return err
	}
	plan := Derive(p)
	h.policy, h.plan = p, &plan
	if err := h.link.Upload(MissionFence, plan.Fence); err != nil {
		return err
	}
	if err := h.link.Upload(MissionRally, plan.Rally); err != nil {
		return err
	}
	for _, pr := range plan.Params {
		if _, err := h.link.SetParam(pr.Name, pr.Value); err != nil {
			return err
		}
	}
	h.log.Printf("drone: policy version %d uploaded", p.Version)
	return h.readBackLocked()
}

// ReadBack reads the aircraft's parameters, fence and rally points over the
// signed link and compares them with the policy in force. Run it after every
// load and at every boot of the key-holder or the aircraft.
func (h *Holder) ReadBack() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.readBackLocked()
}

// ErrMismatch is wrapped by every read-back failure.
var ErrMismatch = errors.New("the aircraft does not hold the signed policy")

func (h *Holder) readBackLocked() error {
	if h.plan == nil {
		return fmt.Errorf("drone: no policy loaded: %w", ErrMismatch)
	}
	st, err := h.link.SysStatus()
	if err != nil {
		h.log.Printf("drone: read-back failed, arming refused: %v", err)
		return fmt.Errorf("drone: %w: no fresh signed answer from the aircraft (check the enforcer's clock and the key): %v", ErrMismatch, err)
	}
	var bad []string
	// RC_PROTOCOLS 0 stops the aircraft from taking up an RC protocol, but not
	// one it already decodes, and it reports an RC receiver from any RC input
	// until it reboots (ASSUMPTIONS.md DRONE-sim-14).
	if st.OnboardControlSensorsPresent&common.MAV_SYS_STATUS_SENSOR_RC_RECEIVER != 0 {
		bad = append(bad, "the aircraft has had RC input since it booted; reboot it with no receiver")
	}
	for _, want := range h.plan.Params {
		got, err := h.link.GetParam(want.Name)
		switch {
		case err != nil:
			bad = append(bad, fmt.Sprintf("%s unreadable", want.Name))
		case got != want.Value:
			bad = append(bad, fmt.Sprintf("%s is %v, policy %v", want.Name, got, want.Value))
		}
	}
	bad = append(bad, h.compareItems(MissionFence, h.plan.Fence)...)
	bad = append(bad, h.compareItems(MissionRally, h.plan.Rally)...)
	if len(bad) > 0 {
		err := fmt.Errorf("drone: %w: %s", ErrMismatch, strings.Join(bad, "; "))
		h.log.Printf("drone: read-back mismatch, arming refused: %s", strings.Join(bad, "; "))
		return err
	}
	return nil
}

func (h *Holder) compareItems(kind common.MAV_MISSION_TYPE, want []Item) []string {
	got, err := h.link.Download(kind)
	if err != nil {
		return []string{fmt.Sprintf("%v unreadable", kind)}
	}
	if len(got) != len(want) {
		return []string{fmt.Sprintf("%v has %d items, policy %d", kind, len(got), len(want))}
	}
	var bad []string
	for i := range want {
		g, w := got[i], want[i]
		same := g.Command == w.Command && g.Lat == w.Lat && g.Lon == w.Lon
		if kind == MissionFence {
			same = same && g.Param1 == w.Param1
		} else {
			same = same && g.AltM == w.AltM
		}
		if !same {
			bad = append(bad, fmt.Sprintf("%v item %d is %+v, policy %+v", kind, i, g, w))
		}
	}
	return bad
}

// ArmCheck is the last check before any arm: a policy is in force and the
// aircraft reads back equal to it, now. Any error refuses the arm (P3).
func (h *Holder) ArmCheck() error {
	if err := h.ReadBack(); err != nil {
		return fmt.Errorf("drone: arming refused: %w", err)
	}
	return nil
}

func writeAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("drone: state: %w", pathErr(err))
	}
	tmp := f.Name()
	if err := f.Chmod(0o600); err == nil {
		if _, err = f.Write(b); err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp, path) // durable:exempt lifecycle:exempt the drone imports nothing from agentOS (brief decision 1) and durable is old core (tools/old_core.txt), so it cannot list here; this is owner config, not a lifecycle, and the directory is synced below
		}
		if err == nil {
			if d, derr := os.Open(filepath.Dir(path)); derr == nil {
				d.Sync()
				d.Close()
			}
			return nil
		}
	} else {
		f.Close()
	}
	os.Remove(tmp)
	return fmt.Errorf("drone: writing state %s failed", filepath.Base(path))
}
