package main

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// Owner Card rotation on the unlock socket (REC-4, CTRL-card-rot-wire).
// The local UI's rotation display (card.Display) begins a rotation here,
// generates the new card itself, and commits only the rotated parts once
// the owner confirms them; this process holds the Pending between the
// two. The unlock socket's only peer is the local UI (-unlock-uid), so
// every op here runs with recovery's local confirmation.
//
// #1090 security review: (R1) the commit's outcomes map to statuses the
// display can act on: 410 for a rotation that lapsed or was dropped
// (nothing changed; the display discards the card), 409 for a commit that
// stopped after a slot was rewritten (the card is in effect; the display
// shows it to print), 400 for a card that does not fit (kept for a
// retry). (R2, CRED-1) the Pending holds the typed vault passphrase, so it
// is dropped on cancel, on lock, and by a timer at recovery.PendingTTL.
//
// #1175 security review S-R1: commit and cancel carry the rotation ID the
// begin was made with, so a late commit or a stale cancel cannot act on a
// newer rotation: a mismatch answers 410 and leaves the waiting Pending
// alone. The page draws the ID (32 hex digits from crypto/rand) and the
// begin echoes it, so the page can cancel a begin that got no answer; an
// ID cancelled before its begin arrived is remembered (dead), and that
// late begin is refused before it drops anything.

// rotation is the vault process's one pending rotation. Lock order:
// rotation.mu before custody.mu; Commit runs under rotation.mu alone,
// since the box's Reencrypt takes custody.mu.
type rotation struct {
	mu sync.Mutex
	// box is the recovery package's view of the open vault, rebuilt when
	// the vault is opened again (gen).
	box *recovery.Box
	gen int
	p   *recovery.Pending
	// pin is this PC's boot PIN for a recovery-key rotation's
	// re-encryption; kept only with p.
	pin  string
	stop func() bool
	// id is the waiting rotation's ID; set only with p.
	id string
	// dead are IDs cancelled while not waiting (most recent last), so a
	// begin arriving after its own cancel is refused.
	dead []string
	// wifi is the network the latest Wi-Fi commit put in effect, for
	// agentosd to take once over the verify socket (#1522). drop leaves
	// it: a commit drops its rotation and then holds this.
	wifi *heldWiFi
}

// maxDead bounds rotation.dead: the page cancels at most one begin it
// gave up on per start.
const maxDead = 16

// rotationID reports an ID of the form the page draws: 32 lowercase hex
// digits.
func rotationID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !('0' <= s[i] && s[i] <= '9' || 'a' <= s[i] && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// mine reports whether id names the waiting rotation. The caller holds
// r.mu.
func (r *rotation) mine(id string) bool {
	return r.p != nil && rotationID(id) && subtle.ConstantTimeCompare([]byte(id), []byte(r.id)) == 1
}

// bury remembers an ID cancelled while not waiting. The caller holds
// r.mu.
func (r *rotation) bury(id string) {
	if !rotationID(id) || slices.Contains(r.dead, id) {
		return
	}
	if len(r.dead) == maxDead {
		r.dead = slices.Delete(r.dead, 0, 1)
	}
	r.dead = append(r.dead, id)
}

// drop cancels the pending rotation, wiping its typed passphrase. The
// caller holds r.mu.
func (r *rotation) drop() {
	if r.p != nil {
		r.p.Cancel()
	}
	if r.stop != nil {
		r.stop()
	}
	r.p, r.pin, r.stop, r.id = nil, "", nil, ""
}

// rotateCommit is the new card's rotated parts, as the display sends
// them; the Wi-Fi name never changes, so it is not sent.
type rotateCommit struct {
	// ID is the rotation's ID, from its begin.
	ID              string `json:"id"`
	WiFiPassword    string `json:"wifi_password,omitempty"`
	SetupSecret     string `json:"setup_secret,omitempty"`
	SetupCode       string `json:"setup_code,omitempty"`
	VaultPassphrase string `json:"vault_passphrase,omitempty"`
	GridSeed        []byte `json:"grid_seed,omitempty"`
	RecoveryKey     string `json:"recovery_key,omitempty"`
}

func (n rotateCommit) card() recovery.Card {
	return recovery.Card{WiFiPassword: n.WiFiPassword, SetupSecret: n.SetupSecret, SetupCode: n.SetupCode,
		VaultPassphrase: n.VaultPassphrase, GridSeed: n.GridSeed, RecoveryKey: n.RecoveryKey}
}

var (
	errNoCard          = uerr(http.StatusConflict, "I keep no Owner Card, so there is nothing to rotate")
	errNoRotation      = uerr(http.StatusGone, "no new card is waiting; nothing changed, start again")
	errRotationLapsed  = uerr(http.StatusGone, "this new card has lapsed; nothing changed, start again")
	errRotationParts   = uerr(http.StatusBadRequest, "choose the card parts to replace: wifi, setup, passphrase, grid, recovery")
	errRotationID      = uerr(http.StatusBadRequest, "this request names no rotation; start again")
	errRotationGone    = uerr(http.StatusGone, "this new card was cancelled; nothing changed, start again")
	errWrongRecovery   = uerr(http.StatusForbidden, "that recovery key does not open this drive")
	errRotationProof   = uerr(http.StatusForbidden, "replacing the passphrase or recovery key needs the current one from the card")
	errRotationPass    = uerr(http.StatusForbidden, "that vault passphrase does not open the drive; check it against the card")
	errNextCard        = uerr(http.StatusBadRequest, "the new card does not match the parts being replaced")
	errCardInEffect    = uerr(http.StatusConflict, "part of the new card is in effect but was not saved; print it now")
	errEnrollTries     = uerr(http.StatusTooManyRequests, "too many wrong codes; show the code again with the recovery key")
	errNoNewGenerator  = uerr(http.StatusConflict, "no new code generator is waiting to be confirmed")
	noteRotationPartly = "a card rotation stopped part way; print the new card shown and replace the parts it owes"
)

// rotBox is the recovery package's view of the open vault, or an error
// when the vault is locked or keeps no Owner Card. The caller holds
// c.rot.mu.
func (c *custody) rotBox() (*recovery.Box, error) {
	c.mu.Lock()
	ph, v, gen := c.ph, c.v, c.gen
	c.mu.Unlock()
	if ph != open {
		return nil, errLocked
	}
	r := &c.rot
	if r.box == nil || r.gen != gen || r.box.V != v {
		r.drop()
		if c.vaultPath == "" || c.keysPath == "" {
			return nil, errNoCard
		}
		r.box = &recovery.Box{VaultPath: c.vaultPath, KeysPath: c.keysPath, V: v,
			// The rotation's PIN, read under c.rot.mu, which Commit holds.
			Reencrypt: func(owner ...vault.Factor) (int, error) { return c.reencrypt(c.rot.pin, owner...) }}
		r.gen = gen
	}
	if _, err := r.box.LoadCard(); err != nil {
		return nil, errNoCard
	}
	return r.box, nil
}

// still reports whether the vault rotBox saw is still the open one. The
// caller holds c.rot.mu, so lock cannot run meanwhile.
func (c *custody) still() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ph == open && c.gen == c.rot.gen && c.rot.box != nil && c.v == c.rot.box.V
}

type rotateBegin struct {
	// ID names the rotation for its commit and cancel (S-R1).
	ID string `json:"id"`
	// Code is a tier-4 approval code (CH-3); Recovery, the current
	// recovery key, replaces it.
	Code     string   `json:"code"`
	Recovery string   `json:"recovery"`
	Parts    []string `json:"parts"`
	// Passphrase is the current vault passphrase typed from the card, the
	// proof for rewriting the passphrase or recovery slot.
	Passphrase string `json:"passphrase"`
	// PIN is this PC's boot PIN, for a recovery-key rotation's
	// re-encryption on a PC trusted with one.
	PIN string `json:"pin"`
}

// beginRotation authorizes a rotation of the chosen parts and holds it
// for commitRotation, dropping any earlier one.
func (c *custody) beginRotation(req rotateBegin) (*recovery.Pending, error) {
	if n := utf8.RuneCountInString(req.PIN); req.PIN != "" && (n < MinPINLen || n > 64) {
		return nil, errBadPIN
	}
	if !rotationID(req.ID) {
		return nil, errRotationID
	}
	if len(req.Parts) == 0 {
		return nil, errRotationParts
	}
	parts := make([]recovery.Part, 0, len(req.Parts))
	set := map[recovery.Part]bool{}
	for _, s := range req.Parts {
		p := recovery.Part(s)
		switch p {
		case recovery.PartWiFi, recovery.PartSetup, recovery.PartPassphrase, recovery.PartGrid, recovery.PartRecovery:
		default:
			return nil, errRotationParts
		}
		if !set[p] {
			set[p] = true
			parts = append(parts, p)
		}
	}
	r := &c.rot
	r.mu.Lock()
	defer r.mu.Unlock()
	if slices.Contains(r.dead, req.ID) {
		// The page gave up on this begin and cancelled it: it must not
		// drop a newer rotation, nor hold a passphrase nobody will use.
		return nil, errRotationGone
	}
	r.drop()
	r.wifi = nil
	b, err := c.rotBox()
	if err != nil {
		return nil, err
	}
	var auth recovery.Auth
	var proof recovery.Proof
	if req.Recovery != "" {
		rk, err := recovery.ParseRecoveryKey(req.Recovery)
		if err != nil {
			c.notify("a recovery key that does not open this drive was typed for a card rotation")
			return nil, errWrongRecovery
		}
		auth.Recovery, proof.Recovery = rk, rk
	} else {
		c.mu.Lock()
		if c.ph != open || c.gen != r.gen {
			c.mu.Unlock()
			return nil, errLocked
		}
		err := c.approvedLocked(req.Code, "a card rotation")
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		auth.Code, auth.Local = true, true
	}
	if req.Passphrase != "" {
		proof.Passphrase = []byte(req.Passphrase)
		defer clear(proof.Passphrase) // BeginRotate keeps its own copy
	}
	p, err := recovery.BeginRotate(b, parts, auth, proof, c.now())
	switch {
	case err == nil:
	case errors.Is(err, recovery.ErrNotAuthorized):
		c.notify("a recovery key that does not open this drive was typed for a card rotation")
		return nil, errWrongRecovery
	case errors.Is(err, recovery.ErrRotationOwed):
		return nil, uerr(http.StatusConflict, strings.TrimPrefix(err.Error(), "recovery: "))
	case errors.Is(err, recovery.ErrWrongPassphrase):
		return nil, errRotationPass
	case errors.Is(err, recovery.ErrLostCardParts), errors.Is(err, recovery.ErrNeedPassphrase):
		return nil, uerr(http.StatusBadRequest, strings.TrimPrefix(err.Error(), "recovery: "))
	case set[recovery.PartPassphrase] || set[recovery.PartRecovery]:
		// The proof did not open the drive (BeginRotate's plain error).
		return nil, errRotationProof
	default:
		return nil, errInternal
	}
	r.p, r.id = p, req.ID
	if set[recovery.PartRecovery] {
		r.pin = req.PIN
	}
	after := c.afterFunc
	if after == nil {
		after = func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }
	}
	r.stop = after(recovery.PendingTTL, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.p == p {
			r.drop()
		}
	})
	return p, nil
}

// commitRotation stores the new card's parts through the pending
// rotation named by next.ID. Only a card that does not fit keeps the
// rotation for a retry; every other outcome drops it. A commit for any
// other rotation answers 410 and leaves the waiting one alone (S-R1).
func (c *custody) commitRotation(next rotateCommit) (recovery.Done, []recovery.Part, bool, error) {
	r := &c.rot
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.mine(next.ID) {
		return recovery.Done{}, nil, false, errNoRotation
	}
	p := r.p
	if !c.still() {
		r.drop()
		return recovery.Done{}, nil, false, errNoRotation
	}
	parts, lost, ssid := p.Parts(), p.Lost(), p.WiFiName()
	// Both a clean commit and one that stopped after a slot (409) show
	// the new card as in effect, so both hold its Wi-Fi network.
	hold := func() {
		if slices.Contains(parts, recovery.PartWiFi) {
			r.wifi = &heldWiFi{ssid: ssid, password: next.WiFiPassword, until: c.now().Add(wifiHold)}
		}
	}
	done, err := p.Commit(r.box, next.card(), c.now())
	switch {
	case err == nil:
	case errors.Is(err, recovery.ErrNextCard):
		return recovery.Done{}, nil, false, errNextCard
	case errors.Is(err, recovery.ErrPendingLapsed):
		r.drop()
		return recovery.Done{}, nil, false, errRotationLapsed
	case errors.Is(err, recovery.ErrCardNotStored):
		r.drop()
		hold()
		c.notify(noteRotationPartly)
		return recovery.Done{}, nil, false, errCardInEffect
	default:
		// Nothing was written (recovery.Commit joins ErrCardNotStored
		// once a slot was), but the rotation is spent.
		r.drop()
		return recovery.Done{}, nil, false, errNoRotation
	}
	r.drop()
	hold()
	names := make([]string, len(parts))
	for i, q := range parts {
		names[i] = string(q)
	}
	c.notify("the Owner Card was replaced on the local page: " + strings.Join(names, ", "))
	return done, parts, lost, nil
}

// heldWiFi is a committed rotation's Wi-Fi network, waiting for
// agentosd to write it to ap-net.json (#1522).
type heldWiFi struct {
	ssid, password string
	until          time.Time
}

// wifiHold is how long a committed Wi-Fi network waits for agentosd. The
// page hands off right after the commit's reply, so minutes are ample.
const wifiHold = 5 * time.Minute

// takeRotatedWiFi gives the network the latest Wi-Fi commit put in
// effect, once, and only while it has not lapsed: it is agentosd's
// one-shot permit to rewrite ap-net.json (#1522), so a page session alone
// cannot change the access point's network.
func (c *custody) takeRotatedWiFi() (ssid, password string, ok bool) {
	r := &c.rot
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.wifi
	r.wifi = nil
	if w == nil || c.now().After(w.until) {
		return "", "", false
	}
	return w.ssid, w.password, true
}

// cancelRotation drops the pending rotation named id (the display's
// cancel, #1090 R2). Any other ID leaves the waiting rotation alone,
// answers 410 and is remembered, so its begin, if still on the way, is
// refused (S-R1).
func (c *custody) cancelRotation(id string) error {
	r := &c.rot
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.mine(id) {
		r.bury(id)
		return errNoRotation
	}
	r.drop()
	return nil
}

// enrollmentPending reports a replaced code generator not yet confirmed,
// for the page to offer showing it again (#1175 UX U-R1). A locked vault
// or one with no Owner Card has none to show.
func (c *custody) enrollmentPending() bool {
	b, err := c.enrollBox()
	if err != nil {
		return false
	}
	return recovery.EnrollmentPending(b)
}

// enrollBox is the box for the code-generator ops after a rotation.
func (c *custody) enrollBox() (*recovery.Box, error) {
	c.rot.mu.Lock()
	defer c.rot.mu.Unlock()
	return c.rotBox()
}

func (c *custody) confirmEnrollment(code string) (bool, error) {
	b, err := c.enrollBox()
	if err != nil {
		return false, err
	}
	ok, err := recovery.ConfirmEnrollment(b, code, true, c.now())
	switch {
	case err == nil:
		return ok, nil
	case errors.Is(err, recovery.ErrEnrollTries):
		return false, errEnrollTries
	case errors.Is(err, recovery.ErrNoEnrollment):
		return false, errNoNewGenerator
	}
	return false, errInternal
}

func (c *custody) showEnrollment(key string) (string, error) {
	b, err := c.enrollBox()
	if err != nil {
		return "", err
	}
	rk, err := recovery.ParseRecoveryKey(key)
	if err != nil {
		c.notify("a recovery key that does not open this drive was typed to show the code generator")
		return "", errWrongRecovery
	}
	e, err := recovery.ShowEnrollment(b, rk, true)
	switch {
	case err == nil:
		return e.URI, nil
	case errors.Is(err, recovery.ErrNoEnrollment):
		return "", errNoNewGenerator
	case errors.Is(err, recovery.ErrNotAuthorized):
		c.notify("a recovery key that does not open this drive was typed to show the code generator")
		return "", errWrongRecovery
	}
	return "", errInternal
}

// rotationRoutes serves Owner Card rotation on the unlock socket.
func rotationRoutes(mux *http.ServeMux, c *custody, read func(http.ResponseWriter, *http.Request, any) bool,
	reply func(http.ResponseWriter, int, any), fail func(http.ResponseWriter, error)) {
	mux.HandleFunc("/rotate/begin", func(w http.ResponseWriter, r *http.Request) {
		var req rotateBegin
		if !read(w, r, &req) {
			return
		}
		p, err := c.beginRotation(req)
		if err != nil {
			fail(w, err)
			return
		}
		parts := []string{}
		for _, q := range p.Parts() {
			parts = append(parts, string(q))
		}
		reply(w, http.StatusOK, map[string]any{"id": req.ID, "parts": parts, "wifi_name": p.WiFiName(), "lost": p.Lost(),
			"expires": c.now().Add(recovery.PendingTTL).UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("/rotate/commit", func(w http.ResponseWriter, r *http.Request) {
		var req rotateCommit
		if !read(w, r, &req) {
			return
		}
		done, parts, lost, err := c.commitRotation(req)
		if err != nil {
			fail(w, err)
			return
		}
		notes := recovery.DoneNotes(parts, lost)
		if n := recovery.RetrustNote(done.Retrust, nil); n != "" {
			notes = append(notes, n)
		}
		out := map[string]any{"notes": notes, "retrust": done.Retrust}
		if done.Enrollment != nil {
			out["enrollment"] = done.Enrollment.URI
		}
		reply(w, http.StatusOK, out)
	})
	mux.HandleFunc("/rotate/cancel", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.cancelRotation(req.ID); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/rotate/status", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !read(w, r, &req) {
			return
		}
		reply(w, http.StatusOK, map[string]any{"enrollment_pending": c.enrollmentPending()})
	})
	mux.HandleFunc("/rotate/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		if !read(w, r, &req) {
			return
		}
		ok, err := c.confirmEnrollment(req.Code)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, map[string]any{"confirmed": ok})
	})
	mux.HandleFunc("/rotate/show-enrollment", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Recovery string `json:"recovery"`
		}
		if !read(w, r, &req) {
			return
		}
		uri, err := c.showEnrollment(req.Recovery)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, map[string]any{"enrollment": uri})
	})
}
