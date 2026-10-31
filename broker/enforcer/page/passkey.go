package page

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Limits on what anyone on the Owner network can make the page hold or
// draw: proposal links per LinkWindow, live challenges, and how long each
// challenge lasts.
const (
	LinkLimit  = 10
	LinkWindow = time.Minute
	MaxLive    = 16
	ChalLife   = 5 * time.Minute
	maxLink    = 64 << 10
	maxBody    = 16 << 10
)

// DomainAct prefixes what the passkey signs to cancel a pending loosening
// or resume the channel: the action, its target and the challenge's own
// ID, so one tap does one named action once.
const DomainAct = "agentos.enforcer.page.act.v1\x00"

// Page actions besides approving a proposal.
const (
	ActCancel = "cancel"
	ActResume = "resume"
)

// challenge is one tap the page asked for: what it signs and what it does.
type challenge struct {
	kind    string // "propose", ActCancel or ActResume
	target  string // ActCancel: the pending loosening's ID
	prop    policy.Proposal
	class   policy.Class
	base    string // propose: the hash of the policy the diff was drawn against
	secret  *sealedRef
	msg     []byte
	expires int64
}

// sealedRef is the sealed device secret an add-device link names: the
// device and the envelope's hash. The envelope itself arrives with the
// assertion and must hash to it.
type sealedRef struct {
	device, hash string
}

// syncState is what the last verified assertion said about the passkey
// (WebAuthn authenticator-data flags BE and BS).
type syncState struct {
	Known, Eligible, Backed bool
}

var (
	errMalformed = errors.New("this link is malformed")
	errLimited   = errors.New("too many links or pending approvals; wait a minute")
	errGone      = errors.New("this approval has expired or was already used; open the link again")
	errRefused   = errors.New("the passkey did not approve this change")
	errMoved     = errors.New("the policy changed since this page was drawn; open the link again")
	errSealed    = errors.New("the device's sealed secret is missing or not the one this change names; nothing was added; pair the device again")
	errStuck     = errors.New("the device's secret was refused but this change could not be withdrawn; cancel it on the home page")
)

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// put stores c under a new ID, unless MaxLive challenges are still live.
func (s *Server) put(c *challenge) (string, error) {
	now := s.nowMS()
	for id, o := range s.chals {
		if o.expires <= now {
			delete(s.chals, id)
		}
	}
	if len(s.chals) >= MaxLive {
		return "", errLimited
	}
	c.expires = now + ChalLife.Milliseconds()
	id := newID()
	s.chals[id] = c
	return id, nil
}

// take removes and returns the live challenge id: each works once, whether
// or not the tap it gets verifies.
func (s *Server) take(id, kind string) (*challenge, error) {
	c, ok := s.chals[id]
	delete(s.chals, id)
	if !ok || c.kind != kind || c.expires <= s.nowMS() {
		return nil, errGone
	}
	return c, nil
}

// limit counts one link against LinkLimit on times, its kind's own count
// (s.links for proposal links, s.acts for action links), so a flood of one
// kind cannot delay the other. s.mu is held.
func (s *Server) limit(times *[]int64) bool {
	now := s.nowMS()
	*times = slices.DeleteFunc(*times, func(t int64) bool { return t <= now-LinkWindow.Milliseconds() })
	if len(*times) >= LinkLimit {
		return false
	}
	*times = append(*times, now)
	return true
}

// draft is the proposal a link asks for, drawn by the enforcer: its next
// document from the link with a version the page picks, its diff rendered
// from the policy in force. The link's version and any summary text it
// carries are never used. A link that carries a safety-list device's
// sealed secret names the device and the envelope's hash (pairseal's
// ParamDevice and ParamHash); the change must add that device to the
// safety list, and the diff gets pairseal.Statement's line naming both.
func (s *Server) draft(r *http.Request) (*challenge, []string, error) {
	q := r.URL.Query()
	for k := range q {
		if k != "d" && k != "s" && k != pairseal.ParamDevice && k != pairseal.ParamHash {
			return nil, nil, errMalformed
		}
	}
	if len(q["d"]) != 1 || len(q["d"][0]) > maxLink || len(q["s"]) > 1 ||
		len(q[pairseal.ParamDevice]) > 1 || len(q[pairseal.ParamDevice]) != len(q[pairseal.ParamHash]) {
		return nil, nil, errMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(q["d"][0])
	if err != nil {
		return nil, nil, errMalformed
	}
	next, err := policy.Decode(raw)
	if err != nil {
		return nil, nil, errMalformed
	}
	s.cfg.Lock.Lock()
	cur, pend := s.cfg.Policy.Current(), s.cfg.Policy.Pending()
	s.cfg.Lock.Unlock()
	floor := max(cur.Version, s.last)
	for _, p := range pend {
		if d, err := policy.Decode(p.Doc); err == nil {
			floor = max(floor, d.Version)
		}
	}
	next.Version = max(floor+1, uint64(max(s.nowMS(), 0)))
	s.last = next.Version
	base, err := policy.Hash(cur)
	if err != nil {
		return nil, nil, err
	}
	class := policy.Classify(cur, next)
	lines := Describe(cur, next, s.cfg.Zone)
	if lines[0] == noChange {
		return nil, nil, errMalformed
	}
	var ref *sealedRef
	if len(q[pairseal.ParamDevice]) == 1 {
		ref = &sealedRef{device: q[pairseal.ParamDevice][0], hash: q[pairseal.ParamHash][0]}
		dev := next.Device(ref.device)
		if s.cfg.Secrets == nil || !pairseal.Device(ref.device) || !hexHash(ref.hash) ||
			dev == nil || dev.Everyday || cur.Device(ref.device) != nil {
			return nil, nil, errMalformed
		}
		lines = append(lines, pairseal.Statement(ref.device, ref.hash))
	}
	prop := policy.Proposal{Doc: next, Diff: diffText(class, lines)}
	root, err := prop.Root(s.cfg.Owner)
	if err != nil {
		return nil, nil, errMalformed
	}
	return &challenge{kind: "propose", prop: prop, class: class, base: base, secret: ref, msg: key.RootMsg(root)}, lines, nil
}

// hexHash is a SHA-256 in lowercase hex, as pairseal.HashHex writes it.
func hexHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == pairseal.HashLen && hex.EncodeToString(b) == s
}

// assertion is a WebAuthn get() result as the page's script posts it,
// base64url without padding.
type assertion struct {
	ID                string `json:"id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

// signature is a's one accepted encoding (key.AssertionSig), checked
// against the owner's passkey over msg: origin, RP ID, user presence and
// verification, challenge (STO-4, NET-4 Passkey rules). On success it
// records whether the passkey is synced.
func (s *Server) signature(a assertion, msg []byte) ([]byte, error) {
	sig, flags, err := parseAssertion(a)
	if err != nil || !s.cfg.Owner.Verify(msg, sig) {
		return nil, errRefused
	}
	s.synced(flags)
	return sig, nil
}

// parseAssertion is a in key.AssertionSig's encoding, and its
// authenticator-data flags.
func parseAssertion(a assertion) ([]byte, byte, error) {
	var ka key.Assertion
	var err1, err2, err3 error
	ka.AuthenticatorData, err1 = base64.RawURLEncoding.DecodeString(a.AuthenticatorData)
	ka.ClientDataJSON, err2 = base64.RawURLEncoding.DecodeString(a.ClientDataJSON)
	ka.Signature, err3 = base64.RawURLEncoding.DecodeString(a.Signature)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, 0, errRefused
	}
	sig, err := key.AssertionSig(ka)
	if err != nil || len(ka.AuthenticatorData) < 37 { // rpIdHash, flags, counter
		return nil, 0, errRefused
	}
	return sig, ka.AuthenticatorData[32], nil
}

// synced records the BE and BS flags of a verified assertion.
func (s *Server) synced(f byte) {
	s.sync = syncState{Known: true, Eligible: f&0x08 != 0, Backed: f&0x10 != 0}
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return errMalformed
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// approve takes the owner's tap on a drawn proposal and hands it to the
// policy, which verifies it again and classifies it against the policy in
// force: a tightening applies now, a loosening waits 10 minutes. An
// add-device change that names a sealed secret needs the envelope posted
// with the tap, hashing to the hash the diff named; the store then admits
// it, and if it refuses, the change is cancelled, so no device is added
// without the secret the owner approved.
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var a struct {
		assertion
		Sealed string `json:"sealed"`
	}
	if err := readJSON(r, &a); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.take(a.ID, "propose")
	if err != nil {
		fail(w, http.StatusGone, err)
		return
	}
	sig, err := s.signature(a.assertion, c.msg)
	if err != nil {
		fail(w, http.StatusForbidden, err)
		return
	}
	var sealed []byte
	if c.secret != nil {
		sealed, err = base64.RawURLEncoding.DecodeString(a.Sealed)
		if err != nil || pairseal.HashHex(sealed) != c.secret.hash {
			fail(w, http.StatusBadRequest, errSealed)
			return
		}
	} else if a.Sealed != "" {
		fail(w, http.StatusBadRequest, errMalformed)
		return
	}
	s.cfg.Lock.Lock()
	defer s.cfg.Lock.Unlock()
	if h, err := policy.Hash(s.cfg.Policy.Current()); err != nil || h != c.base {
		fail(w, http.StatusConflict, errMoved)
		return
	}
	out, err := s.cfg.Policy.Propose(c.prop, sig, s.nowMS())
	if err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	if c.secret != nil {
		if err := s.cfg.Secrets.Admit(c.secret.device, sealed, c.prop, sig); err != nil {
			if out.Pending == "" || s.cfg.Policy.Cancel(out.Pending) != nil {
				fail(w, http.StatusInternalServerError, errStuck)
				return
			}
			s.cfg.Secrets.Prune() // fails closed: an unsaved erase still holds in memory
			fail(w, http.StatusConflict, errSealed)
			return
		}
	}
	if s.cfg.Secrets != nil {
		s.cfg.Secrets.Prune() // fails closed, as above
	}
	res := map[string]any{"applied": out.Applied}
	if out.Pending != "" {
		res["pending"] = out.Pending
		res["due"] = s.when(out.DueMS)
	}
	writeJSON(w, http.StatusOK, res)
}

// challenge draws a tap for a page action: cancelling a pending loosening
// or resuming the paused channel (NET-4, NET-6).
func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Target string `json:"target"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	switch req.Action {
	case ActCancel:
		s.cfg.Lock.Lock()
		ok := slices.ContainsFunc(s.cfg.Policy.Pending(), func(p policy.Pending) bool { return p.ID == req.Target })
		s.cfg.Lock.Unlock()
		if !ok {
			fail(w, http.StatusNotFound, policy.ErrNoPending)
			return
		}
	case ActResume:
		if s.cfg.Channel == nil || req.Target != "" {
			fail(w, http.StatusNotFound, errMalformed)
			return
		}
	default:
		fail(w, http.StatusBadRequest, errMalformed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &challenge{kind: req.Action, target: req.Target}
	id, err := s.put(c)
	if err != nil {
		fail(w, http.StatusTooManyRequests, err)
		return
	}
	c.msg = actMsg(req.Action, req.Target, id)
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "challenge": chal(c.msg), "rp_id": s.cfg.Name})
}

func actMsg(action, target, id string) []byte {
	return []byte(DomainAct + action + "\x00" + target + "\x00" + id)
}

func chal(msg []byte) string {
	c := key.Challenge(msg)
	return base64.RawURLEncoding.EncodeToString(c[:])
}

// act does a page action after the owner's tap on its challenge.
func (s *Server) act(w http.ResponseWriter, r *http.Request) {
	var a struct {
		assertion
		Action string `json:"action"`
	}
	if err := readJSON(r, &a); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.take(a.ID, a.Action)
	if err != nil {
		fail(w, http.StatusGone, err)
		return
	}
	if _, err := s.signature(a.assertion, c.msg); err != nil {
		fail(w, http.StatusForbidden, err)
		return
	}
	switch c.kind {
	case ActCancel:
		s.cfg.Lock.Lock()
		err = s.cfg.Policy.Cancel(c.target)
		if err == nil && s.cfg.Secrets != nil {
			err = s.cfg.Secrets.Prune() // a cancelled add-device change takes its secret with it
		}
		s.cfg.Lock.Unlock()
	case ActResume:
		err = s.cfg.Channel.Resume()
	}
	if err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}
