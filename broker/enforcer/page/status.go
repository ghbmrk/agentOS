package page

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Alerts is the enforcer's alert log as the page shows and clears it
// (alert.Alerts, slice h): every open alert, a silent core and the
// light's colour, and the owner's clear of one alert after a tap. The
// page is the record the core cannot drop or forge (NET-2 Texts and
// calls, KRN-12 Silence).
type Alerts interface {
	Status() Status
	Resolve(id uint64) error
}

// Status is what the page shows of the alerts (alert.Status).
type Status struct {
	Open     []Alert
	CoreDown bool
	Red      bool // the light: a trip at the enforcer is unresolved (D-254)
}

// Alert is one open alert: its fixed wording, when it was first raised,
// how often since, and whether the core took its text. Fixed is an alert
// only another step clears (a paused channel clears when it resumes).
// Revoke is one whose choice is to keep the core or revoke its key (the
// core's log forked from the copies: it may have been rolled back), so
// its card names that choice and leads to the revoke step.
type Alert struct {
	ID     uint64
	Text   string
	At     time.Time
	Count  int
	Sent   bool
	Fixed  bool
	Revoke bool
}

// Core is the core's channel sub-key as the page revokes it (heads
// ASSUMPTIONS ENF-h-1, KEY-7, STO-4's stolen core): the revocation
// reaches the enforcer at home, without the core.
type Core interface {
	// RevokeMsg is what owner's passkey signs to revoke the core's
	// sub-key: key.RootMsg(heads.SubKeyRoot(owner, sub)).
	RevokeMsg(owner key.PublicKey) []byte
	// Revoke revokes it on that signature; an error after which it is
	// revoked for this run only says so.
	Revoke(sig []byte) error
	Revoked() bool
}

// Page actions on the enforcer's own state, each after a tap of the
// passkey in force.
const (
	ActClear      = "clear"       // resolve one open alert (target: its ID)
	ActRevokeCore = "revoke-core" // revoke the core's channel sub-key
)

var (
	errNoAlert = errors.New("no open alert with that number; open the home page again")
	errFixed   = errors.New("this alert clears when the channel resumes")
	errRevoked = errors.New("the core's key is already revoked")
)

// stateChallenge checks that action can be drawn on the enforcer's state
// as it is now; ok is false for an action that is not one of these.
func (s *Server) stateChallenge(action, target string) (ok bool, code int, err error) {
	switch action {
	case ActClear:
		if s.cfg.Alerts == nil {
			return true, http.StatusNotFound, errMalformed
		}
		id, err := strconv.ParseUint(target, 10, 64)
		if err != nil {
			return true, http.StatusBadRequest, errMalformed
		}
		for _, a := range s.cfg.Alerts.Status().Open {
			if a.ID == id && a.Fixed {
				return true, http.StatusConflict, errFixed
			}
			if a.ID == id {
				return true, http.StatusOK, nil
			}
		}
		return true, http.StatusNotFound, errNoAlert
	case ActRevokeCore:
		switch {
		case s.cfg.Core == nil || target != "":
			return true, http.StatusNotFound, errMalformed
		case s.cfg.Core.Revoked():
			return true, http.StatusConflict, errRevoked
		}
		return true, http.StatusOK, nil
	}
	return false, 0, nil
}

// stateAct does action after the owner's tap; res is the answer's extra
// fields.
func (s *Server) stateAct(c *challenge, sig []byte) (res map[string]any, err error) {
	switch c.kind {
	case ActClear:
		id, _ := strconv.ParseUint(c.target, 10, 64) // checked when drawn
		err = s.cfg.Alerts.Resolve(id)
	case ActRevokeCore:
		err = s.cfg.Core.Revoke(sig)
	}
	return res, err
}

// status is the home page's view of the enforcer's own state.
func (s *Server) status() map[string]any {
	out := map[string]any{}
	if s.cfg.Alerts != nil {
		st := s.cfg.Alerts.Status()
		out["Alerts"], out["CoreDown"], out["Red"], out["Shown"] = st.Open, st.CoreDown, st.Red, true
	}
	if s.cfg.Core != nil {
		out["Core"], out["Revoked"] = true, s.cfg.Core.Revoked()
	}
	return out
}
