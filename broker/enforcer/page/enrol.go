package page

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"rsc.io/qr"

	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The enrolment and recovery screens (slice c, NET-4 Enrolment and
// recovery, HW-10, CH-9). They answer only where the rest of the page
// does: the Owner network, which carries the setup network before
// enrolment (ap.Layout), and the wired admin port. The case code and the
// recovery code are typed here and nowhere else; agentOS never asks for
// them (CH-9).

// Page actions on the enrolment state, each after a tap of the passkey in
// force.
const (
	ActKeep           = "keep"            // sign the policy in force as this passkey's
	ActCancelRecovery = "cancel-recovery" // stop a replacement passkey waiting
)

var errEnrolFirst = errors.New("no passkey is enrolled on this enforcer; enrol one first")

// live reports whether the page takes the owner's taps: a passkey is
// enrolled and it is still the one in force. After a factory reset or a
// recovery that applied, a page built for the old passkey serves only the
// enrolment screens until the daemon builds it again for the new one.
func (s *Server) live() bool {
	return s.cfg.Owner.Valid() && (s.cfg.Enrol == nil || s.cfg.Enrol.Owner() == s.cfg.Owner)
}

// enrolScreen is the enrolment screen for where enrolment stands.
func (s *Server) enrolScreen(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Name":   s.cfg.Name,
		"Phase":  string(s.cfg.Enrol.Phase()),
		"CA":     len(s.cfg.CA) > 0,
		"CoreCA": len(s.cfg.CoreCA) > 0,
	}
	if due, ok := s.cfg.Enrol.Recovery(); ok {
		data["Due"] = s.when(due.UnixMilli())
	}
	s.render(w, "enrol.html", data)
}

// certificate serves the enforcer's root certificate, or the core's page
// authority, for the phone to install in the step that enrols the passkey
// (CH-9). Each is a public certificate.
func (s *Server) certificate(w http.ResponseWriter, der []byte) {
	if len(der) == 0 {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Write(der)
}

// enrolBegin takes a code and a new passkey's public key (WebAuthn
// getPublicKey(), SubjectPublicKeyInfo) and returns the message the new
// passkey signs to show it holds its key. The book checks the code and
// counts misses.
func (s *Server) enrolBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code      string `json:"code"`
		PublicKey string `json:"public_key"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	pk, err := s.spki(req.PublicKey)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	id, msg, err := s.cfg.Enrol.Begin(req.Code, pk)
	if err != nil {
		fail(w, status(err), plainErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "challenge": chal(msg), "rp_id": s.cfg.Name})
}

// spki is a passkey's SubjectPublicKeyInfo as an ES256 key on the page's
// own name, the only kind the enforcer takes.
func (s *Server) spki(b64 string) (key.PublicKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return key.PublicKey{}, errMalformed
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	ec, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok || ec.Curve != elliptic.P256() {
		return key.PublicKey{}, errors.New("this passkey's kind is not one the enforcer takes")
	}
	point, err := ec.Bytes()
	if err != nil {
		return key.PublicKey{}, errMalformed
	}
	return key.ES256(s.cfg.Name, point)
}

// qrCode is a QR code as the page's script draws it: its side in modules
// and one character per module, row by row, "1" for dark.
type qrCode struct {
	Size    int    `json:"size"`
	Modules string `json:"modules"`
}

func qrOf(text string) (qrCode, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return qrCode{}, err
	}
	var b strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
	}
	return qrCode{Size: c.Size, Modules: b.String()}, nil
}

// enrolFinish takes the new passkey's tap and shows, once, the recovery
// code and either the Owner network to join (a passkey now in force) or
// when the replacement applies (a recovery).
func (s *Server) enrolFinish(w http.ResponseWriter, r *http.Request) {
	var a assertion
	if err := readJSON(r, &a); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	sig, _, err := parseAssertion(a)
	if err != nil {
		fail(w, http.StatusForbidden, err)
		return
	}
	res, err := s.cfg.Enrol.Finish(a.ID, sig)
	if err != nil {
		fail(w, status(err), plainErr(err))
		return
	}
	out := map[string]any{"recovery": grouped(res.Recovery)}
	if !res.Due.IsZero() {
		out["due"] = s.when(res.Due.UnixMilli())
	} else {
		code, err := qrOf(res.Card.QR)
		if err != nil {
			fail(w, http.StatusInternalServerError, errors.New("enrolled, but the Owner network's QR could not be drawn; its name and password are below"))
			return
		}
		out["network"] = map[string]any{"ssid": res.Card.SSID, "password": res.Card.Shown, "qr": code}
	}
	writeJSON(w, http.StatusOK, out)
}

// enrolReset is a factory reset by the case code (NET-2 Hardening).
func (s *Server) enrolReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Enrol.FactoryReset(req.Code); err != nil {
		fail(w, status(err), plainErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// grouped is a code in groups of four, as the owner writes it down.
func grouped(c string) string {
	var parts []string
	for len(c) > 4 {
		parts = append(parts, c[:4])
		c = c[4:]
	}
	return strings.Join(append(parts, c), " ")
}

func status(err error) int {
	switch {
	case errors.Is(err, enrol.ErrLimited), errors.Is(err, enrol.ErrBusy):
		return http.StatusTooManyRequests
	case errors.Is(err, enrol.ErrCode), errors.Is(err, enrol.ErrProof):
		return http.StatusForbidden
	case errors.Is(err, enrol.ErrGone):
		return http.StatusGone
	case errors.Is(err, enrol.ErrPhase), errors.Is(err, enrol.ErrKept):
		return http.StatusConflict
	case errors.Is(err, enrol.ErrKey):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// plainErr is err in the page's words: the book's message without its
// package prefix.
func plainErr(err error) error {
	m := strings.TrimPrefix(err.Error(), "enrol: ")
	return errors.New(strings.ToUpper(m[:1]) + m[1:])
}
