package localui

import (
	"errors"
	"html/template"
	"net/http"
	"sync"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// SetupWiFi is a preloaded box's setup network as the claim step sees it
// (HW-10, #1692): at the claim the sticker's password is replaced by one
// only the claiming phone is shown, so the sticker stops opening the
// network. AgentosdSetup is one.
type SetupWiFi interface {
	// SetupWiFi is the network's name and whether it is rotated;
	// ErrNoSetupWiFi when the box has none (not preloaded with one, or
	// burned at the Owner Card confirm).
	SetupWiFi() (ssid string, rotated bool, err error)
	// RotateSetupWiFi replaces the sticker's password with password, once.
	RotateSetupWiFi(password string) error
}

// ErrNoSetupWiFi: the box serves no setup network, so there is nothing to
// rotate.
var ErrNoSetupWiFi = errors.New("localui: no setup network")

// errWiFiRotated: the setup network's password was already rotated.
var errWiFiRotated = errors.New("localui: setup network already rotated")

// SetupWiFi reads the setup network's name from agentosd. A setup session
// that serves no setup Wi-Fi op (setup finished, or no -setup-net) counts
// as no setup network.
func (a AgentosdSetup) SetupWiFi() (string, bool, error) {
	var n localapi.SetupWiFiName
	err := a.call(localapi.OpSetupWiFiName, nil, &n)
	switch {
	case refused(err, localapi.ErrNoSetupWiFi), refused(err, string(sockets.ErrUnknownOp)):
		return "", false, ErrNoSetupWiFi
	case err != nil:
		return "", false, err
	}
	return n.SSID, n.Rotated, nil
}

// RotateSetupWiFi sends the new password to agentosd, which writes it
// root-only for agentos-ap (ARC-1). The password goes only there (CRED-1).
func (a AgentosdSetup) RotateSetupWiFi(password string) error {
	err := a.call(localapi.OpSetupWiFi, localapi.SetupWiFi{Password: password}, nil)
	switch {
	case refused(err, localapi.ErrNoSetupWiFi), refused(err, string(sockets.ErrUnknownOp)):
		return ErrNoSetupWiFi
	case refused(err, localapi.ErrWiFiRotated):
		return errWiFiRotated
	}
	return err
}

// claimWiFi is the claim's Wi-Fi step: the password the claimant is shown
// (made once per page process, so a reload shows the same one) and
// whether the step is over.
type claimWiFi struct {
	mu      sync.Mutex
	pending string
	done    bool
}

type claimWiFiView struct {
	SSID, Password string
	QR             template.HTML
	Err            string
}

func init() {
	template.Must(tmpl.Parse(`{{define "claimwifi"}}{{template "head" ""}}
<h1>Save my new Wi-Fi password</h1>
<p>You claimed me. Now I replace the Wi-Fi password on my sticker with a new one that only this phone sees, so the sticker no longer lets anyone onto my setup Wi-Fi.</p>
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{.QR}}
<p>Wi-Fi name: <span class="mono">{{.SSID}}</span><br>New password: <span class="mono">{{.Password}}</span></p>
<p><strong>Take a screenshot of this page, or write the password down, before you go on.</strong></p>
<p>When you tap the button, my Wi-Fi restarts with the new password and this phone drops off it. Join <span class="mono">{{.SSID}}</span> again with the new password (or scan the code above from your screenshot), then open <span class="mono">http://{{boxhost}}/setup</span> to carry on.</p>
<form method="post" action="/claim/wifi"><button>I saved it: switch now</button></form>
{{template "foot"}}{{end}}`))
	template.Must(tmpl.Parse(`{{define "claimwifidone"}}{{template "head" ""}}
<h1>Switching my Wi-Fi</h1>
<p>My Wi-Fi is restarting with the new password. Join <span class="mono">{{.SSID}}</span> again with the password you saved, then open <span class="mono">http://{{boxhost}}/setup</span>.</p>
<p><a href="/setup">Carry on with setup</a></p>
{{template "foot"}}{{end}}`))
}

// claimWiFiDone reports whether the claimant may go on to setup: the step
// is done, or the box has no setup network left to rotate. An error is
// agentosd not answering; the caller fails closed.
func (s *Server) claimWiFiDone() (bool, error) {
	c := s.claimWiFi
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return true, nil
	}
	_, rotated, err := s.cfg.SetupWiFi.SetupWiFi()
	switch {
	case errors.Is(err, ErrNoSetupWiFi):
		c.done = true
	case err != nil:
		return false, err
	case rotated:
		c.done = true
	}
	return c.done, nil
}

// claimWiFiGate keeps the claimant on the Wi-Fi step until it is done: a
// GET goes to /claim/wifi, anything else is refused. It reports whether it
// answered the request.
func (s *Server) claimWiFiGate(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.SetupWiFi == nil {
		return false
	}
	done, err := s.claimWiFiDone()
	switch {
	case err != nil:
		http.Error(w, "I could not read my setup Wi-Fi. Reload in a moment.", http.StatusServiceUnavailable)
		return true
	case done:
		return false
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		http.Redirect(w, r, "/claim/wifi", http.StatusSeeOther)
	default:
		http.Error(w, "Save my new Wi-Fi password first.", http.StatusForbidden)
	}
	return true
}

// claimWiFiPage is /claim/wifi, for the claimant only: GET shows the new
// password and its Wi-Fi QR; POST commits it (HW-10, #1692). A POST
// commits only the password a GET showed.
func (s *Server) claimWiFiPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Claim.Status().Claimed || !s.isClaimant(r) {
		http.Redirect(w, r, "/claim", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if done, err := s.claimWiFiDone(); err != nil {
		http.Error(w, "I could not read my setup Wi-Fi. Reload in a moment.", http.StatusServiceUnavailable)
		return
	} else if done {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	ssid, _, err := s.cfg.SetupWiFi.SetupWiFi()
	if err != nil {
		http.Error(w, "I could not read my setup Wi-Fi. Reload in a moment.", http.StatusServiceUnavailable)
		return
	}
	c := s.claimWiFi
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Method == http.MethodPost {
		if c.pending == "" {
			http.Redirect(w, r, "/claim/wifi", http.StatusSeeOther)
			return
		}
		err := s.cfg.SetupWiFi.RotateSetupWiFi(c.pending)
		switch {
		case err == nil:
			c.done = true
			s.render(w, "claimwifidone", claimWiFiView{SSID: ssid})
		case errors.Is(err, ErrNoSetupWiFi), errors.Is(err, errWiFiRotated):
			c.done = true
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
		default:
			s.showClaimWiFi(w, http.StatusServiceUnavailable, ssid, c.pending, "I could not switch my Wi-Fi. Try again.")
		}
		return
	}
	if c.pending == "" {
		pw, err := claim.NewSetupPassword(s.cfg.Rand)
		if err != nil {
			http.Error(w, "Page error", http.StatusInternalServerError)
			return
		}
		c.pending = pw
	}
	s.showClaimWiFi(w, http.StatusOK, ssid, c.pending, "")
}

func (s *Server) showClaimWiFi(w http.ResponseWriter, code int, ssid, pw, msg string) {
	qr, err := card.QRSVG(card.WiFiQR(ssid, pw))
	if err != nil {
		http.Error(w, "Page error", http.StatusInternalServerError)
		return
	}
	var b = claimWiFiView{SSID: ssid, Password: pw, QR: qr, Err: msg}
	if code != http.StatusOK {
		w.WriteHeader(code)
	}
	s.render(w, "claimwifi", b)
}
