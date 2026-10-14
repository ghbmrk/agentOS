package localui

import (
	"context"
	"net/http"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// RotationCard is a waiting card rotation (REC-4) as the page sees it: the
// new parts' display (card.Display in rotation mode), whose confirm
// commits the rotation and erases the display copy.
type RotationCard interface {
	// Display is the waiting rotation's display; nil when none waits.
	Display() *card.Display
}

// rotationCard serves the waiting rotation's display (card.Display.Handler)
// to a signed-in phone, behind the Host, same-origin and subnet checks of
// ServeHTTP. The confirm, cancel and lapse return the phone home.
func (s *Server) rotationCard(w http.ResponseWriter, r *http.Request) {
	d := s.cfg.Rotation.Display()
	if d == nil {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}
	if rot, ok := s.cfg.Rotation.(*Rotation); ok {
		// The vault process's rotation: its result shows once there, to
		// the confirming session (#1316).
		rot.serveCard(d, s.isSignedIn, s.rotateAPNet, "/rotate/done", w, r)
		return
	}
	d.Handler(s.isSignedIn, "/home").ServeHTTP(w, r)
}

// rotateAPNet hands a committed rotation's Wi-Fi network to agentosd as
// the confirming session, which writes it for the access point (#1191).
// The commit has already stood, so the hand-off is not bound to the
// request's own context.
func (s *Server) rotateAPNet(r *http.Request, ssid, password string) error {
	return s.call(context.Background(), localapi.OpRotateAPNet,
		localapi.RotateAPNet{Token: cookieToken(r), SSID: ssid, Password: password}, nil)
}
