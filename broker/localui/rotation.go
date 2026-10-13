package localui

import (
	"net/http"

	"github.com/ghbmrk/agentos/broker/card"
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
		rot.serveCard(d, s.isSignedIn, "/rotate/done", w, r)
		return
	}
	d.Handler(s.isSignedIn, "/home").ServeHTTP(w, r)
}
