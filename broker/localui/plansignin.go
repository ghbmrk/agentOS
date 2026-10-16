package localui

import (
	"context"
	"net/http"
	"strings"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// planSignIn starts the owner's plan sign-in again after setup (ONB-3,
// ONB-9, #1264), from the home page's form. Like adopting a SIM it always
// takes a code: whoever approves the provider's code becomes the plan's
// login (CRED-5), so a stolen session alone must not start one. The
// session that started a sign-in still waiting gets its link and code back
// (#1945). Each text names a step that works in its state (CH-12).
func (s *Server) planSignIn(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	if strings.HasPrefix(code, owner.UnlockProofPrefix) || len(code) > localapi.MaxCode {
		s.homeView(w, r, "", "", wrongCodeText, localapi.DeviceCode{})
		return
	}
	// The CLI may take most of DeviceCodeTimeout to print its code.
	ctx, cancel := context.WithTimeout(r.Context(), localapi.DeviceCodeTimeout)
	defer cancel()
	var a localapi.PlanSignInStarted
	err := s.callFor(ctx, localapi.OpPlanSignIn, localapi.PlanSignInStart{Token: cookieToken(r), Code: code}, &a)
	text := ""
	switch {
	case refused(err, localapi.ErrLimited):
		// Past the bound on starts or on wrong codes: not only codes.
		text = planLimitedText
	case refused(err, localapi.ErrSignInBusy):
		text = planBusyText
	case refused(err, localapi.ErrBadArgs):
		text = planGoneText
	case err != nil:
		text = planFailedText
	case a.Refusal == localapi.RefusedCodeNeeded:
		text = planCodeText
	case a.Refusal != "":
		text = refusalText(a.Refusal, a.Text)
	case a.Link == "":
		text = planFailedText
	}
	s.homeView(w, r, "", "", text, a.DeviceCode)
}

const (
	planCodeText = "To sign in to your plan, enter a code from your code generator (not the one I texted)."
	// planBusyText is shown only when the page does not hold the waiting
	// sign-in's code (the session it is kept for gets the code back), so
	// it names when that code expires: localapi.PlanSignInWait.
	planBusyText    = "Another sign-in with ChatGPT is still waiting. Try again in 15 minutes, once its code expires."
	planLimitedText = "Too many tries on this Wi-Fi. Wait a minute, then try again."
	planGoneText    = "Sign-in isn't needed now. Reload to see why."
	planFailedText  = "Could not start sign-in with ChatGPT. Try again."
)
