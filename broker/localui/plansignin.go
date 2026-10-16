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
// login (CRED-5), so a stolen session alone must not start one.
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
		text = limitedText
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
	planCodeText   = "To sign in to your plan, enter a code from your code generator (not the one I texted)."
	planBusyText   = "A sign-in with ChatGPT is still waiting. Enter its code on ChatGPT's page, or try again once the code expires."
	planGoneText   = "Sign-in isn't needed now. Reload to see why."
	planFailedText = "Could not start sign-in with ChatGPT. Try again."
)
