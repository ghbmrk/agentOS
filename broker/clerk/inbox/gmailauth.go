package inbox

import (
	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Google's consent page and revocation endpoint for an installed-app client
// (D-150). The consent page is never dialed: the owner opens it on their
// phone.
const (
	GmailConsent = "https://accounts.google.com/o/oauth2/v2/auth"
	GmailRevoke  = "https://oauth2.googleapis.com/revoke"
)

// GmailUses is the one scope each declared use of a Gmail account asks for
// (CLK-9, SPEC §12.1 step 7): metadata to watch, read-only to archive, modify
// to sort or trim. Modify also sends as the owner, which the owner page says
// before it begins that sign-in. The values are Google's scope names, never
// dialed.
var GmailUses = map[string]string{
	"watch":   "https://www.googleapis.com/auth/gmail.metadata",
	"archive": "https://www.googleapis.com/auth/gmail.readonly",
	"sort":    "https://www.googleapis.com/auth/gmail.modify",
}

// GmailRedirect is the loopback address consent returns to. Nothing listens
// on it, so the owner's phone shows a page that does not load, and the owner
// pastes its address on the owner page (D-150 item 4).
const GmailRedirect = "http://127.0.0.1:8521/agentos"

// GmailReconnect is the owner text for a Gmail grant the token endpoint
// refused (reconnect). It names both causes, since a client left in Testing
// loses its grants 7 days after consent (D-150 item 3) and looks the same.
const GmailReconnect = "Gmail stopped letting me in. Either the sign-in was removed or ran out, " +
	"or your Google client is still in Testing, which ends every sign-in after 7 days: " +
	"set it to In production, then sign in again on the owner page."

// GmailSignIn is the sign-in for a Gmail account whose grant lives in slot,
// at consent, token and revoke (GmailConsent, GmailToken, GmailRevoke, or a
// fake's). access_type=offline asks for a refresh token, and prompt=consent
// asks for one again on a reconnect.
func GmailSignIn(consent, token, revoke, slot string, guard *netguard.Policy, clock clerk.Clock) clerk.SignInDeclaration {
	return clerk.SignInDeclaration{Name: Name, Auth: consent, Token: token, Revoke: revoke, Redirect: GmailRedirect,
		Uses: GmailUses, Params: map[string]string{"access_type": "offline", "prompt": "consent"},
		Slot: slot, Guard: guard, Clock: clock}
}
