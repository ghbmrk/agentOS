// Package mailtest is the old mail adapter's name for the mail clerk's test
// server (broker/clerk/inbox/imapsmtp/imaptest). It is transitional: MIG-4-mail's
// delete (2574b, #2574) removes it with broker/mail.
package mailtest

import "github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"

type (
	Server     = imaptest.Server
	Submission = imaptest.Submission
	Message    = imaptest.Message
)

const (
	User     = imaptest.User
	Password = imaptest.Password
	Token    = imaptest.Token
)

// Start runs a server until the test ends.
var Start = imaptest.Start
