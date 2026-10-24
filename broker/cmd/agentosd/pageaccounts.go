package main

import (
	"errors"
	"os"

	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/localsrv/accountsock"
)

// pageAccounts is the Connect page's account sign-ins (#3006): Gmail, by
// localui.GmailConnect's ID, on the mail clerk's owner socket, called only
// on the mail process's own uid. No socket serves no account.
func pageAccounts(mailOwner string, mailUID int, others ...int) (map[string]localsrv.AccountSignIn, error) {
	if (mailOwner == "") != (mailUID < 0) {
		return nil, errors.New("-mail-owner and -mail-uid go together")
	}
	if mailOwner == "" {
		return nil, nil
	}
	for _, uid := range append(others, os.Getuid()) {
		if mailUID == uid {
			return nil, errors.New("-mail-uid must name the mail clerk's own uid, distinct from the broker's, the local UI's and the modem bridge's")
		}
	}
	return map[string]localsrv.AccountSignIn{"gmail": accountsock.Gmail{Socket: mailOwner, UID: mailUID}}, nil
}
