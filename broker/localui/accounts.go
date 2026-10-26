package localui

import (
	"context"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// AgentosdAccounts is Accounts over agentosd's account ops on localui.sock
// (#3006): agentosd checks the session, bounds each field again and passes
// the frame to the account's clerk across the keeper boundary (D-154 rule
// 1). The page treats every failure as the clerk's silence: Begin's
// generic text, or Finish's "start again".
type AgentosdAccounts struct{ Owner Owner }

// finishFor bounds Finish, which redeems the code at the provider.
const finishFor = 70 * time.Second

func (a AgentosdAccounts) Begin(ctx context.Context, session, account, use string, reg *AccountRegistration) (consent, detail string) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	in := localapi.AccountBegin{Token: session, Account: account, Use: use}
	if reg != nil {
		in.Registration = &localapi.AccountRegistration{ID: reg.ID, Secret: reg.Secret}
	}
	var out localapi.AccountBegun
	if a.Owner.Call(ctx, localapi.OpAccountBegin, in, &out) != nil {
		return "", localapi.ErrFailed
	}
	return out.Consent, out.Detail
}

func (a AgentosdAccounts) Finish(ctx context.Context, session, account, use, pasted string) string {
	ctx, cancel := context.WithTimeout(ctx, finishFor)
	defer cancel()
	var out localapi.AccountFinished
	if a.Owner.Call(ctx, localapi.OpAccountFinish, localapi.AccountFinish{Token: session, Account: account, Use: use, Pasted: pasted}, &out) != nil {
		return localapi.ErrFailed
	}
	return out.Detail
}

// planFor bounds Plan: a first plan reads the senders of the newest mail.
// The clerk goes on to the end and keeps the plan, so the page opened again
// gets it at once.
const planFor = 30 * time.Second

// Plan is setup's account plan over OpAccountPlan (AccountPlan).
func (a AgentosdAccounts) Plan(ctx context.Context, session string) (localapi.AccountPlanned, bool) {
	ctx, cancel := context.WithTimeout(ctx, planFor)
	defer cancel()
	var out localapi.AccountPlanned
	if a.Owner.Call(ctx, localapi.OpAccountPlan, localapi.Auth{Token: session}, &out) != nil {
		return localapi.AccountPlanned{}, false
	}
	return out, true
}
