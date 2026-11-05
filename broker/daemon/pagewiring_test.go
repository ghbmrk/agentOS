package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: P2-2w, CH-7, CRED-5, OSS-10, W5a-resume

// pageSeed is a synthetic code-generator seed for the page's sign-in.
var pageSeed = []byte("synthetic-page-seed-0123")

type pagePlan struct{ localsrv.PlanSignIn }

func (pagePlan) Ready() bool   { return true }
func (pagePlan) Waiting() bool { return false }

type pageAccount struct{ localsrv.AccountSignIn }

func (pageAccount) Begin(context.Context, string, *localapi.AccountRegistration) (string, string, error) {
	return "https://consent.example.test/a", "", nil
}

type pageForget struct{}

func (pageForget) PageTasks(bool) localapi.ForgetTasks {
	return localapi.ForgetTasks{Tasks: []localapi.ForgetTask{{ID: "goal-1", Date: "Nov 5", Label: "a task"}}}
}
func (pageForget) PageForget(context.Context, string, bool) string { return "forgotten" }

type pagePasskeys struct{ localsrv.Passkeys }
type pageBackups struct{ localsrv.Backups }
type pageRecovery struct{ localsrv.Recovery }

// startPage runs agentosd serving the page with every optional part set,
// and returns its socket and a signed-in session's token.
func startPage(t *testing.T) (sock, token string, d *Daemon) {
	t.Helper()
	dir := t.TempDir()
	_, d = startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		c.OwnerSecrets = ownerch.Secrets{TOTPSeed: pageSeed}
		c.Modem = modem.NewCarrier().Line("+15550000009")
		c.Redactor = func(s string) string { return s }
		c.Executors = map[string]journal.Executor{"mail": unknownExec{}, "bank": unknownExec{}}
		c.Grants.Declared = map[string]map[string]string{"mail": {"message.send": "send"}, "bank": {"message.send": "send"}}
		c.PageSocket = &PageSocket{
			UID:        os.Getuid(),
			PlanSignIn: pagePlan{},
			Accounts:   map[string]localsrv.AccountSignIn{"mail": pageAccount{}},
			Passkeys:   pagePasskeys{}, Backups: pageBackups{}, Recovery: pageRecovery{},
			BackupNotes: func() []string { return []string{"only one copy"} },
			Held:        func() localapi.HeldList { return localapi.HeldList{} },
			Forget:      pageForget{},
			DescribeRoot: func(context.Context, []byte, [][]byte) (localapi.RootSummary, error) {
				return localapi.RootSummary{Version: 7}, nil
			},
		}
	})
	sock = filepath.Join(dir, "run", localapi.Socket)
	r := send(t, sock, localapi.OpSignIn, localapi.SignIn{Code: ownerch.TOTP(pageSeed, time.Now())})
	var ses localapi.Session
	if !r.OK || json.Unmarshal(r.Result, &ses) != nil || ses.Token == "" {
		t.Fatalf("sign-in: %+v", r)
	}
	return sock, ses.Token, d
}

// Every part of the page agentosd is given reaches the page: the plan's
// sign-in, the account clerks, the backups notice and ops, the recovery
// ops, what was held, FORGET's tasks, and what following a root would
// change (P2-2w; #1264, #3006, BAK-1, REC-4, #993, W3-forget-b3r, OSS-10).
func TestEveryPagePartAgentosdIsGivenReachesThePage(t *testing.T) {
	sock, tok, _ := startPage(t)
	auth := localapi.Auth{Token: tok}
	var plan localapi.PlanSignIn
	if r := send(t, sock, localapi.OpPlanSignInReady, auth); !r.OK || json.Unmarshal(r.Result, &plan) != nil || !plan.Ready {
		t.Errorf("plan sign-in: %+v", r)
	}
	var begun localapi.AccountBegun
	if r := send(t, sock, localapi.OpAccountBegin, localapi.AccountBegin{Token: tok, Account: "mail", Use: "mail"}); !r.OK ||
		json.Unmarshal(r.Result, &begun) != nil || begun.Consent != "https://consent.example.test/a" {
		t.Errorf("account begin: %+v", r)
	}
	var st localapi.Status
	if r := send(t, sock, localapi.OpStatus, struct{}{}); !r.OK || json.Unmarshal(r.Result, &st) != nil || !slices.Equal(st.Backups, []string{"only one copy"}) {
		t.Errorf("status's backups notice: %+v", r)
	}
	for _, op := range []string{localapi.OpBackups, localapi.OpRecoveryBegin, localapi.OpHeld} {
		if r := send(t, sock, op, struct{}{}); r.Error == "unknown op" {
			t.Errorf("%s is not served", op)
		}
	}
	var tasks localapi.ForgetTasks
	if r := send(t, sock, localapi.OpForgetTasks, auth); !r.OK || json.Unmarshal(r.Result, &tasks) != nil || len(tasks.Tasks) != 1 {
		t.Errorf("forget tasks: %+v", r)
	}
	var txt localapi.Text
	if r := send(t, sock, localapi.OpForget, localapi.Forget{Token: tok, ID: "goal-1"}); !r.OK || json.Unmarshal(r.Result, &txt) != nil || txt.Text != "forgotten" {
		t.Errorf("forget: %+v", r)
	}
	var sum localapi.RootSummary
	if r := send(t, sock, localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: []byte("root")}); !r.OK ||
		json.Unmarshal(r.Result, &sum) != nil || sum.Version != 7 {
		t.Errorf("follow root: %+v", r)
	}
}

// The page lists every paused grant the gate holds (W5a-resume).
func TestThePageListsEveryPausedGrant(t *testing.T) {
	_, _, d := startPage(t)
	g, ctx := d.Gate(), context.Background()
	var ids []string
	for i, acct := range []string{"mail", "bank"} {
		id := "local/grant/" + acct
		spec := map[string]any{"grant": map[string]any{"account": acct, "executor": acct, "ops": map[string]any{"message.send": "send"}}}
		if _, err := g.Submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount,
			Action: journal.ActionGrantChange, Params: spec, Executor: grants.ExecutorName}); err != nil {
			t.Fatal(err)
		}
		if st, err := g.Authorize(ctx, id); err != nil || st.State != journal.Pending {
			t.Fatalf("grant %d: %s %q %v", i, st.State, st.Permission.Reason, err)
		}
		g.Flush()
		reqs := d.Owner().LocalRequests()
		if len(reqs) == 0 {
			t.Fatalf("grant %d: nothing asked on the page", i)
		}
		req := reqs[len(reqs)-1]
		for n, it := range req.Items {
			g.Decide(ownerch.Decision{Request: req.ID, Item: n + 1, Ref: it.Ref, Approved: true, Why: "owner", Page: true, Sum: ownerch.ItemSum(it)})
		}
		g.Wait()
		st, err := d.Engine().Get(id)
		if err != nil || st.State != journal.Succeeded {
			t.Fatalf("grant %d: %s %v", i, st.State, err)
		}
		gid := st.Attempts[len(st.Attempts)-1].Evidence
		pause := "loop2/pause/" + gid
		if _, err := g.Submit(journal.Intent{ID: pause, Origin: grants.OriginLoop2, Account: journal.BrokerAccount,
			Action: journal.ActionGrantPause, GrantRef: gid, Executor: grants.ExecutorName, Params: map[string]any{"finding": "advisory:f1"}}); err != nil {
			t.Fatal(err)
		}
		if st, err := g.Authorize(ctx, pause); err != nil || st.State != journal.Authorized {
			t.Fatalf("pause %d: %s %v", i, st.State, err)
		}
		if st, err := g.Dispatch(ctx, pause); err != nil || st.State != journal.Succeeded {
			t.Fatalf("pause %d: %s %v", i, st.State, err)
		}
		ids = append(ids, gid)
	}
	var got []string
	for _, p := range pausedGrants(g) {
		got = append(got, p.ID)
	}
	slices.Sort(got)
	slices.Sort(ids)
	if !slices.Equal(got, ids) {
		t.Fatalf("the page lists %q paused, want %q", got, ids)
	}
}
