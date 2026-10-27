package guest

// MIG-4-guest-result-codes (#3262): the guest's result filter is an
// allowlist by value. A clerk detail that has a code's shape but is not a
// listed code (a lowercase word from a mail or a page, an error's text) never
// reaches the planner.
//
// REQ: PLN-1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/follow/followclerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// clerkConsts are the clerks' named result codes, by the constant each
// clerk answers with, so a constant renamed or given another value fails
// here rather than silently drop or pass a code.
var clerkConsts = []string{
	proc.DUnreachable, proc.DLost, proc.DView, proc.DTooLarge,

	clerk.RClaim, clerk.RDispatch, clerk.RHold, clerk.DTooLarge,
	clerk.DSent, clerk.DDone, clerk.DUndeclared, clerk.DArg, clerk.DCredential, clerk.DBlocked,
	clerk.DNoAnswer, clerk.DInflight, clerk.DAuth, clerk.DDeclined, clerk.DNotFound,
	clerk.DRejected, clerk.DTimeout, clerk.DConflict, clerk.DBusy, clerk.DRedirect,
	clerk.DServer, clerk.DRefresh, clerk.DReconnect,
	clerk.DSignedIn, clerk.DNoSignIn, clerk.DNotOurs, clerk.DState, clerk.DUse, clerk.DRefused,
	clerk.DScope, clerk.DNoGrant, clerk.DExchange, clerk.DRevoked, clerk.DNoRevoke,
	clerk.DNoAccount, clerk.DRegistered,

	run.DNotApproved, run.DNotStaged, run.DNotThis,
	run.DNoAccount, run.DSignInRefused, run.DNoSignIn, run.DReconnect, run.DGmailAddress, run.DNotGmail,
	run.DPlanNotAllowed, run.DPlanConsent, run.DSignInBusy, run.DSignInCode, run.DSignInFailed,
	run.DSignInTimedOut, run.DSignInStopped, run.DSignedIn, run.DRequalify, run.DPlanRefused, run.DPlanMeter,

	plan.DUnmetered, plan.DBody, plan.DUndeclared, plan.DPlaceholder, plan.DStopped,
	plan.DUnswappable, plan.DExchange, plan.DSave, plan.DEncoded, plan.DStale, plan.DEnded,

	followclerk.RVerb, followclerk.ROwner, followclerk.RMalformed,
}

// clerkLiterals are the codes a clerk writes as a literal at its answer,
// by the file that holds the literal.
var clerkLiterals = map[string][]string{
	"../clerk/clerk.go":   {"fault"},
	"../browser/clerk.go": {"unapproved", "verb"},
	"../clerk/inbox/inbox.go": {"unconfirmed", "unclassified", "not-dispatched", "unknown-mail",
		"bad-label", "not-trashable", "no-alert-guard", "alert", "trash-not-restorable",
		"unknown-sender", "no-longer-eligible", "outside-key"},
}

// TestCodesAreTheClerksCodes holds the allowlist to the codes the kernel,
// the key and the clerks answer with, both ways: every listed code has a
// source, and every named or literal clerk code is listed.
func TestCodesAreTheClerksCodes(t *testing.T) {
	src := set(clerkConsts...)
	for _, c := range []string{kernel.CKey, kernel.CUngranted, kernel.CGrantHeld, kernel.CCutOff,
		kernel.CPlan, kernel.CDuplicate, kernel.CClerk, kernel.CPool, kernel.CNotHeld,
		kernel.CExtension, kernel.CHeld, kernel.CBroken, kernel.CInFlight, kernel.CTask, kernel.CCosign} {
		src[c] = true
	}
	for c := range refusalCodes(t) {
		src[c] = true
	}
	for file, lits := range clerkLiterals {
		in := literals(t, file)
		for _, l := range lits {
			if !in[l] {
				t.Errorf("%s no longer answers %q", file, l)
			}
			src[l] = true
		}
	}
	for c := range codes {
		if !src[c] {
			t.Errorf("listed code %q has no clerk, kernel or key source", c)
		}
		if !nameRE.MatchString(c) {
			t.Errorf("listed code %q is not a lowercase name", c)
		}
	}
	for c := range src {
		if !codes[c] {
			t.Errorf("clerk code %q is not listed, so the guest never sees it", c)
		}
	}
}

// refusalCodes are the key package's exported refusal codes (authorize.go's
// R constants), read from its source so a new one is listed or fails here.
func refusalCodes(t *testing.T) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "../kernel/key/authorize.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if len(n.Name) < 2 || n.Name[0] != 'R' || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, _ := strconv.Unquote(lit.Value)
					out[v] = true
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no refusal codes found in key/authorize.go")
	}
	return out
}

// literals are the string literals in a Go source file.
func literals(t *testing.T, file string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil {
				out[v] = true
			}
		}
		return true
	})
	return out
}

// TestCodePassesOnlyListedValues: a detail with a code's shape that no clerk
// answers with, such as a word a follow clerk's error or a mail carried, is
// dropped like free text; a listed code passes as it is.
func TestCodePassesOnlyListedValues(t *testing.T) {
	for _, s := range []string{"wire-funds-to-attacker", "ignore-your-key", "eof", "ok", "already", ""} {
		if nameRE.MatchString(s) && code(s) != "" {
			t.Errorf("code(%q) = %q, want it dropped", s, code(s))
		}
	}
	for _, c := range slices.Sorted(maps.Keys(codes)) {
		if code(c) != c {
			t.Errorf("code(%q) = %q, want it kept", c, code(c))
		}
	}
}
