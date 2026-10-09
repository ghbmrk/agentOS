package mailsock_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: CRED-1

// forbidden are what mailsock must never reach, directly or through
// anything it imports: the mail protocol client that holds the
// credential, and any network client or launcher (W1-c, M1).
var forbidden = []string{"github.com/ghbmrk/agentos/broker/mail/imapsmtp", "crypto/tls", "net/smtp", "net/http", "os/exec"}

// TestClientLinksNoCredentialOrNetworkClient (W1-c): the package
// agentosd links to reach the mailbox carries no IMAP or SMTP client, no
// TLS and no HTTP client, so the mailbox credential and the server stay
// in the vault process.
func TestClientLinksNoCredentialOrNetworkClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	if bad := forbiddenIn(strings.Fields(string(out))); bad != nil {
		t.Fatalf("mailsock depends on %v", bad)
	}
}

func forbiddenIn(deps []string) []string {
	var bad []string
	for _, d := range deps {
		for _, f := range forbidden {
			if d == f || strings.HasPrefix(d, "github.com/emersion/") {
				bad = append(bad, d)
				break
			}
		}
	}
	return bad
}

// TestForbiddenListCatchesImapsmtp: the check above sees imapsmtp when
// it is linked (the mutant: import it from a non-test mailsock file).
func TestForbiddenListCatchesImapsmtp(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../imapsmtp").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	bad := forbiddenIn(strings.Fields(string(out)))
	if len(bad) == 0 || !strings.Contains(strings.Join(bad, " "), "imapsmtp") {
		t.Fatalf("imapsmtp's deps not caught: %v", bad)
	}
}

// TestDialsOnlyUnix: mailsock refers to net only for a connection and a
// dialer, and every dial names "unix", as modelroute does.
func TestDialsOnlyUnix(t *testing.T) {
	fs := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		pf, err := parser.ParseFile(fs, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(pf, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" && x.Sel.Name != "Conn" && x.Sel.Name != "Dialer" {
					t.Errorf("%s uses net.%s", f, x.Sel.Name)
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "Dial") {
					if len(x.Args) < 2 {
						t.Errorf("%s: %s with no network", f, sel.Sel.Name)
						return true
					}
					lit, ok := x.Args[1].(*ast.BasicLit)
					if v, _ := strconv.Unquote(litValue(lit, ok)); v != "unix" {
						t.Errorf("%s: %s dials a network other than unix", f, sel.Sel.Name)
					}
				}
			}
			return true
		})
	}
}

func litValue(l *ast.BasicLit, ok bool) string {
	if !ok {
		return ""
	}
	return l.Value
}
