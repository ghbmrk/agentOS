package line

// REQ: CLK-1, CLK-8

import (
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The clerk runs in the keeper (D-154 option A): it links no SIP or SRTP
// stack, which parse what providers and third parties send, and no texting
// client. Its own files import only these broker packages and the digest
// arithmetic sipsign already links; the line process (part b) runs sipline.
func TestTheClerkLinksNoSIPStack(t *testing.T) {
	const module = "github.com/ghbmrk/agentos/broker/"
	allowed := []string{"clerk", "clerk/check", "kernel", "kernel/key", "sipsign", "sendrules", "github.com/icholy/digest"}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			own := strings.TrimPrefix(p, module)
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && !slices.Contains(allowed, own) && !slices.Contains(allowed, p) {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, s := range []string{"github.com/emiago/sipgo", "github.com/pion/", module + "modem/", module + "smsapi"} {
			if strings.HasPrefix(dep, s) {
				t.Errorf("the clerk links %s", dep)
			}
		}
	}
	if !strings.Contains(string(out), module+"sipsign") {
		t.Error("the clerk does not link sipsign; the fence above checks nothing")
	}
}

// sign.go is the whole signing binding, so it drops cleanly under D-154
// option B: no other file of the clerk names its types.
func TestTheSigningBindingIsOneFile(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if f == "sign.go" || strings.HasSuffix(f, "_test.go") {
			continue
		}
		out, err := exec.Command("grep", "-nE", `\bSigner\b|NewSigner|digest\.[A-Z]|ErrUnbound|ErrRegisterRate`, f).Output()
		if err == nil && len(out) > 0 {
			t.Errorf("%s names the signing binding:\n%s", f, out)
		}
	}
}
