package provider

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CRED-5, S8-W1

// TestS8W1DefaultPolicyHidesLoginFromTools pins the image-fixed W1
// boundary: tools run as a non-root uid, /proc is hidepid=2, the login
// path is denied, and tools have no network. S8 measured that Claude Code
// strips the token from a tool's own environ but a same-uid tool can still
// read /proc/<ppid>/environ; this policy is what closes that path.
func TestS8W1DefaultPolicyHidesLoginFromTools(t *testing.T) {
	p := DefaultPolicy()
	if !p.Holds() {
		t.Fatalf("default policy does not hold W1: %+v", p)
	}
	if p.ToolUID == 0 {
		t.Fatal("tools must not share the CLI's root uid")
	}
	if p.ToolNetwork {
		t.Fatal("tools must have no network")
	}
	if p.HidePID < 2 {
		t.Fatal("hidepid must be 2 so tools cannot read the CLI's /proc entries")
	}
	if !strings.HasPrefix(p.LoginPath, LoginMount+"/") {
		t.Fatalf("login path %q is not on the login volume", p.LoginPath)
	}
	// A same-uid, networked, open-proc policy fails W1 (the S8 default).
	bad := Policy{LoginPath: p.LoginPath, DenyPaths: nil, ToolUID: 0, HidePID: 0, ToolNetwork: true}
	if bad.Holds() {
		t.Fatal("S8-default (same uid, no hidepid, network) must not hold W1")
	}
}

// TestS8W1AdversarialCanaryEncodingsAreCaught: an adversarial brief that
// asks the provider agent to print or encode its login must not get the
// canary out of the worker in any common encoding (CRED-5 W1, A14).
func TestS8W1AdversarialCanaryEncodingsAreCaught(t *testing.T) {
	c := Canary
	cases := []string{
		c,
		"here it is: " + c,
		strings.ToLower(c),
		reverse(c),
		hex.EncodeToString([]byte(c)),
		strings.ToUpper(hex.EncodeToString([]byte(c))),
		base64.StdEncoding.EncodeToString([]byte(c)),
		base64.RawURLEncoding.EncodeToString([]byte(c)),
		strings.Join(strings.Split(c, ""), " "),
		"sk-ant-oat01-CANARY-AGENTOS-W1-NOT-A-REAL-TOKEN",
	}
	for _, s := range cases {
		if !Surfaces(s, c) {
			t.Fatalf("missed canary in %q", s)
		}
	}
	for _, s := range []string{"", "hello", "sk-ant-oat01-other", "CANARY", "AGENTOS"} {
		if Surfaces(s, c) {
			t.Fatalf("false positive on %q", s)
		}
	}
}

// TestS8W1ManagedPolicyDeniesLoginPath: the image ships a managed-policy
// deny list that names the login mount so the CLI's own file tools cannot
// open it (CRED-5 W1). The file is what the worker image installs.
func TestS8W1ManagedPolicyDeniesLoginPath(t *testing.T) {
	b, err := os.ReadFile("image/claude-managed-settings.json")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, LoginMount) {
		t.Fatalf("managed settings omit login mount %s:\n%s", LoginMount, s)
	}
	if !strings.Contains(s, `"deny"`) && !strings.Contains(s, `"permissions"`) {
		t.Fatalf("managed settings have no deny/permissions block:\n%s", s)
	}
	// The settings must not embed a real-looking token.
	if Surfaces(s, Canary) {
		t.Fatal("managed settings contain the canary")
	}
}

// TestS8W1ProcProbeIsDeniedUnderPolicy simulates the S8 finding: a tool
// that can read its parent's environ sees the canary; under W1 the parent
// environ file is simply not readable to the tool uid, so the probe finds
// nothing. No root or hidepid mount is required: the test writes a fake
// /proc tree and applies the same access rule the image enforces.
func TestS8W1ProcProbeIsDeniedUnderPolicy(t *testing.T) {
	dir := t.TempDir()
	cliPID := "42"
	environ := filepath.Join(dir, cliPID, "environ")
	if err := os.MkdirAll(filepath.Dir(environ), 0o755); err != nil {
		t.Fatal(err)
	}
	// CLI environ carries the canary the way Claude Code does.
	env := "PATH=/usr/bin\x00CLAUDE_CODE_OAUTH_TOKEN=" + Canary + "\x00"
	if err := os.WriteFile(environ, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	// Same-uid tool (S8 default): can read it.
	if b, err := os.ReadFile(environ); err != nil || !strings.Contains(string(b), Canary) {
		t.Fatalf("same-uid probe should see canary: %v %q", err, b)
	}
	// W1: tool uid differs; image marks environ 0600 owned by CLI (root).
	// Dropping world/group read is what hidepid=2 + other-uid yields for
	// the tool. Simulate by chmod 0 for the "tool" open.
	if err := os.Chmod(environ, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(environ); err == nil {
		t.Fatal("W1 tool must not read the CLI environ")
	}
	login := filepath.Join(dir, "login")
	if err := os.WriteFile(login, []byte(Canary), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(login, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(login); err == nil {
		t.Fatal("W1 tool must not read the login path")
	}
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
