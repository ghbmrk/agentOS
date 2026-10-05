package daemon

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: ARC-2

// The control path is every package that STOP, RESUME, STATUS, HELP, and
// admission run through. ARC-2 says none of it may invoke inference. Model
// access needs a network client or a child process, so the control path may
// import neither, and may import only these broker packages. A future model
// egress package lives outside this list; wiring it into the control path
// fails this test.
var controlPath = map[string][]string{
	"journal":   {},
	"control":   {"journal"},
	"admission": {},
	"sockets":   {},
	"cgroup":    {},
	"owner":     {"control", "journal", "modem"},
	"modem":     {},
	// The approval policy (grants) runs inside the engine's checks, so it
	// is on the control path too; adapters reach it only through its
	// Verifier interface.
	"grants": {"journal", "owner", "verb"},
	"verb":   {},
	"daemon": {"journal", "control", "admission", "sockets", "owner", "modem", "grants"},
	// The composition root also opens the machine plane (below) and hands
	// it to admission as a Preempter, and serves the guest plane (below)
	// on each machine's socket.
	// It forwards each machine's model route to the vault process
	// (modelroute, P2-4) and journals the denials that come back.
	"cmd/agentosd": {"daemon", "cgroup", "vm", "vm/gvisor", "guest", "meter", "modelroute", "journal"},
}

// compositionRoot links the machine plane, so its transitive dependencies
// include runsc's launcher; it is excluded from the transitive check, and
// the machine plane is held to its own rules below.
const compositionRoot = "cmd/agentosd"

// The machine plane runs agent machines (P1-4). Admission reaches it only
// through the admission.Preempter interface. It may not open network
// clients or use third-party code; only vm/gvisor may start a process, and
// only runsc (vm/gvisor TestOnlyRunscIsExecuted).
var machinePlane = map[string]struct {
	allowed []string
	forbid  []string
}{
	"vm":         {[]string{"admission", "cgroup", "vm/overlay"}, forbiddenStd},
	"vm/overlay": {nil, []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}},
	"vm/gvisor":  {[]string{"vm", "vm/overlay"}, []string{"net", "net/http", "net/rpc", "net/smtp", "plugin", "unsafe", "C"}},
}

// The guest plane serves each machine's ARC-6 socket (P1-7). STOP,
// STATUS, and admission never import it (the control path's allowed lists
// above). It holds no credential: model egress and the vault are other
// packages it may not import, and the composition root may not link them
// (TestDaemonLinksNoCredentialCustody).
var guestPlane = map[string]struct {
	allowed []string
	forbid  []string
}{
	"guest": {[]string{"journal", "meter", "route"}, []string{"os/exec", "plugin", "unsafe", "C"}},
	"meter": {nil, []string{"net", "os/exec", "plugin", "unsafe", "C"}},
	// modelroute forwards to the vault process over its Unix socket and
	// reports usage to the meter; never the vault or the proxy.
	"modelroute": {[]string{"meter"}, []string{"os/exec", "plugin", "unsafe", "C"}},
	"route":      {nil, []string{"net", "os/exec", "plugin", "unsafe", "C"}},
}

var forbiddenStd = []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "syscall", "unsafe", "C"}

// stdExceptions are the forbidden standard packages a control-path package
// may still use, and why.
var stdExceptions = map[string][]string{
	"sockets":      {"net", "syscall"}, // Unix listeners, SO_PEERCRED, flock
	"cmd/agentosd": {"syscall"},        // signal numbers for shutdown
	"journal":      {"syscall"},        // flock on the journal file
}

// Never anywhere in the control path's transitive dependencies.
var forbiddenDeps = []string{"net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "crypto/tls"}

const module = "github.com/ghbmrk/agentos/broker/"

func TestARC2ControlPathCannotReachInference(t *testing.T) {
	for pkg, allowed := range controlPath {
		checkImports(t, pkg, allowed, forbiddenStd, stdExceptions[pkg])
	}
	for pkg, rule := range machinePlane {
		checkImports(t, pkg, rule.allowed, rule.forbid, nil)
	}
	for pkg, rule := range guestPlane {
		checkImports(t, pkg, rule.allowed, rule.forbid, nil)
	}
}

// TestDaemonLinksNoCredentialCustody: the daemon process, which serves the
// guest sockets, links neither the vault, the credentialed egress proxy,
// nor the TPM seal (vault V2, ARC-1, P2-4b). Model egress runs where the vault is unlocked (P2-4).
func TestDaemonLinksNoCredentialCustody(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-deps", "./"+compositionRoot).Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == module+"vault" || dep == module+"egress" || dep == module+"tpmseal" {
			t.Errorf("agentosd links %s", dep)
		}
	}
}

func checkImports(t *testing.T, pkg string, allowed, forbidden, exceptions []string) {
	t.Helper()
	root := ".."
	files, err := filepath.Glob(filepath.Join(root, pkg, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("%s: no sources (%v)", pkg, err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			switch {
			case strings.HasPrefix(p, module):
				if !contains(allowed, strings.TrimPrefix(p, module)) {
					t.Errorf("%s imports %s, outside the control path", f, p)
				}
			case strings.Contains(strings.SplitN(p, "/", 2)[0], "."):
				t.Errorf("%s imports third-party %s (DEP-1, ARC-2)", f, p)
			case contains(exceptions, p):
			case contains(forbidden, p):
				t.Errorf("%s imports %s; the control path may not open network clients or child processes", f, p)
			}
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestARC2TransitiveDepsHaveNoNetworkClientOrLauncher(t *testing.T) {
	var pkgs []string
	for pkg := range controlPath {
		if pkg != compositionRoot {
			pkgs = append(pkgs, "./"+pkg)
		}
	}
	out, err := exec.Command("go", append([]string{"list", "-C", "..", "-deps"}, pkgs...)...).Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if contains(forbiddenDeps, dep) {
			t.Errorf("control path depends on %s", dep)
		}
	}
}
