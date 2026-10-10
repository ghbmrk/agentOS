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
	"journal": {},
	// The journal checker (SIM-check): pure predicates over records.
	"journal/check": {"journal"},
	"control":       {"journal"},
	"admission":     {},
	"sockets":       {},
	"cgroup":        {},
	"budget":        {"admission", "cgroup"}, // RES-2 component budget (P2-5)
	"accel":         {"admission"},           // RES-3 discovery from sysfs (P2-5)
	"owner":         {"boxname", "control", "journal", "modem"},
	"modem":         {},
	"boxname":       {}, // CH-21 name check, for NAME
	// The modem bridge's contract and agentosd's end of it (P2-3w): types
	// and an in-process queue; the bridge's client is bridgeclient.
	"bridgeproto": {},
	"modemlink":   {"bridgeproto", "modem", "sockets"},
	// The local UI's contract and agentosd's end of it (P2-2w): agentosd
	// serves the page's ops on the owner channel; the local UI, which
	// decodes untrusted photos, stays in its own process (L15).
	"localapi": {"owner"},
	"localsrv": {"localapi", "owner", "sockets"},
	// The approval policy (grants) runs inside the engine's checks, so it
	// is on the control path too; adapters reach it only through its
	// Verifier interface. Its refusals' guest text is guesterr's (SR2-3j),
	// which imports nothing beyond the standard library.
	"grants": {"guesterr", "journal", "owner", "reversible", "verb"},
	"verb":   {},
	// Reversible forms (REV-3) are declarations the gate validates: pure
	// data, held to the control path's rules.
	"reversible": {"journal", "verb"},
	"daemon":     {"journal", "journal/check", "control", "admission", "sockets", "owner", "modem", "grants", "localapi", "localsrv"},
	// The composition root also opens the machine plane (below) and hands
	// it to admission as a Preempter, and serves the guest plane (below)
	// on each machine's socket.
	// It forwards each machine's model route to the vault process
	// (modelroute, P2-4) and journals the denials that come back, and
	// gives the owner channel the vault process's verify operation
	// (owner.Verifier, egress K7). It keeps the owner's agent machine
	// running as foreground work (admission.Foreground, RES-1). It runs the
	// learning plane in-process (W3): the change pipeline, the loop
	// scheduler, and the replay evaluator, whose transitive imports
	// TestAgentosdLinksNoInference holds free of inference. It names the
	// grants gate's types to harvest the owner's verdicts (PW3 on #90).
	// Loop 1's skill compiler (compile) is its one in-process builder: it
	// calls no model and imports only the skill file format (W3 step 3a).
	// Every other builder runs in its own machine behind loopbuild's
	// socket (W3-builder).
	// It runs the owner-question book (W9) on the box clock (P2-9).
	// clock imports golang.org/x/sys/unix (adjtimex), so it has no entry
	// below, whose rules refuse third-party imports; TestAgentosdLinks-
	// NoInference holds it instead, through netOK.
	// It opens recall (recalltool) once the vault process hands over the
	// identity key, and serves the recall tools on the guest plane.
	// It serves the worker-machine tools (workers, CAP-8) on the live guest
	// plane. It opens the machines' disk quotas (quota, RES-4); quota
	// imports golang.org/x/sys/unix, so like clock it is held by
	// TestAgentosdLinksNoInference through netOK. It hands the modem
	// link's state to the page's socket as a localapi.Line (P2-2w d2a).
	// It changes where updates come from (follow, OSS-10): the follow
	// executor over the update store, already linked through change, and
	// the page's root summary (localapi) the daemon serves. A held restore
	// (W3-forget-b1-7) serves the bridge's ops itself, hears its state
	// report (bridgeproto) and checks its texts fit (modem); both are
	// already linked through modemlink. It wires LOOP-7's fuzz source
	// (loop7, P3-4b-3a), whose one exec runs release-listed fuzz binaries
	// (TestAgentosdLinksNoInference's escapeOK); loop7 does not import
	// sockprobe, whose in-guest dialer stays out of the daemon. It replays
	// the corpus built into the binary through the in-process closed
	// checks (corpus, P3-4b-4c-corpus), which links no mail code. It sends
	// the daily digest (W5-Dc) from its queue (digestqueue), fitted to one
	// owner text as Inform fits it (control). It binds the owner's mail
	// account (SR3-mail-w2): the mail adapter (mail, which judges organize
	// by verb) over the vault process's mail socket (mail/mailsock), so the
	// credential and the IMAP and SMTP clients stay in agentos-egress (M1);
	// mail imports golang.org/x/text, so like clock it has no entry below
	// and is held by TestAgentosdLinksNoInference, which holds mailsock to
	// the unix dial modelroute makes.
	"cmd/agentosd": {"daemon", "admission", "cgroup", "budget", "accel", "vm", "vm/gvisor", "guest", "meter", "modelroute", "journal", "owner", "change", "loops", "replay", "question", "clock", "routerule", "grants", "compile", "loopbuild", "recall", "recalltool", "workers", "quota", "modemlink", "guesterr", "localapi", "localsrv", "sockets", "follow", "update", "bridgeproto", "modem", "loop7", "corpus", "digestqueue", "control", "mail", "mail/mailsock", "verb"},
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
	"vm":         {[]string{"admission", "cgroup", "vm/overlay", "quota"}, forbiddenStd},
	"vm/overlay": {nil, []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}},
	"vm/gvisor":  {[]string{"vm", "vm/overlay", "quota", "childproc"}, []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}},
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
	"guest": {[]string{"fold", "guesterr", "journal", "meter"}, []string{"os/exec", "plugin", "unsafe", "C"}},
	"meter": {nil, []string{"net", "os/exec", "plugin", "unsafe", "C"}},
	// fold keeps an oversized tool result for the machine that produced it
	// and hands back a stand-in. It stores bytes in memory. No network,
	// no process, no model.
	"fold": {nil, forbiddenStd},
	// modelroute forwards to the vault process over its Unix socket and
	// reports usage to the meter; never the vault or the proxy. It
	// journals the denials that come back (modelroute.Journal), coalesced
	// by the journal's own gate, as the guest plane may. Its routing client
	// carries the router's rule types (W3, potency PW4 on #90).
	"modelroute": {[]string{"journal", "meter", "routerule"}, []string{"os/exec", "plugin", "unsafe", "C"}},
	// The router's rule types, without the router (W3): what the change
	// pipeline and Loop 1 read and change.
	"routerule": {nil, forbiddenStd},
	// Replay (LOOP-5) serves replay machines through a guest plane of its
	// own: no journal writes, no executors, no network clients.
	"replay": {[]string{"admission", "change", "guest", "journal", "meter", "vm"}, []string{"net", "os/exec", "plugin", "unsafe", "C"}},
	// Recall (CAP-3) and the event bus (CAP-4) are broker state served to
	// guests as tools: no network clients, no processes, no inference
	// beyond the in-process hashing embedder (DEP-1).
	"recall":     {nil, []string{"net", "net/http", "os/exec", "plugin", "unsafe", "C"}},
	"events":     {[]string{"recall"}, []string{"net", "net/http", "os/exec", "plugin", "unsafe", "C"}},
	"recalltool": {[]string{"recall", "events", "journal", "guesterr"}, []string{"net", "net/http", "os/exec", "plugin", "unsafe", "C"}},
	// Loop 1's model-backed builder (W3-builder) serves each builder
	// machine its own socket, as replay does: the brief, one candidate,
	// and the metered model route; no executors, no network clients.
	"loopbuild": {[]string{"admission", "change", "journal", "loops", "meter", "vm"}, []string{"net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}},
	// Worker machines (CAP-8): served to guests as tools over the machine
	// manager; no journal, no executors, no network clients, no processes
	// (commands run through vm/gvisor's runsc exec).
	"workers": {[]string{"admission", "vm", "vm/overlay", "guesterr"}, forbiddenStd},
	// Agents' questions to the owner (P3-8, W9): served to guests and
	// answered from the owner channel, through hooks the wiring passes.
	"question": {[]string{"guesterr"}, forbiddenStd},
	// The one filter on what a tool's error shows the guest (SR2-3g):
	// fixed text passes, anything else is a ref and a broker-log line.
	"guesterr": {nil, forbiddenStd},
}

// The learning plane (W3; arbitrator, adopting potency PW1 on #56): the
// deterministic change pipeline and loop scheduler, linked into agentosd.
// They decide and record; model-calling builders stay behind a socket
// (TestAgentosdLinksNoInference).
var learningPlane = map[string]struct {
	allowed []string
	forbid  []string
}{
	"change": {[]string{"journal", "owner", "routerule", "update"}, forbiddenStd},
	"loops":  {[]string{"change", "journal", "meter", "owner", "skill/format", "vm"}, forbiddenStd},
	// The skill file format without the bridge (P3-6e): Loop 1 decodes
	// the skills and procedures a builder writes.
	"skill/format": {nil, forbiddenStd},
	// The daily digest's queue (W5-Db): durable batches and a send gate,
	// standard library only (W5-Dc).
	"digestqueue": {nil, forbiddenStd},
	// LOOP-7's closed checks and the embedded corpus (P3-4b-4c-corpus):
	// pure data and functions over owner's filters; the mail checks come
	// in through an interface, so no mail code is linked.
	"corpus": {[]string{"control", "loops", "owner"}, forbiddenStd},
}

var forbiddenStd = []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "syscall", "unsafe", "C"}

// stdExceptions are the forbidden standard packages a control-path package
// may still use, and why.
var stdExceptions = map[string][]string{
	"sockets":      {"net", "syscall"}, // Unix listeners, SO_PEERCRED, flock
	"cmd/agentosd": {"syscall"},        // signal numbers for shutdown
	"journal":      {"syscall"},        // flock on the journal file
	"loops":        {"syscall"},        // O_NOFOLLOW, O_NONBLOCK for the tamper digest (P3-4b-4c-nofollow)
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
	for pkg, rule := range learningPlane {
		checkImports(t, pkg, rule.allowed, rule.forbid, stdExceptions[pkg])
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
		// mail/imapsmtp holds the mailbox credential's clients, and with
		// net/smtp sends mail; both run in agentos-egress behind the mail
		// socket (SR3-mail-w2, M1). crypto/tls and net/http are linked
		// through modelroute's unix-socket client (TestAgentosdLinks-
		// NoInference holds every dial to "unix").
		if dep == module+"vault" || dep == module+"egress" || dep == module+"tpmseal" || dep == module+"mail/imapsmtp" || dep == "net/smtp" {
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
