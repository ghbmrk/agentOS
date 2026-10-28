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
	// The durable-write helper (SIM-fs) every package may import: file
	// calls only, held to the control path's rules here.
	"durable": {},
	// The atomic replace of a process's own file (#2643 c), which the
	// owner state, the setup record and the question book write through
	// (#2778): file calls only, held to the control path's rules here.
	"kernel/privfile": {},
	// The journal checker (SIM-check): pure predicates over records.
	"journal/check": {"journal"},
	"control":       {},
	// The journal engine as the owner commands drive it (#2778), until
	// #2783 (c) leaves them to the kernel.
	"daemon/journalowner": {"control", "journal"},
	"admission":           {},
	"sockets":             {},
	"cgroup":              {},
	"budget":              {"admission", "cgroup"}, // RES-2 component budget (P2-5)
	"accel":               {"admission"},           // RES-3 discovery from sysfs (P2-5)
	"owner":               {"boxname", "control", "kernel/privfile", "modem"},
	"modem":               {},
	"boxname":             {}, // CH-21 name check, for NAME
	// The modem bridge's contract and agentosd's end of it (P2-3w): types
	// and an in-process queue; the bridge's client is bridgeclient.
	"bridgeproto": {},
	"modemlink":   {"bridgeproto", "modem", "sockets"},
	// The local UI's contract and agentosd's end of it (P2-2w): agentosd
	// serves the page's ops on the owner channel; the local UI, which
	// decodes untrusted photos, stays in its own process (L15).
	"localapi": {"owner"},
	"localsrv": {"kernel/privfile", "localapi", "owner", "pageca", "sockets"},
	// The owner page's authority (#3153): the standard library's crypto
	// and the private-file helpers; its Sealer is clerk.Sealer's method
	// set, so it links no clerk (which brings crypto/tls and net/http).
	"pageca": {"kernel/privfile"},
	// The approval policy (grants) runs inside the engine's checks, so it
	// is on the control path too; adapters reach it only through its
	// Verifier interface. Its refusals' guest text is guesterr's (SR2-3j),
	// which imports nothing beyond the standard library.
	"grants": {"guesterr", "journal", "owner", "reversible", "verb"},
	"verb":   {},
	// Reversible forms (REV-3) are declarations the gate validates: pure
	// data, held to the control path's rules.
	"reversible": {"journal", "verb"},
	// The kernel's verb classes (KRN-4), which a RETRY of a parked kernel
	// step is tiered by (#2783 b): a pure library, held to the control
	// path's rules.
	"kernel/key": {},
	"daemon":     {"journal", "journal/check", "control", "daemon/journalowner", "admission", "sockets", "owner", "modem", "grants", "localapi", "localsrv", "kernel/key"},
	// The composition root also opens the machine plane (below) and hands
	// it to admission as a Preempter, and serves the guest plane (below)
	// on each machine's socket.
	// It forwards each machine's model route to the vault process
	// (modelroute, P2-4) and journals the denials that come back, and
	// gives the owner channel the vault process's verify operation
	// (owner.Verifier, egress K7). It keeps the owner's agent machine
	// running as foreground work (admission.Foreground, RES-1). The
	// learning plane went with MIG-4-untrusted-learn: what is left is the
	// owner's FORGET, whose stores are change's file stores, and the loop
	// settings parser (loops.ParseText), with which the box answers the
	// old loop settings texts.
	// It runs the owner-question book (W9) on the box clock (P2-9).
	// clock imports golang.org/x/sys/unix (adjtimex), so it has no entry
	// below, whose rules refuse third-party imports; TestAgentosdLinks-
	// NoInference holds it instead, through netOK.
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
	// already linked through modemlink. It fits its own owner texts to one text as Inform fits them (control). It binds the owner's mail
	// account (SR3-mail-w2): the mail adapter (mail, which judges organize
	// by verb) over the vault process's mail socket (mail/mailsock), so the
	// credential and the IMAP and SMTP clients stay in agentos-egress (M1);
	// mail imports golang.org/x/text, so like clock it has no entry below
	// and is held by TestAgentosdLinksNoInference, which holds mailsock to
	// the unix dial modelroute makes. It wires the provider-agent runner
	// (provagent, CAP-11) to the worker tools through an adapter, and its
	// seeder to modelroute's route control, so neither workers nor
	// provagent links the model route's client. It asks the checker to
	// verify owner codes through checker/checkersock, a dial-only client
	// of the checker's verify socket, so agentosd links none of the
	// checker that holds the seed (SIM-split-wire, CH-4). It calls the
	// kernel's owner socket through owner/kernelsock, a dial-only client
	// that takes the owner side's uid on the calling thread (#2682); it
	// imports golang.org/x/sys/unix, so like clock it has no entry below.
	// It keeps the guests' plan holder key with kernel/privfile and narrows
	// the owner's grant per machine with kernel/key (#3087). It derives a
	// new recovery key's backup recipient with backup, pure crypto over
	// the kernel's types, for the Recovery key page (REC-4 r4a, #3409).
	"cmd/agentosd": {"daemon", "admission", "cgroup", "budget", "accel", "vm", "vm/gvisor", "guest", "meter", "modelroute", "journal", "owner", "change", "loops", "question", "clock", "grants", "recall", "workers", "quota", "modemlink", "guesterr", "localapi", "localsrv", "sockets", "follow", "update", "bridgeproto", "modem", "control", "mail", "mail/mailsock", "verb", "provagent", "owner/notice", "owner/notice/noticesock", "infer", "infer/supervise", "vision", "vision/supervise", "checker/checkersock", "localsrv/accountsock", "owner/kernelsock", "kernel/key", "kernel/privfile", "backup"},
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
	"vm/gvisor":  {[]string{"vm", "vm/overlay", "quota", "childproc", "cgroup"}, []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}},
	// photo re-encodes owner photos through agentos-photo in a one-shot
	// sandbox (CH-23): no image decoder links into the broker, and the
	// decoder package (photo/decoder) only into agentos-photo. The decoder
	// may import exactly one third-party package, the pure-Go HEIC decoder
	// (CH-photo-heic, #3124): it runs only inside that sandbox, and
	// photo's TestPhotoImportsNoDecoder keeps it out of the broker.
	"photo":             {[]string{"vm/gvisor"}, []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C", "image/jpeg", "image/png", "image/gif"}},
	"photo/decoder":     {[]string{"github.com/gen2brain/h265/heic"}, []string{"net", "net/http", "net/rpc", "net/smtp", "os", "os/exec", "plugin", "unsafe", "C"}},
	"cmd/agentos-photo": {[]string{"photo/decoder"}, []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}},
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
	// It signs each machine's plans and hands them to the kernel's seam
	// (PLN-5 (b)): the kernel's plan and key types, pure data and the key
	// check, never the kernel's process (kernel/proc).
	"guest": {[]string{"fold", "guesterr", "kernel", "kernel/key"}, []string{"os/exec", "plugin", "unsafe", "C"}},
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
	// The local inference service's protocol and client (INFER-SVC INF-5):
	// the standard library only, dialing the service's unix socket. Its
	// supervisor (infer/supervise) has no plane entry: it sets no_new_privs
	// through golang.org/x/sys/unix, and TestAgentosdLinksNoInference
	// holds its imports.
	"infer": {nil, []string{"net/http", "os/exec", "plugin", "unsafe", "C"}},
	// The camera vision service's protocol and client (VIS-svc), as
	// infer's: the standard library only, dialing the service's unix
	// socket. Its supervisor wraps infer/supervise's jail and holds no
	// socket, process or system call of its own.
	"vision":           {nil, []string{"net/http", "os/exec", "plugin", "unsafe", "C"}},
	"vision/supervise": {[]string{"cgroup", "infer/supervise"}, forbiddenStd},
	// Face enrolment's trusted side (VIS-faces): template slots through
	// the store surface its wiring hands it, the service's control calls,
	// and the anchor co-signature check (kernel/key) that makes enrolment
	// the owner's tier-4 step; no socket, process or system call of its own.
	"vision/faces": {[]string{"vision", "kernel/key"}, forbiddenStd},
	// Recall (CAP-3) and the event bus (CAP-4) are broker state served to
	// guests as tools: no network clients, no processes, no inference
	// beyond the in-process hashing embedder (DEP-1).
	"recall": {nil, []string{"net", "net/http", "os/exec", "plugin", "unsafe", "C"}},
	"events": {[]string{"recall"}, []string{"net", "net/http", "os/exec", "plugin", "unsafe", "C"}},
	// Worker machines (CAP-8): served to guests as tools over the machine
	// manager; no journal, no executors, no network clients, no processes
	// (commands run through vm/gvisor's runsc exec).
	"workers": {[]string{"admission", "vm", "vm/overlay", "guesterr"}, forbiddenStd},
	// The provider-agent runner (CAP-11): declarations, the qualification
	// gate and the run path over the machine manager's provider workers.
	// The guest reaches it only through workers' provider_run, which names
	// it through an interface agentosd adapts; its seed comes from the
	// model route through a Seeder agentosd adapts, so it links no network
	// client, no process and no model route.
	"provagent": {[]string{"admission", "vm"}, forbiddenStd},
	// Agents' questions to the owner (P3-8, W9): served to guests and
	// answered from the owner channel, through hooks the wiring passes.
	"question": {[]string{"guesterr", "kernel/privfile"}, forbiddenStd},
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
	// change reads the closed verb list to check an adapter's demo runs
	// before adoption (ADP-8b); verb is standard library only.
	"change": {[]string{"journal", "owner", "routerule", "update", "verb"}, forbiddenStd},
	// loops is the probe vocabulary and the settings-text parser; its
	// scheduler, spare envelope and Guard went with the change pipeline
	// (#2785, MIG-4-untrusted-change-c2).
	"loops": {nil, forbiddenStd},
	// The skill file format without the bridge (P3-6e): Loop 1 decodes
	// the skills and procedures a builder writes.
	"skill/format": {nil, forbiddenStd},
	// LOOP-7's closed checks and the embedded corpus (P3-4b-4c-corpus):
	// pure data and functions over owner's filters; the mail checks come
	// in through an interface, so no mail code is linked.
	"corpus": {[]string{"control", "loops", "owner"}, forbiddenStd},
}

// The edge link's codec, hello and TLS configurations (EDGE-link-core c1,
// #3296): the standard library only, and no socket, process or kernel
// import of its own; the link process (agentos-link) owns those. The link
// process (c2, #3297) links the codec, the kernel's pure edge helpers
// (SmallOrder, HelloMsg) and the socket peer check, and no kernel process
// code: it reaches the kernel only over its link socket. It listens (net,
// syscall, x/sys/unix for SO_BINDTODEVICE) and starts one child, itself,
// as the pre-store hello reader, through childproc; it opens no network
// client.
var edgeLink = map[string]struct {
	allowed []string
	forbid  []string
}{
	"edgelink":         {nil, forbiddenStd},
	"cmd/agentos-link": {[]string{"edgelink", "kernel", "sockets", "childproc", "golang.org/x/sys/unix"}, []string{"net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}},
}

// The drone key-holder is enforcer code (DRONE-sim, #3516, brief decision 1):
// it imports nothing from agentOS, only the standard library and gomavlib's
// MAVLink framing, and its stand-in main links only it.
// TestDroneImportsNothingFromAgentOS holds the same rule transitively.
var drone = map[string]struct {
	allowed []string
	forbid  []string
}{
	"drone": {[]string{"github.com/bluenviron/gomavlib/v3/pkg/dialect",
		"github.com/bluenviron/gomavlib/v3/pkg/dialects/common", "github.com/bluenviron/gomavlib/v3/pkg/frame",
		"github.com/bluenviron/gomavlib/v3/pkg/message"}, droneForbid},
	"cmd/agentos-drone": {[]string{"drone"}, droneForbid},
}

var droneForbid = []string{"net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}

// The enforcer is enforcer code too (ENF, briefs/ENF.md decision 1): it
// shares no kernel, secret or update source with agentOS (NET-2 Channel),
// so it imports only the key-check library STO-4 names, broker/drone and
// broker/camwire. Each slice that adds a package or an import adds it here.
// TestEnforcerImportsNothingFromAgentOS holds the same rule transitively.
var enforcer = map[string]struct {
	allowed []string
	forbid  []string
}{
	"enforcer":         {nil, droneForbid},
	"enforcer/policy":  {[]string{"kernel/key"}, droneForbid},
	"enforcer/wire":    {nil, droneForbid},
	"enforcer/channel": {[]string{"enforcer/policy", "enforcer/wire"}, droneForbid},
}

var forbiddenStd = []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "syscall", "unsafe", "C"}

// stdExceptions are the forbidden standard packages a control-path package
// may still use, and why.
var stdExceptions = map[string][]string{
	"sockets":         {"net", "syscall"}, // Unix listeners, SO_PEERCRED, flock
	"cmd/agentosd":    {"syscall"},        // signal numbers for shutdown
	"journal":         {"syscall"},        // flock on the journal file
	"kernel/privfile": {"syscall"},        // O_NOFOLLOW and Stat_t for the owner-only check
	"pageca":          {"net", "syscall"}, // x509's excluded IP ranges are net.IPNet; O_NOFOLLOW and Stat_t for the sealed file
	"loops":           {"syscall"},        // O_NOFOLLOW, O_NONBLOCK for the tamper digest (P3-4b-4c-nofollow)
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
	for pkg, rule := range edgeLink {
		checkImports(t, pkg, rule.allowed, rule.forbid, nil)
	}
	for pkg, rule := range drone {
		checkImports(t, pkg, rule.allowed, rule.forbid, nil)
	}
	for pkg, rule := range enforcer {
		checkImports(t, pkg, rule.allowed, rule.forbid, nil)
	}
}

// TestDroneImportsNothingFromAgentOS: everything the drone key-holder and
// its main link, transitively, is the standard library, gomavlib's MAVLink
// packages or the drone package itself (DRONE-sim decision 1), and none of it
// launches a process or speaks HTTP.
func TestDroneImportsNothingFromAgentOS(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-deps", "./drone", "./cmd/agentos-drone").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case dep == module+"drone" || dep == module+"cmd/agentos-drone":
		case strings.HasPrefix(dep, module):
			t.Errorf("the drone key-holder links %s", dep)
		case strings.Contains(strings.SplitN(dep, "/", 2)[0], ".") && !strings.HasPrefix(dep, "github.com/bluenviron/gomavlib/v3/pkg/"):
			t.Errorf("the drone key-holder links third-party %s", dep)
		case contains(forbiddenDeps, dep):
			t.Errorf("the drone key-holder links %s", dep)
		}
	}
}

// TestEnforcerImportsNothingFromAgentOS: everything under broker/enforcer
// links, transitively, only the standard library, the enforcer's own
// packages, broker/kernel/key, broker/drone and broker/camwire (ENF
// decision 1, STO-4), and no third-party package yet; none of it launches a
// process or speaks HTTP. Slices e (the nft loader, os/exec), b (the page,
// net/http) and l (the daemon) widen this with a reason each.
func TestEnforcerImportsNothingFromAgentOS(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-deps", "./enforcer/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	links := map[string]bool{"kernel/key": true, "drone": true, "camwire": true}
	var own int
	for _, dep := range strings.Fields(string(out)) {
		rel := strings.TrimPrefix(dep, module)
		switch {
		case rel == "enforcer" || strings.HasPrefix(rel, "enforcer/"):
			own++
			if _, ok := enforcer[rel]; !ok {
				t.Errorf("%s has no import rule in the enforcer map", dep)
			}
		case strings.HasPrefix(dep, module):
			if !links[rel] {
				t.Errorf("the enforcer links %s", dep)
			}
		case strings.Contains(strings.SplitN(dep, "/", 2)[0], "."):
			t.Errorf("the enforcer links third-party %s", dep)
		case contains(forbiddenDeps, dep):
			t.Errorf("the enforcer links %s", dep)
		}
	}
	if own < len(enforcer) {
		t.Errorf("go list found %d enforcer packages, the rule map names %d", own, len(enforcer))
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
				if !contains(allowed, strings.TrimPrefix(p, module)) && p != module+"durable" {
					t.Errorf("%s imports %s, outside the control path", f, p)
				}
			case strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && !contains(allowed, p):
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
