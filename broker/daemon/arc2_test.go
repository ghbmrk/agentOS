package daemon

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	"localsrv": {"boxname", "kernel/privfile", "localapi", "owner", "pageca", "sockets"},
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
	// It hosts the follow clerk on kernel/proc's clerk socket, under the
	// owner's anchors read with clerk/handoff (#3430); kernel/proc serves
	// and dials only unix sockets (netOK in inference_test.go).
	"cmd/agentosd": {"daemon", "admission", "cgroup", "budget", "accel", "vm", "vm/gvisor", "guest", "meter", "modelroute", "journal", "owner", "change", "loops", "question", "clock", "grants", "workers", "quota", "modemlink", "guesterr", "localapi", "localsrv", "sockets", "follow", "update", "bridgeproto", "modem", "control", "mail", "mail/mailsock", "verb", "provagent", "owner/notice", "owner/notice/noticesock", "infer", "infer/supervise", "vision", "vision/supervise", "checker/checkersock", "localsrv/accountsock", "owner/kernelsock", "kernel/key", "kernel/privfile", "backup", "kernel/proc", "follow/followclerk", "clerk/handoff"},
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
	"enforcer":          {nil, droneForbid},
	"enforcer/policy":   {[]string{"kernel/key"}, droneForbid},
	"enforcer/wire":     {nil, droneForbid},
	"enforcer/channel":  {[]string{"enforcer/policy", "enforcer/wire"}, droneForbid},
	"enforcer/alert":    {[]string{"enforcer/wire"}, droneForbid},               // slice h: texts and light
	"enforcer/heads":    {[]string{"kernel/key", "enforcer/wire"}, droneForbid}, // slice h: owner sub-key revocations (STO-4)
	"enforcer/nft":      {[]string{"enforcer/policy"}, droneForbid},
	"enforcer/nft/load": {nil, slices.DeleteFunc(slices.Clone(droneForbid), func(s string) bool { return s == "os/exec" })},
	"enforcer/dns":      {[]string{"enforcer/nft", "enforcer/policy"}, droneForbid},                                                              // slice f: dnsmasq configuration
	"enforcer/mdns":     {[]string{"enforcer/nft"}, droneForbid},                                                                                 // slice f: the pair relay
	"enforcer/wol":      {[]string{"enforcer/nft"}, droneForbid},                                                                                 // slice f: the Wake-on-LAN relay
	"enforcer/dns/run":  {[]string{"enforcer/dns"}, slices.DeleteFunc(slices.Clone(droneForbid), func(s string) bool { return s == "os/exec" })}, // slice l: runs dnsmasq in step with the firewall (#4464)
	"enforcer/traffic":  {[]string{"enforcer/nft", "enforcer/policy", "enforcer/wire"}, droneForbid},                                             // slice i: traffic summaries; byte-cap counts (#4174)
	"enforcer/offload":  {[]string{"golang.org/x/sys/unix"}, droneForbid},                                                                        // ENF-cap-gro (#4610): merging offloads off on the counted ports, over netlink through syscall, with x/sys/unix's names for the kernel's numbers (#5088)
	// The page is the enforcer's own HTTPS origin (slice b, NET-4), so it
	// alone may serve HTTP and TLS; it still launches nothing.
	// It also serves the enrolment screens (slice c) and draws the Owner
	// network's Wi-Fi QR with rsc.io/qr (enforcerWebDeps).
	"enforcer/page": {[]string{"kernel/key", "enforcer/policy", "enforcer/action", "enforcer/pairseal", "enforcer/enrol", "enforcer/page/internal/csrf", "rsc.io/qr"}, enforcerWebForbid},
	// The page's anti-forgery pair (#4685, enforcerCSRF): the standard
	// library only.
	"enforcer/page/internal/csrf": {nil, enforcerWebForbid},
	// Enrolment (slice c): the case code, the recovery code and the
	// passkey's handover; it texts through the alert kinds.
	"enforcer/enrol": {[]string{"kernel/key", "enforcer/policy", "enforcer/alert"}, droneForbid},
	// Asserted safety-list actions (slice s): once-only owner challenges;
	// the page serves them and the daemon wires their actuator.
	"enforcer/action": {[]string{"kernel/key", "enforcer/policy"}, droneForbid},
	// Lock rules (slice q): the second assertion, relock and keypad codes,
	// as the actuator behind slice s's unlock and disarm challenges.
	"enforcer/locks": {[]string{"kernel/key", "enforcer/policy", "enforcer/action", "enforcer/alert"}, droneForbid},
	// The radio host (slice k) speaks to each stack over a socket pair; its
	// launcher alone starts the stacks and installs their seccomp filter.
	"enforcer/radio":         {[]string{"enforcer/wire"}, droneForbid},
	"enforcer/radio/ble":     {[]string{"enforcer/radio"}, droneForbid}, // #3906: BlueZ's D-Bus client, its own codec (no godbus: it links os/exec)
	"enforcer/radio/confine": {nil, slices.DeleteFunc(slices.Clone(droneForbid), func(s string) bool { return s == "os/exec" || s == "unsafe" })},
	// Thread's adapter (slice t, D-231): ot-daemon's command socket on one
	// side, the radio host's interface on the other; the daemon starts both
	// through confine.
	"enforcer/radio/thread": {[]string{"enforcer/radio"}, droneForbid},
	// The access point (slice g): ap renders its config from the policy,
	// with VLANs read by the firewall's own rule; push alone carries it
	// over SSH (enforcerSSH).
	"enforcer/ap":      {[]string{"enforcer/policy", "enforcer/nft"}, droneForbid},
	"enforcer/ap/push": {[]string{"enforcer/ap", "golang.org/x/crypto/ssh"}, droneForbid},
	// Safety-list devices' secrets (slice r, decision 10): the sealed
	// envelope both ends import, standard library only, and the enforcer's
	// store, which neither the page nor the channel links.
	"enforcer/pairseal":  {nil, droneForbid},
	"enforcer/devsecret": {[]string{"kernel/key", "enforcer/policy", "enforcer/pairseal"}, droneForbid},
}

// coreEnforcer are the core packages that link an enforcer package: the
// core's half of a shared format, never the enforcer's logic (ENF brief,
// guard files). TestCoreLinksOnlyEnforcerFormats holds that for every core
// package.
var coreEnforcer = map[string]struct {
	allowed []string
	forbid  []string
}{
	// The pairing clerks' sealing helper (slice r): seals to the
	// enforcer's pairing key with pairseal and holds no private key.
	"clerk/enfpair": {[]string{"enforcer/pairseal"}, forbiddenStd},
	// The byte caps' composer (#4578): writes the next policy document
	// with each cap sized from its stated figure; the enforcer's page
	// draws and the owner signs it.
	"clerk/enflist": {[]string{"enforcer/policy"}, forbiddenStd},
	// The kernel's byte-cap check (#4173): the summary interval and the
	// cap edge from the shared format definition, never a copy (D-255).
	"kernel/capgate": {[]string{"enforcer/wire"}, forbiddenStd},
	// The kernel's check of every channel message before it is sent
	// (#4373): the format, the rates and the bucket from the shared
	// format definition, never a copy (D-255).
	"kernel/chancheck": {[]string{"enforcer/wire"}, forbiddenStd},
}

// enforcerMain is the enforcer's daemon (slice l, #3670): the one
// composition root that links the page, the nft loader and the rest
// together. It imports only enforcer packages, kernel/key and x/sys/unix
// for CLOCK_BOOTTIME (#4507), starts no process itself and serves no
// HTTP of its own; TestEnforcerImportsNothingFromAgentOS holds its
// dependencies to the enforcer's.
const enforcerMain = "cmd/agentos-enforcer"

var enforcerMainRule = struct {
	allowed []string
	forbid  []string
}{
	[]string{"kernel/key", "enforcer/alert", "enforcer/channel", "enforcer/dns", "enforcer/dns/run", "enforcer/enrol", "enforcer/heads",
		"enforcer/mdns", "enforcer/nft", "enforcer/nft/load", "enforcer/offload", "enforcer/page", "enforcer/policy", "enforcer/traffic",
		"enforcer/wire", "enforcer/wol", "golang.org/x/sys/unix"},
	[]string{"net/http", "net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"},
}

// enforcerWebDeps are the third-party packages the page links: rsc.io/qr
// draws the Owner network's Wi-Fi QR at enrolment (HW-10). The enforcer
// shares no code with agentOS, so the core's card package, which wraps
// the same encoder, cannot be reused; the encoder is small, pure Go and
// already vendored for the Owner Card.
var enforcerWebDeps = []string{"rsc.io/qr", "rsc.io/qr/coding", "rsc.io/qr/gf256"}

var enforcerWebForbid = []string{"net/rpc", "net/smtp", "os/exec", "plugin", "unsafe", "C"}

// enforcerExec are the enforcer packages that start a process: the
// firewall loader runs nft (ENF decision 4, slice e), the radio launcher
// starts the confined stacks (decision 6, slice k) and the resolver's
// runner keeps the dnsmasq instances in step with the firewall (slice l,
// #4464; dns ASSUMPTIONS ENF-f-9). Only the daemon imports them, so no
// other enforcer package links os/exec through them.
var enforcerExec = []string{"enforcer/nft/load", "enforcer/radio/confine", "enforcer/dns/run"}

// enforcerWeb is the one enforcer package that links net/http and
// crypto/tls: the page (slice b) serves the owner's confirm screen, and no
// other enforcer package imports it.
const enforcerWeb = "enforcer/page"

// enforcerCSRF is the page's anti-forgery package: it links net/http for
// the page alone. Go's internal rule admits any package under
// enforcer/page; the enforcer map pins the page as its only importer,
// since every enforcer package needs a rule there and only the page's
// allows it.
const enforcerCSRF = "enforcer/page/internal/csrf"

// enforcerSSH is the one enforcer package that links a third-party
// package: the access point pusher (slice g) reaches OpenWrt's admin over
// SSH with a pinned host key. OpenWrt's admin paths are SSH or HTTP, the
// enforcer links no HTTP client, and golang.org/x/crypto/ssh is the Go
// project's own client, so reuse beats writing SSH again. It may link
// exactly enforcerSSHDeps, and no other enforcer package imports it.
const enforcerSSH = "enforcer/ap/push"

var enforcerSSHDeps = []string{
	"golang.org/x/crypto/ssh", "golang.org/x/crypto/ssh/internal/bcrypt_pbkdf", "golang.org/x/crypto/blowfish",
	"golang.org/x/crypto/chacha20", "golang.org/x/crypto/curve25519", "golang.org/x/crypto/internal/alias",
	"golang.org/x/crypto/internal/poly1305", "golang.org/x/crypto/cryptobyte", "golang.org/x/crypto/cryptobyte/asn1",
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
	for pkg, rule := range coreEnforcer {
		checkImports(t, pkg, rule.allowed, rule.forbid, nil)
	}
	checkImports(t, enforcerMain, enforcerMainRule.allowed, enforcerMainRule.forbid, nil)
}

// TestCoreLinksOnlyEnforcerFormats: no core package imports an enforcer
// package except as coreEnforcer allows, so the core links no enforcer
// logic, its device-secret store above all (STO-4).
func TestCoreLinksOnlyEnforcerFormats(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		pkg := strings.TrimPrefix(f[0], module)
		if pkg == "enforcer" || strings.HasPrefix(pkg, "enforcer/") || pkg == enforcerMain {
			continue
		}
		for _, im := range f[1:] {
			rel := strings.TrimPrefix(im, module)
			if (rel == "enforcer" || strings.HasPrefix(rel, "enforcer/")) && !contains(coreEnforcer[pkg].allowed, rel) {
				t.Errorf("core package %s links enforcer package %s: list it in coreEnforcer with a reason, or, if %s is enforcer code outside broker/enforcer (cmd/agentos-enforcer, kernel/enforcer), add the case that skips it here", pkg, rel, pkg)
			}
		}
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

// enforcerLinks are the module packages outside broker/enforcer that the
// enforcer may link (ENF decision 1, STO-4).
var enforcerLinks = []string{"kernel/key", "drone", "camwire"}

// TestEnforcerImportsNothingFromAgentOS: everything under broker/enforcer
// links, transitively, only the standard library, the enforcer's own
// packages, broker/kernel/key, broker/drone and broker/camwire (ENF
// decision 1, STO-4), and no third-party package but the access point
// pusher's SSH client (enforcerSSH, slice g); only the page
// (enforcerWeb, slice b, with its anti-forgery package enforcerCSRF) speaks HTTP or TLS, and only the firewall loader
// the radio launcher and the resolver's runner (enforcerExec, slices e, k and l) launch a process. Slice l (the daemon) widens
// this with a reason.
func TestEnforcerImportsNothingFromAgentOS(t *testing.T) {
	list, err := exec.Command("go", "list", "-C", "..", "./enforcer/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var rest []string
	for _, p := range strings.Fields(string(list)) {
		if rel := strings.TrimPrefix(p, module); !slices.Contains(enforcerExec, rel) && rel != enforcerWeb && rel != enforcerCSRF && rel != enforcerSSH {
			rest = append(rest, p)
		}
	}
	own := map[string]bool{}
	check := func(pkgs []string, forbidden []string, third ...string) {
		out, err := exec.Command("go", append([]string{"list", "-C", "..", "-deps"}, pkgs...)...).Output()
		if err != nil {
			t.Fatalf("go list: %v", err)
		}
		for _, dep := range strings.Fields(string(out)) {
			rel := strings.TrimPrefix(dep, module)
			switch {
			case rel == enforcerMain && slices.Contains(pkgs, module+enforcerMain):
				// the daemon itself, when it is the package checked
			case rel == "enforcer" || strings.HasPrefix(rel, "enforcer/"):
				own[rel] = true
				if _, ok := enforcer[rel]; !ok {
					t.Errorf("%s has no import rule in the enforcer map", dep)
				}
			case strings.HasPrefix(dep, module):
				if !slices.Contains(enforcerLinks, rel) {
					t.Errorf("the enforcer links %s", dep)
				}
			case strings.Contains(strings.SplitN(dep, "/", 2)[0], "."):
				if !slices.Contains(third, dep) {
					t.Errorf("the enforcer links third-party %s", dep)
				}
			case contains(forbidden, dep):
				t.Errorf("%v link %s", pkgs, dep)
			}
		}
	}
	// Of them only offload imports x/sys/unix (its rule above), for the
	// kernel's numbers; the daemon links it anyway.
	check(rest, forbiddenDeps, "golang.org/x/sys/unix")
	for _, p := range append(slices.Clone(enforcerExec), enforcerWeb, enforcerSSH) {
		if own[p] {
			t.Errorf("an enforcer package other than %s links it", p)
		}
	}
	for _, p := range enforcerExec {
		check([]string{module + p}, slices.DeleteFunc(slices.Clone(forbiddenDeps), func(s string) bool { return s == "os/exec" }))
	}
	check([]string{module + enforcerWeb}, slices.DeleteFunc(slices.Clone(forbiddenDeps), func(s string) bool { return s == "net/http" || s == "crypto/tls" }), enforcerWebDeps...)
	check([]string{module + enforcerSSH}, forbiddenDeps, enforcerSSHDeps...)
	// The daemon links every enforcer package; nothing else of agentOS,
	// no third party but the page's QR encoder and x/sys/unix, and no RPC,
	// mail or plugin loader.
	check([]string{module + enforcerMain}, []string{"net/rpc", "net/smtp", "plugin"},
		append(slices.Clone(enforcerWebDeps), "golang.org/x/sys/unix")...)
	if len(own) < len(enforcer) {
		t.Errorf("go list found %d enforcer packages, the rule map names %d", len(own), len(enforcer))
	}
}

// TestARC2EnforcerHoldsOnlyGoSource completes ARC2's per-package bans on
// unsafe and C for the enforcer, which is trusted base (KRN-2, STO-4) and
// parses what the network sends it: no directory of the enforcer, nor of
// a module package it may link (enforcerLinks), holds a source the Go
// compiler does not check for memory safety (assembly, C, C++, Fortran,
// Objective-C, SWIG or a prebuilt object), whatever its build constraints
// (#4789). It scans agentOS's own packages only: third-party code the
// enforcer links (enforcerWebDeps, enforcerSSHDeps; golang.org/x/crypto
// holds assembly) is trusted as any dependency is and not scanned. It is
// not a secrecy device between enforcer packages, which
// trust one another (ASSUMPTIONS ENF-page-csrf-2). The roots are the
// enforcer's tree, its daemon (enforcerMain, #4818: a .s or .syso in the
// daemon's main package links into the same process) and the list
// TestEnforcerImportsNothingFromAgentOS holds (#4798), so a module package
// the enforcer is later allowed to link is scanned too.
func TestARC2EnforcerHoldsOnlyGoSource(t *testing.T) {
	bad, n, err := foreignSources("..", arc2EnforcerRoots())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range bad {
		t.Errorf("%s: an enforcer package holds only Go source", p)
	}
	if n < len(enforcer)+1 {
		t.Fatalf("scanned %d directories, the enforcer map names %d packages and the daemon is one more", n, len(enforcer))
	}
}

// arc2EnforcerRoots are the directories TestARC2EnforcerHoldsOnlyGoSource
// scans: the enforcer's tree, walked whole, and each other root as one
// directory.
func arc2EnforcerRoots() []string {
	return append([]string{"enforcer", enforcerMain}, enforcerLinks...)
}

// foreignSources walks roots under base and returns every file the Go
// compiler does not check for memory safety, whatever its build
// constraints, with the number of directories walked. Only "enforcer" is
// walked whole; testdata is skipped.
func foreignSources(base string, roots []string) (bad []string, dirs int, err error) {
	foreign := []string{".s", ".S", ".sx", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".f", ".F", ".for", ".f90", ".swig", ".swigcxx", ".syso"}
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join(base, root), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || (root != "enforcer" && p != filepath.Join(base, root)) {
					return filepath.SkipDir
				}
				dirs++
				return nil
			}
			if slices.Contains(foreign, filepath.Ext(p)) {
				bad = append(bad, p)
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return bad, dirs, nil
}

// TestARC2RootsIncludeEnforcerDaemon plants an assembly file and a
// prebuilt object in a copy of the daemon's directory: the scan must
// report both (#4818).
func TestARC2RootsIncludeEnforcerDaemon(t *testing.T) {
	base := t.TempDir()
	for _, r := range arc2EnforcerRoots() {
		if err := os.MkdirAll(filepath.Join(base, r), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	planted := []string{filepath.Join(base, enforcerMain, "start_amd64.s"), filepath.Join(base, enforcerMain, "rsrc.syso")}
	for _, p := range append(slices.Clone(planted), filepath.Join(base, enforcerMain, "main.go")) {
		if err := os.WriteFile(p, []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bad, _, err := foreignSources(base, arc2EnforcerRoots())
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(bad)
	slices.Sort(planted)
	if !slices.Equal(bad, planted) {
		t.Errorf("foreignSources reported %v, want %v", bad, planted)
	}
}

// enforcerTestHTTP are the enforcer directories whose _test.go files may
// import net/http (and its subpackages) or crypto/tls, and why; checkImports
// reads no test file, so TestEnforcerTestFilesKeepImportPins holds test
// files to the page's pins (#4852, ASSUMPTIONS ENF-page-csrf-2).
var enforcerTestHTTP = map[string]string{
	enforcerWeb:       "the page's own tests drive its handler",
	enforcerCSRF:      "the anti-forgery pair's tests set and read cookies",
	"enforcer/action": "the action tests drive the page's challenge handler with httptest",
	enforcerMain:      "the daemon's lifecycle test drives the page it serves over TLS",
}

// TestEnforcerTestFilesKeepImportPins: no _test.go file in the enforcer or
// its daemon imports enforcerCSRF unless it sits in the page's or the
// csrf package's own directory (Go's internal rule would admit any
// package under enforcer/page), and none imports net/http or crypto/tls
// outside enforcerTestHTTP (#4852).
func TestEnforcerTestFilesKeepImportPins(t *testing.T) {
	bad, n, err := enforcerTestImportViolations("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Error(b)
	}
	if n == 0 {
		t.Fatal("read no enforcer test file")
	}
}

// enforcerTestImportViolations reads every _test.go file under
// base/enforcer and base/cmd/agentos-enforcer, skipping testdata, and
// returns each import that breaks the pins, with the number of files read.
func enforcerTestImportViolations(base string) (bad []string, files int, err error) {
	for _, root := range []string{"enforcer", enforcerMain} {
		err := filepath.WalkDir(filepath.Join(base, root), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || (root == enforcerMain && p != filepath.Join(base, root)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, "_test.go") {
				return nil
			}
			files++
			dir, err := filepath.Rel(base, filepath.Dir(p))
			if err != nil {
				return err
			}
			dir = filepath.ToSlash(dir)
			af, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, im := range af.Imports {
				ip, _ := strconv.Unquote(im.Path.Value)
				switch {
				case ip == module+enforcerCSRF && dir != enforcerWeb && dir != enforcerCSRF:
					bad = append(bad, p+" imports "+ip+"; only the page and its own tests may")
				case ip == "net/http" || strings.HasPrefix(ip, "net/http/") || ip == "crypto/tls":
					if _, ok := enforcerTestHTTP[dir]; !ok {
						bad = append(bad, p+" imports "+ip+"; list its directory in enforcerTestHTTP with a reason")
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return bad, files, nil
}

// TestEnforcerTestFilePinsCatchPlants plants test files that break each
// pin, beside allowed ones, and checks the scan reports exactly the
// planted breaks (#4852).
func TestEnforcerTestFilePinsCatchPlants(t *testing.T) {
	base := t.TempDir()
	write := func(rel, imp string) string {
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("package x\n\nimport _ \""+imp+"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	csrf := module + enforcerCSRF
	write("enforcer/page/ok_test.go", csrf)
	write("enforcer/page/internal/csrf/ok_test.go", csrf)
	write("enforcer/page/ok2_test.go", "net/http/httptest")
	write("enforcer/action/ok_test.go", "net/http")
	write(enforcerMain+"/ok_test.go", "crypto/tls")
	write("enforcer/radio/testdata/ignored_test.go", csrf)
	write("enforcer/radio/plain.go", csrf) // not a test file: checkImports' job
	want := []string{
		write("enforcer/radio/x_test.go", csrf),
		write("enforcer/page/sub/y_test.go", csrf), // under page, so Go's internal rule admits it
		write(enforcerMain+"/z_test.go", csrf),
		write("enforcer/wol/w_test.go", "net/http/httptest"),
		write("enforcer/dns/v_test.go", "crypto/tls"),
	}
	bad, n, err := enforcerTestImportViolations(base)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range bad {
		got = append(got, strings.SplitN(b, " ", 2)[0])
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("reported %v, want %v", got, want)
	}
	if n != 10 {
		t.Errorf("read %d test files, want 10", n)
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
