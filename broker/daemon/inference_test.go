package daemon

// REQ: ARC-2, LOOP-5, LOOP-6
//
// W3's gate (arbitrator, adopting potency PW1 on #56; L3 on #62): agentosd,
// and every package W3 links into it (the change pipeline, the loop
// scheduler, the grants gate), hold no inference-capable code. No model
// router or provider adapter, no egress proxy, and no network client
// except the modelroute proxy, which speaks only to the vault process's
// unix socket. A package that newly needs net/http, a socket-level import,
// or an escape hatch (cgo, unsafe, plugin, os/exec, assembly) must be added
// below, with its reason, by review.
//
// This is a tripwire against drift, not proof against an adversary (L3 on
// #83). Residuals it does not cover, held by review instead: the standard
// library's and third-party packages' own internals beyond their imports
// (only their socket-capable imports are checked); reflection; values
// built from the allowed types and handed across packages (modelroute's
// transport, once built, is only as good as the code that builds it, which
// this test reads); where a unix dial's address comes from past its
// package (configured holds it to a parameter or a listed field,
// dialCallers holds the package's own callers, and fieldStores the listed
// fields, but callers in other packages are the composition root's
// wiring of the operator's configuration); _test.go files, which are not linked; and code generated or
// loaded at run time (plugin, os/exec, and os.StartProcess are refused
// outside their allow-lists, so none is expected).

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// linked is the composition root and what W3 links into it.
var linked = []string{compositionRoot, "change", "loops", "grants"}

// forbidden broker packages: the model router and its provider adapters,
// and the egress proxy.
var forbidden = []string{"route", "egress", "cmd/agentos-egress", "cmd/agentos-infer", "cmd/agentos-vision"}

// providerSDK matches third-party model provider clients.
var providerSDK = regexp.MustCompile(`(?i)(anthropic|openai|genai|generativeai|mistral|cohere|ollama|bedrock)`)

// runtimeSDK matches third-party inference runtimes and their bindings,
// which only the untrusted services (forbidden above) may link.
var runtimeSDK = regexp.MustCompile(`(?i)(onnxruntime|llama|ggml|tensorflow|torch)`)

// httpOK are the broker packages in the graph allowed to import net/http
// (or anything that depends on it), and why. None may hold an HTTP client
// except modelroute, whose every dial is to a unix socket (sourceUse).
var httpOK = map[string]string{
	"meter":                   "wraps guest model handlers (OP-8); serves, never dials",
	"guest":                   "serves the guest plane over the machine socket; never dials",
	"modelroute":              "the one client: forwards model calls to the vault process's unix socket",
	"owner/notice/noticesock": "the second client, as modelroute: reads the vault process's notice socket (a unix-socket HTTP long poll), every dial on unix (P2-2w c4e4 s2b); by review",
	"checker/checkersock":     "the third client, as modelroute: asks the checker's verify socket to check an owner code, every dial on unix (SIM-split-wire); by review",
	"inflight":                "admits the clean room's model calls under its memory budget (RES-5); serves, never dials",
}

// allowance is what one package may use of a socket-capable import: the
// names it may refer to, and why.
type allowance struct {
	why  string
	uses []string // "net.Listen", "syscall.Flock"
}

// netOK are the broker packages in the graph allowed to import net,
// syscall, or golang.org/x/sys/unix directly, the names they may use from
// them, and why. Every net.Listen and dial must name "unix" (sourceUse).
var netOK = map[string]allowance{
	"sockets": {"unix listeners, SO_PEERCRED peer checks, and flock on the socket lock, opened O_NOFOLLOW",
		[]string{"net.Conn", "net.ErrClosed", "net.Listen", "net.Listener", "net.UnixConn", "net.UnixListener",
			"syscall.EWOULDBLOCK", "syscall.Flock", "syscall.GetsockoptUcred", "syscall.LOCK_EX", "syscall.LOCK_NB",
			"syscall.O_NOFOLLOW", "syscall.SOL_SOCKET", "syscall.SO_PEERCRED", "syscall.Stat_t", "syscall.Ucred"}},
	"guest":      {"the guest plane's unix listeners; O_NOFOLLOW to read its inbox file", []string{"net.Conn", "net.ErrClosed", "net.Listen", "net.Listener", "syscall.O_NOFOLLOW"}},
	"modelroute": {"dials only the vault process's unix socket", []string{"net.Conn", "net.Dialer", "net.OpError"}},
	// The owner's mail account's client (SR3-mail-w2), as modelroute.
	"mail/mailsock": {"dials only the vault process's unix socket", []string{"net.Conn", "net.Dialer"}},
	// The owner-notice puller's client (P2-2w c4e4 s2b, #1421), as modelroute.
	"owner/notice/noticesock": {"dials only the vault process's notice unix socket", []string{"net.Conn", "net.Dialer"}},
	// The checker's verify-socket client (SIM-split-wire), as modelroute.
	"checker/checkersock": {"dials only the checker's verify unix socket", []string{"net.Conn", "net.Dialer", "net.OpError"}},
	// The Connect page's client of the mail clerk's owner socket (#3006), as modelroute.
	"localsrv/accountsock": {"dials only the mail clerk's owner unix socket", []string{"net.Dialer"}},
	// agentosd's client of the kernel's owner socket (#2682), as modelroute;
	// it dials on a thread whose effective uid alone is the owner side's.
	// It also dials the keeper's recovery-key rotation socket, as root
	// (REC-4 r4a, #3409).
	"owner/kernelsock": {"dials only the kernel's owner unix socket, as the owner side's uid on the calling thread, and the keeper's rotation unix socket",
		[]string{"golang.org/x/sys/unix.RawSyscall", "golang.org/x/sys/unix.SYS_GETEUID", "golang.org/x/sys/unix.SYS_SETRESUID", "net.Dialer"}},
	// The local inference service's client and supervisor (INFER-SVC
	// INF-2, INF-1): the client dials the service's unix socket; the
	// supervisor makes that socket, hands it to the jailed service as fd 3
	// and starts it into the inference leaf.
	"infer": {"dials only the inference service's unix socket", []string{"net.Conn", "net.Dialer"}},
	// The camera vision service's client (VIS-svc), as infer's; its
	// supervisor is infer/supervise's and needs no entry.
	"vision": {"dials only the vision service's unix socket", []string{"net.Conn", "net.Dialer"}},
	"infer/supervise": {"the inference service's unix listener; its jail's user, empty network namespace, own IPC namespace and identity-mapped user namespace; no_new_privs on the starting thread; its start into the inference leaf",
		[]string{"golang.org/x/sys/unix.PR_SET_NO_NEW_PRIVS", "golang.org/x/sys/unix.Prctl",
			"net.Listen", "net.UnixListener",
			"syscall.CLONE_NEWIPC", "syscall.CLONE_NEWNET", "syscall.CLONE_NEWUSER", "syscall.Close", "syscall.Credential",
			"syscall.O_CLOEXEC", "syscall.O_DIRECTORY", "syscall.O_RDONLY", "syscall.Open", "syscall.SysProcAttr", "syscall.SysProcIDMap"}},
	"journal": {"flock on the journal file", []string{"syscall.Flock", "syscall.LOCK_EX", "syscall.LOCK_NB"}},
	"update":  {"flock on the update store; O_NOFOLLOW to open no planted link (#3942); Stat_t to read who owns each directory above the store (#3990); openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS to read a drive beneath its root (#3989), opened O_NONBLOCK and fstat'd so a FIFO or other non-regular file is refused, and ELOOP/EXDEV named as a link (#4918)", []string{"syscall.Flock", "syscall.LOCK_EX", "syscall.O_NOFOLLOW", "syscall.Stat_t", "syscall.O_DIRECTORY", "syscall.O_CLOEXEC", "golang.org/x/sys/unix.Openat2", "golang.org/x/sys/unix.OpenHow", "golang.org/x/sys/unix.O_RDONLY", "golang.org/x/sys/unix.O_CLOEXEC", "golang.org/x/sys/unix.RESOLVE_BENEATH", "golang.org/x/sys/unix.RESOLVE_NO_SYMLINKS", "golang.org/x/sys/unix.RESOLVE_NO_MAGICLINKS", "golang.org/x/sys/unix.EAGAIN", "golang.org/x/sys/unix.EINTR", "syscall.ELOOP", "syscall.EXDEV", "golang.org/x/sys/unix.O_NONBLOCK", "golang.org/x/sys/unix.O_NOCTTY", "golang.org/x/sys/unix.Stat_t", "golang.org/x/sys/unix.Fstat", "golang.org/x/sys/unix.S_IFMT", "golang.org/x/sys/unix.S_IFREG", "golang.org/x/sys/unix.SetNonblock", "golang.org/x/sys/unix.Close"}},
	"vm/overlay": {"overlay files: xattrs, device nodes, stat, timestamps, the FICLONE ioctl for copies, and handle-relative deletion in a stopped worker's layer (CAP-8c), and directory handles to measure a layer past the path limit",
		[]string{"syscall.Close", "syscall.Dup", "syscall.EEXIST", "syscall.EINVAL", "syscall.ELOOP", "syscall.ENAMETOOLONG", "syscall.ENOENT",
			"syscall.ENOTDIR", "syscall.ENOTEMPTY", "syscall.ENXIO", "syscall.Fstat", "syscall.Getxattr", "syscall.Listxattr",
			"syscall.Mknod", "syscall.NsecToTimespec", "syscall.O_CLOEXEC", "syscall.O_DIRECTORY", "syscall.O_NOFOLLOW",
			"syscall.O_RDONLY", "syscall.Open", "syscall.Openat", "syscall.Removexattr", "syscall.Rmdir", "syscall.SYS_IOCTL",
			"syscall.S_IFCHR", "syscall.S_IFDIR", "syscall.S_IFLNK", "syscall.S_IFMT", "syscall.S_IFREG", "syscall.Setxattr",
			"syscall.Stat_t", "syscall.Statfs", "syscall.Statfs_t", "syscall.Syscall", "syscall.Timespec",
			"syscall.TimespecToNsec", "syscall.Unlinkat", "syscall.UtimesNano"}},
	"vm/gvisor": {"mounts and cgroup directory handles for runsc, and its SysProcAttr",
		[]string{"syscall.Close", "syscall.EINVAL", "syscall.ENOENT", "syscall.MNT_DETACH", "syscall.MS_NODEV",
			"syscall.MS_NOSUID", "syscall.MS_PRIVATE", "syscall.Mount", "syscall.O_CLOEXEC", "syscall.O_DIRECTORY",
			"syscall.O_RDONLY", "syscall.Open", "syscall.SysProcAttr", "syscall.Unmount"}},
	// Per-machine disk quotas (RES-4, SR2-3).
	"quota": {"quotactl_fd and FS_IOC_FS[GS]ETXATTR on the machines' directories; capget/capset to drop CAP_SYS_RESOURCE on one thread; O_NOFOLLOW to tag a tree without following links, and O_DIRECTORY|O_NOFOLLOW to open a directory refusing a link or FIFO (REV-CHK-links, #3945); no network client",
		[]string{"golang.org/x/sys/unix.CAP_SYS_RESOURCE", "golang.org/x/sys/unix.CapUserData", "golang.org/x/sys/unix.CapUserHeader",
			"golang.org/x/sys/unix.Capget", "golang.org/x/sys/unix.Capset", "golang.org/x/sys/unix.LINUX_CAPABILITY_VERSION_3",
			"golang.org/x/sys/unix.SYS_IOCTL", "golang.org/x/sys/unix.SYS_QUOTACTL_FD", "golang.org/x/sys/unix.Syscall", "golang.org/x/sys/unix.Syscall6",
			"syscall.O_DIRECTORY", "syscall.O_NOFOLLOW"}},
	// The box clock check (P2-9, W9 links it for question deadlines).
	"clock": {"read-only adjtimex (is NTP synced) and CLOCK_BOOTTIME; O_NOFOLLOW on its state and sysfs reads (REV-CHK-links, #3945); no network client",
		[]string{"golang.org/x/sys/unix.Adjtimex", "golang.org/x/sys/unix.CLOCK_BOOTTIME", "golang.org/x/sys/unix.ClockGettime", "golang.org/x/sys/unix.STA_UNSYNC", "golang.org/x/sys/unix.TIME_ERROR", "golang.org/x/sys/unix.Timespec", "golang.org/x/sys/unix.Timex", "syscall.O_NOFOLLOW"}},
	// The probe runner starts its children in a process group of their own
	// and kills the group on cancel (#515 Security 1).
	"probecmd": {"its probe children's own process group", []string{"syscall.SysProcAttr"}},
	// The one package that starts a process (P3-4b-3r-env-r8).
	"childproc": {"a child's SysProcAttr, and the process-group kill on cancel", []string{"syscall.Kill", "syscall.SIGKILL", "syscall.SysProcAttr"}},
	// The tamper verdict's digest (P3-4b-4c-nofollow): a file a guest can
	// swap is opened without following a link or blocking on a FIFO.
	"loops": {"O_NOFOLLOW and O_NONBLOCK to open a guest-writable file safely; no network client",
		[]string{"syscall.O_NOFOLLOW", "syscall.O_NONBLOCK"}},
	// The atomic replace of the owner state, the setup record and the
	// question book (#2778): a temporary opened without following a link,
	// and the owner-only check's file owner. SyncDir opens its directory
	// with O_DIRECTORY, so a FIFO or device there fails at once (#3954).
	"kernel/privfile": {"O_NOFOLLOW for its temporary, O_DIRECTORY for the synced directory, and Stat_t for the owner-only check; no network client",
		[]string{"syscall.O_DIRECTORY", "syscall.O_NOFOLLOW", "syscall.Stat_t"}},
	// The owner page's authority (#3153): x509's name constraint takes its
	// excluded address ranges as net.IPNet, and the sealed file is opened
	// without following a link or blocking on a FIFO.
	"pageca": {"net.IPNet values for x509's excluded IP ranges and ParseIP to refuse an address as the page name; O_NOFOLLOW, O_NONBLOCK and Stat_t to open the sealed authority file safely; no network client",
		[]string{"net.CIDRMask", "net.IPNet", "net.IPv4zero", "net.IPv6zero", "net.ParseIP", "syscall.O_NOFOLLOW", "syscall.O_NONBLOCK", "syscall.Stat_t"}},
	compositionRoot: {"SIGTERM for shutdown; O_NOFOLLOW, O_NONBLOCK, and Stat_t to open the launch file safely; read-only Getxattr for systemd's cgroup delegate mark (budget R13)",
		[]string{"syscall.Getxattr", "syscall.O_NOFOLLOW", "syscall.O_NONBLOCK", "syscall.SIGTERM", "syscall.Stat_t"}},
	// The follow clerk's kernel socket, which agentosd hosts (#3430):
	// kernel/proc's ListenClerk and ServeClerk, and the rest of the package
	// they come in, which serves and dials only unix sockets (its dials are
	// unixDialCalls), locks its own store and refuses to be dumpable.
	"kernel/proc": {"unix listeners and dials with SO_PEERCRED peer checks, flock on its store and restore lock, O_NOFOLLOW opens, O_NONBLOCK so the restore lock's open never waits on a FIFO; no network client",
		[]string{"net.Conn", "net.ErrClosed", "net.Listener", "net.UnixConn",
			"syscall.EWOULDBLOCK", "syscall.Flock", "syscall.GetsockoptUcred", "syscall.LOCK_EX", "syscall.LOCK_NB",
			"syscall.O_NOFOLLOW", "syscall.O_NONBLOCK", "syscall.SOL_SOCKET", "syscall.SO_PEERCRED", "syscall.Ucred"}},
	"procguard": {"prctl to read and clear the process's dumpable flag (CLK-1); no network client",
		[]string{"syscall.PR_GET_DUMPABLE", "syscall.PR_SET_DUMPABLE", "syscall.RawSyscall6", "syscall.SYS_PRCTL"}},
	"clerk/clerkkey": {"Fstat and the file type of a handed-in key descriptor; no network client",
		[]string{"syscall.Fstat", "syscall.S_IFIFO", "syscall.S_IFMT", "syscall.S_IFSOCK", "syscall.Stat_t"}},
	"clerk/handoff": {"Fstat and the file type of a handed-in descriptor; no network client",
		[]string{"syscall.Fstat", "syscall.S_IFIFO", "syscall.S_IFMT", "syscall.Stat_t"}},
	// RES-5: wraps a machine socket's listener so each open connection holds budget; never listens or dials.
	"inflight": {"wraps a caller's listener, budgeting its open connections", []string{"net.Conn", "net.ErrClosed", "net.Listener"}},
	// Root-side reads that refuse a link planted at the path (REV-CHK-links, #3945).
	"backup": {"O_NOFOLLOW on key-table reads and the target directory's sync open, with O_DIRECTORY; no network client", []string{"syscall.O_DIRECTORY", "syscall.O_NOFOLLOW"}},
	"follow": {"O_NOFOLLOW on the pending-alert read; no network client", []string{"syscall.O_NOFOLLOW"}},
	"meter":  {"O_NOFOLLOW on the meter state's read; no network client", []string{"syscall.O_NOFOLLOW"}},
}

// escapeOK are the broker packages in the graph allowed an escape hatch
// import (escapes), and why.
var escapeOK = map[string]map[string]string{
	"vm/gvisor": {"os/exec": "starts runsc, the only executable (vm/gvisor TestOnlyRunscIsExecuted)"},
	"clock":     {"os/exec": "runs /usr/bin/chronyc for read-only sync queries, the only executable (clock TestOnlyChronycIsExecuted; HOST-1b)"},
	"quota":     {"unsafe": "hands the quotactl and fsxattr structs to the kernel"},
	// LOOP-7's runners (P3-4b-3a, design A in cmd/agentosd ASSUMPTIONS):
	// each runs only a file directly in its release directory, a constant
	// in agentosd, never a link and never a path from configuration or
	// state, with a minimal environment, in a process group a timeout
	// kills whole.
	// They start them through childproc, the one package that may import
	// os/exec once P3-4b-3r-env-r8b moves vm/gvisor and clock (childproc
	// TestOnlyChildprocStartsAProcess); it checks each child's environment
	// immediately before the start.
	"childproc": {"os/exec": "starts every child, with a deny-by-default environment checked at the start (childproc TestTheEnvironmentIsDeniedByDefault)"},
}

// rawOK are the syscall numbers besides SYS_IOCTL a broker package may
// pass to a raw Syscall, and why: a raw call could otherwise open a socket.
var rawOK = map[string]map[string]string{
	"quota": {"golang.org/x/sys/unix.SYS_QUOTACTL_FD": "reads and sets project quotas (RES-4)"},
	"owner/kernelsock": {
		"golang.org/x/sys/unix.SYS_SETRESUID": "sets one thread's effective uid to the owner side's and back to root's (#2682)",
		"golang.org/x/sys/unix.SYS_GETEUID":   "checks the thread's effective uid took (#2682)",
	},
	"procguard": {"syscall.SYS_PRCTL": "reads and clears the dumpable flag only (PR_GET_DUMPABLE, PR_SET_DUMPABLE; CLK-1)"},
}

// unixDialCalls are the dial functions a package may call directly, and
// why; dials still checks each is on "unix" to a configured address.
// kernel/proc dials its clerks' and its owner seam's sockets (#3430).
var unixDialCalls = map[string]map[string]string{
	"kernel/proc": {"net.Dial": "dials only a configured clerk's or kernel's unix socket, then checks the peer's uid"},
}

// escapes are imports past the checks above: foreign code, unchecked
// memory (and go:linkname, which needs it), loaded code, and processes.
var escapes = map[string]bool{"C": true, "unsafe": true, "plugin": true, "os/exec": true}

// thirdPartyNet are the third-party packages in the graph allowed a
// socket-capable import, and which one.
var thirdPartyNet = map[string]string{
	"github.com/google/go-containerregistry/pkg/name": "net", // parses registry host names; dials nothing
	"golang.org/x/sys/unix":                           "syscall",
	"golang.org/x/term":                               "golang.org/x/sys/unix", // sigstore cryptoutils' terminal prompt
}

// socketPkgs are the standard (and x/sys) packages that can open a network
// connection or raw socket; anything that depends on net/http counts too
// (httpReach).
var socketPkgs = map[string]bool{
	"net": true, "crypto/tls": true, "net/smtp": true, "net/rpc": true, "net/rpc/jsonrpc": true,
	"log/syslog": true, "syscall": true, "golang.org/x/sys/unix": true,
}

// unixDialers are the packages whose client types may be built, as
// composite literals that set their own non-nil transport or dialer
// (clientTypes), each dial on "unix" to a configured address: modelroute
// and the mail socket's client (SR3-mail-w2), both to the vault process.
var unixDialers = map[string]bool{"modelroute": true, "mail/mailsock": true, "owner/notice/noticesock": true, "infer": true, "vision": true, "checker/checkersock": true, "localsrv/accountsock": true, "owner/kernelsock": true}

// clients are the names that hold or open a connection, by package. In
// unixDialers the types are allowed only as composite literals that set
// their own non-nil transport or dialer (clientTypes).
var clients = map[string]map[string]bool{
	"net/http":          {"Client": true, "DefaultClient": true, "DefaultTransport": true, "Transport": true, "Get": true, "Head": true, "Post": true, "PostForm": true},
	"net":               {"Dial": true, "DialTimeout": true, "DialTCP": true, "DialUDP": true, "DialIP": true, "DialUnix": true, "Dialer": true},
	"crypto/tls":        {"Dial": true, "DialWithDialer": true, "Dialer": true},
	"net/http/httptest": {"NewServer": true, "NewTLSServer": true, "NewUnstartedServer": true, "Server": true},
	"net/http/httputil": {"NewSingleHostReverseProxy": true, "ReverseProxy": true},
}

// clientTypes are the client types modelroute may build, and the field
// each literal must set to a non-nil value.
var clientTypes = map[string]string{
	"net/http.Client":                "Transport",
	"net/http.Transport":             "DialContext",
	"net/http/httputil.ReverseProxy": "Transport",
	"net.Dialer":                     "",
}

// dials are method or function names that open a connection, and the
// index of their network argument, which must be "unix".
var dials = map[string]int{"Dial": 0, "DialTimeout": 0, "DialContext": 1, "Listen": 0}

type listed struct {
	path, dir string
	imports   []string
	files     []string
	cgo, asm  int
}

func linkedDeps(t *testing.T) []listed {
	t.Helper()
	var pkgs []string
	for _, p := range linked {
		pkgs = append(pkgs, module+p)
	}
	return listDeps(t, "..", pkgs)
}

// listDeps lists the non-test dependency graph of pkgs from the module in
// dir, as the union over both cgo settings: the shipped binaries build
// with CGO_ENABLED=0 (image/build.sh) and CI's race tests with 1, and a
// file tagged for one is invisible to go list under the other (#659 L3 2,
// Security 4a 2; the childproc gate does the same).
func listDeps(t *testing.T, dir string, pkgs []string) []listed {
	t.Helper()
	byPath := map[string]*listed{}
	var order []string
	for _, cgoOn := range []string{"0", "1"} {
		args := append([]string{"list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .Imports \" \"}}\t{{join .GoFiles \" \"}}\t{{len .CgoFiles}}\t{{len .SFiles}}"}, pkgs...)
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgoOn)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (CGO_ENABLED=%s): %v\n%s", cgoOn, err, stderr.String())
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			f := strings.Split(sc.Text(), "\t")
			if len(f) != 6 {
				t.Fatalf("go list line: %q", sc.Text())
			}
			p := byPath[f[0]]
			if p == nil {
				p = &listed{path: f[0], dir: f[1]}
				byPath[f[0]] = p
				order = append(order, f[0])
			}
			for _, x := range strings.Fields(f[2]) {
				if !slices.Contains(p.imports, x) {
					p.imports = append(p.imports, x)
				}
			}
			for _, x := range strings.Fields(f[3]) {
				if !slices.Contains(p.files, x) {
					p.files = append(p.files, x)
				}
			}
			cgo, _ := strconv.Atoi(f[4])
			asm, _ := strconv.Atoi(f[5])
			p.cgo, p.asm = max(p.cgo, cgo), max(p.asm, asm)
		}
	}
	var ps []listed
	for _, path := range order {
		ps = append(ps, *byPath[path])
	}
	return ps
}

// REQ: ARC-2
func TestAgentosdLinksNoInference(t *testing.T) {
	ps := linkedDeps(t)
	if len(ps) == 0 {
		t.Fatal("no packages listed")
	}
	if bad := inferenceUse(t, ps); len(bad) > 0 {
		t.Fatalf("agentosd's import graph holds inference-capable code:\n%s", strings.Join(bad, "\n"))
	}
}

// REQ: ARC-2
//
// The graph is the union over both cgo settings, as the childproc gate's
// is: the shipped binaries build with CGO_ENABLED=0 and CI's race tests
// with 1, and an import made only in a file tagged for one is invisible to
// go list under the other (#659 L3 2, Security 4a 2).
func TestTheInferenceWalkTakesBothCgoSettings(t *testing.T) {
	dir := t.TempDir()
	root := strings.TrimSuffix(module, "/")
	for name, src := range map[string]string{
		"go.mod":         "module " + root + "\n\ngo 1.25\n",
		"daemon/d.go":    "package daemon\n",
		"daemon/cgo.go":  "//go:build cgo\n\npackage daemon\n\nimport _ \"" + module + "route\"\n",
		"daemon/pure.go": "//go:build !cgo\n\npackage daemon\n\nimport _ \"" + module + "egress\"\n",
		"route/r.go":     "package route\n",
		"egress/e.go":    "package egress\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bad := inferenceUse(t, listDeps(t, dir, []string{module + "daemon"}))
	for _, want := range []string{module + "route: forbidden in agentosd", module + "egress: forbidden in agentosd"} {
		if !slices.Contains(bad, want) {
			t.Errorf("not reported: %s; got %q", want, bad)
		}
	}
}

// inferenceUse reports each package in ps that breaks the rules above.
func inferenceUse(t *testing.T, ps []listed) []string {
	t.Helper()
	reach := httpReach(ps)
	var bad []string
	for _, p := range ps {
		rel, ours := strings.CutPrefix(p.path, module)
		for _, f := range forbidden {
			if ours && rel == f {
				bad = append(bad, p.path+": forbidden in agentosd")
			}
		}
		if !ours && providerSDK.MatchString(p.path) {
			bad = append(bad, p.path+": a model provider client")
		}
		if !ours && runtimeSDK.MatchString(p.path) {
			bad = append(bad, p.path+": an inference runtime")
		}
		if !ours && !strings.Contains(strings.SplitN(p.path, "/", 2)[0], ".") {
			continue // the standard library
		}
		if ours && (p.cgo > 0 || p.asm > 0) {
			bad = append(bad, p.path+": cgo or assembly sources")
		}
		for _, im := range p.imports {
			if strings.HasPrefix(im, module) {
				continue // checked as a package of its own
			}
			switch {
			case !ours && (reach[im] || socketPkgs[im]) && thirdPartyNet[p.path] != im:
				bad = append(bad, p.path+": third-party package imports "+im)
			case ours && reach[im] && httpOK[rel] == "":
				bad = append(bad, p.path+": imports "+im+", which reaches net/http; add it to httpOK with its reason, by review")
			case ours && socketPkgs[im] && !reach[im] && netOK[rel].why == "":
				bad = append(bad, p.path+": imports "+im+"; add it to netOK with its reason, by review")
			case ours && escapes[im] && escapeOK[rel][im] == "":
				bad = append(bad, p.path+": imports "+im+"; add it to escapeOK with its reason, by review")
			}
		}
		if !ours {
			continue
		}
		bad = append(bad, packageUse(t, p.dir, p.files, p.path, rel)...)
	}
	sort.Strings(bad)
	return bad
}

// httpReach marks every listed package that is or depends on net/http.
func httpReach(ps []listed) map[string]bool {
	imports := map[string][]string{}
	for _, p := range ps {
		imports[p.path] = p.imports
	}
	memo := map[string]bool{}
	var visit func(string) bool
	visit = func(p string) bool {
		if r, ok := memo[p]; ok {
			return r
		}
		memo[p] = p == "net/http"
		for _, im := range imports[p] {
			if visit(im) {
				memo[p] = true
				break
			}
		}
		return memo[p]
	}
	for p := range imports {
		visit(p)
	}
	return memo
}

// sourceUse reports, in one source file of broker package rel, by what its
// imports are called there (renamed and dot imports included):
//   - any client name (clients), except in modelroute a client type used
//     as a composite literal's type that sets its own non-nil transport or
//     dialer (clientTypes), or as a pointer type;
//   - any name from net, syscall, or x/sys/unix outside rel's netOK uses;
//   - any dial or Listen not called directly, or not on "unix".
func sourceUse(t *testing.T, path, name, rel string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	local := map[string]string{} // local name -> import path
	var bad []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if clients[p] == nil && !socketPkgs[p] && p != "os" {
			continue
		}
		n := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			n = im.Name.Name
		}
		if n == "." {
			bad = append(bad, name+": dot-imports "+p)
		}
		local[n] = p
	}
	uses := map[string]bool{}
	for _, u := range netOK[rel].uses {
		uses[u] = true
	}
	sel := func(e ast.Expr) string {
		if se, ok := e.(*ast.SelectorExpr); ok {
			if id, ok := se.X.(*ast.Ident); ok && local[id.Name] != "" {
				return local[id.Name] + "." + se.Sel.Name
			}
		}
		return ""
	}
	at := func(n ast.Node, what string) {
		bad = append(bad, fmt.Sprintf("%s:%d: %s", name, fset.Position(n.Pos()).Line, what))
	}
	literalType := map[ast.Expr]bool{} // client types built as checked literals
	callee := map[ast.Expr]bool{}
	// Identifiers bound by := to a checked &http.Transport{} literal, which
	// a client's Transport may name.
	transports := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && as.Tok == token.DEFINE && len(as.Lhs) == len(as.Rhs) {
			for i, l := range as.Lhs {
				if id, ok := l.(*ast.Ident); ok && transportLit(as.Rhs[i], sel) {
					transports[id.Name] = true
				}
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			full := sel(n.Type)
			key, isClient := clientTypes[full]
			if !isClient {
				return true
			}
			if key != "" && !setsChecked(n, key, sel, transports) {
				at(n, full+" without its own "+key)
			}
			if unixDialers[rel] {
				literalType[n.Type] = true
			}
		case *ast.StarExpr:
			// A pointer type (a field holding a built client) has no
			// value of its own but nil or a checked literal's.
			if _, isClient := clientTypes[sel(n.X)]; isClient && unixDialers[rel] {
				literalType[n.X] = true
			}
		case *ast.CallExpr:
			callee[n.Fun] = true
			se, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if fn := sel(se); strings.HasPrefix(fn, "syscall.Syscall") || strings.HasPrefix(fn, "syscall.RawSyscall") ||
				strings.HasPrefix(fn, "golang.org/x/sys/unix.Syscall") || strings.HasPrefix(fn, "golang.org/x/sys/unix.RawSyscall") {
				nr := ""
				if len(n.Args) > 0 {
					nr = sel(n.Args[0])
				}
				if nr != "syscall.SYS_IOCTL" && nr != "golang.org/x/sys/unix.SYS_IOCTL" && rawOK[rel][nr] == "" {
					at(n, fn+" other than SYS_IOCTL")
				}
			}
			i, isDial := dials[se.Sel.Name]
			if !isDial {
				return true
			}
			// A multi-value call spread into the dial (DialContext(t(ctx)))
			// hides its network and address, so it fails closed (#6090).
			if len(n.Args) < i+2 {
				at(n, se.Sel.Name+" with arguments the lint cannot check")
				return true
			}
			if lit, ok := n.Args[i].(*ast.BasicLit); !ok || lit.Value != `"unix"` {
				at(n, se.Sel.Name+" on a network other than \"unix\"")
			}
			// A unix socket can front a network proxy, so a dial's
			// address must come from configuration (a field or a
			// variable), never a literal or an expression built here.
			if se.Sel.Name != "Listen" && !configured(n.Args[i+1], rel, f) {
				at(n, se.Sel.Name+" to an address not taken from configuration")
			}
		case *ast.SelectorExpr:
			if _, isDial := dials[n.Sel.Name]; isDial && !callee[n] {
				at(n, n.Sel.Name+" used as a value, not called")
			}
			full := sel(n)
			if full == "" {
				return true
			}
			pkg, id := full[:strings.LastIndex(full, ".")], n.Sel.Name
			switch {
			case full == "os.StartProcess" && escapeOK[rel]["os/exec"] == "":
				at(n, "starts a process (os.StartProcess)")
			case clients[pkg][id] && !literalType[n] && !(callee[n] && unixDialCalls[rel][full] != ""):
				at(n, "network client ("+full+")")
			case socketPkgs[pkg] && !clients[pkg][id] && !uses[full]:
				at(n, full+" is outside this package's netOK uses")
			}
		}
		return true
	})
	return bad
}

// configured reports a dial address that comes from configuration, and
// accepts exactly three shapes (#6030 re-plan):
//   - a string parameter of a function declared in this file, by value,
//     that no statement here writes;
//   - a field read through such a function's parameter or receiver
//     (p.field), when configuredFields lists the parameter's type and the
//     field for package rel and nothing here writes p;
//   - a socket in a directory the function made (inTempDir).
//
// Anything else is not: a local (`sock := "/run/proxy.sock"`, #5775), a
// func literal's parameter, a named result, a constant, a literal, an
// expression, a package-level variable, a longer chain (c.a.b), or a
// name this file does not declare (L3 S1 on #90).
func configured(e ast.Expr, rel string, f *ast.File) bool {
	field := ""
	if se, ok := e.(*ast.SelectorExpr); ok {
		field, e = se.Sel.Name, se.X
	}
	id, ok := e.(*ast.Ident)
	if !ok || id.Obj == nil || id.Obj.Kind != ast.Var || written(id.Obj, f) {
		return false
	}
	typ := param(id.Obj, f)
	if field != "" {
		if st, ok := typ.(*ast.StarExpr); ok {
			typ = st.X
		}
		t, ok := typ.(*ast.Ident)
		return ok && configuredFields[rel][t.Name+"."+field] != ""
	}
	t, ok := typ.(*ast.Ident)
	return ok && t.Name == "string" || inTempDir(id.Obj, f)
}

// configuredFields are the fields a dial may read through a parameter or
// receiver, by package, as "Type.field" for a parameter of type Type or
// *Type, and why each holds only configuration. Go lets a value reach a
// struct without naming its type (assignability from an unnamed struct,
// type parameters, reflect), so no rule over syntax shows that a field is
// only ever handed in (#6030 rounds 1 to 3). Each entry is instead a claim
// a reviewer accepts, as an entry here in the PR's diff: that no code of
// the package stores into the field, so it holds what callers hand in.
// fieldStores backs the claim over the package's types (#6028).
var configuredFields = map[string]map[string]string{
	"infer":                {"Client.Path": "the inference service's socket, from agentosd's wiring"},
	"kernel/proc":          {"Conn.Socket": "a kernel or clerk socket its caller names", "remote.Socket": "Remote.Socket, embedded; a Remote is handed to Clerk"},
	"localsrv/accountsock": {"Gmail.Socket": "the mail process's owner socket, from agentosd's wiring"},
	"modelroute":           {"Config.Socket": "the vault process's model socket, from Forward's caller"},
	"owner/kernelsock":     {"Keeper.Socket": "the keeper's socket, from agentosd's wiring", "Owner.Socket": "the kernel's owner socket, from agentosd's wiring"},
}

// param is the declared type of obj when obj is a parameter or receiver
// of a function declared in f, or nil. A func literal's parameter is not
// one: the literal is called here, where its caller may pass a literal
// (Lens R1 on #6030).
func param(obj *ast.Object, f *ast.File) ast.Expr {
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		for _, fl := range []*ast.FieldList{fd.Recv, fd.Type.Params} {
			if fl == nil {
				continue
			}
			for _, p := range fl.List {
				for _, nm := range p.Names {
					if nm.Obj == obj {
						return p.Type
					}
				}
			}
		}
	}
	return nil
}

// inTempDir reports a local bound by `sock := filepath.Join(dir, "s.sock")`
// to a literal file name in dir (no "/", not "." or ".."), itself bound by `dir, err := os.MkdirTemp(...)`:
// a socket in a fresh directory this process made, which nothing listened
// on before it (agentos-infer's llama-server socket). Neither may be
// written again (written).
func inTempDir(obj *ast.Object, f *ast.File) bool {
	call, ok := definedBy(obj, f, "path/filepath.Join")
	if !ok || len(call.Args) != 2 {
		return false
	}
	dir, ok := call.Args[0].(*ast.Ident)
	name, lit := call.Args[1].(*ast.BasicLit)
	if !ok || !lit || dir.Obj == nil || written(dir.Obj, f) {
		return false
	}
	if n, err := strconv.Unquote(name.Value); err != nil || n == "" || n == "." || n == ".." || strings.Contains(n, "/") {
		return false
	}
	_, ok = definedBy(dir.Obj, f, "os.MkdirTemp")
	return ok
}

// definedBy returns the call to fn (an import path and name) that obj's
// := statement binds it to, as the first name of the statement.
func definedBy(obj *ast.Object, f *ast.File, fn string) (*ast.CallExpr, bool) {
	as, ok := obj.Decl.(*ast.AssignStmt)
	if !ok || as.Tok != token.DEFINE || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
		return nil, false
	}
	if id, ok := as.Lhs[0].(*ast.Ident); !ok || id.Obj != obj {
		return nil, false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	se, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	x, ok := se.X.(*ast.Ident)
	if !ok || x.Obj != nil {
		return nil, false
	}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		n := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			n = im.Name.Name
		}
		if n == x.Name && p+"."+se.Sel.Name == fn {
			return call, true
		}
	}
	return nil, false
}

// written reports a statement of f, other than the := that declares obj,
// that writes obj or a part of it, or takes its address.
func written(obj *ast.Object, f *ast.File) bool {
	w := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				w = w || n != obj.Decl && writes(l, obj)
			}
		case *ast.RangeStmt:
			w = w || n.Tok == token.ASSIGN && (writes(n.Key, obj) || writes(n.Value, obj))
		case *ast.IncDecStmt:
			w = w || writes(n.X, obj)
		case *ast.UnaryExpr:
			w = w || n.Op == token.AND && writes(n.X, obj)
		}
		return true
	})
	return w
}

// writes reports that e, as an assignment's target or an operand of &,
// is obj or a part of it (obj.f, obj[i], *obj).
func writes(e ast.Expr, obj *ast.Object) bool {
	for {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.Ident:
			return x.Obj == obj
		default:
			return false
		}
	}
}

// packageUse runs sourceUse on each of a package's files, then the dial
// rules that need the whole package (#6028): dialCallers, fieldStores and
// links. They rest on: callers in other packages being the composition
// root, which wires the operator's configuration; another package's code
// reaching a listed field only through what fieldStores sees handed to it
// (it cannot name the package's types); unsafe staying an escape; and a
// link or rename going only through os, syscall or x/sys/unix.
func packageUse(t *testing.T, dir string, files []string, prefix, rel string) []string {
	t.Helper()
	var bad []string
	fset := token.NewFileSet()
	var fs []*ast.File
	for _, name := range files {
		bad = append(bad, sourceUse(t, filepath.Join(dir, name), prefix+"/"+name, rel)...)
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		fs = append(fs, f)
	}
	seen := map[string]bool{}
	at := func(n ast.Node, what string) {
		p := fset.Position(n.Pos())
		s := fmt.Sprintf("%s/%s:%d: %s", prefix, filepath.Base(p.Filename), p.Line, what)
		if !seen[s] {
			seen[s] = true
			bad = append(bad, s)
		}
	}
	dialCallers(fs, rel, at)
	fieldStores(t, fset, fs, rel, at)
	links(fs, files, rel, at)
	return bad
}

// dialAddrs calls visit with each unix dial's address in f.
func dialAddrs(f *ast.File, visit func(ast.Expr)) {
	ast.Inspect(f, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if se, ok := c.Fun.(*ast.SelectorExpr); ok {
				if i, ok := dials[se.Sel.Name]; ok && se.Sel.Name != "Listen" && len(c.Args) >= i+2 {
					visit(c.Args[i+1])
				}
			}
		}
		return true
	})
}

// dialCallers holds each caller in the package to what configured holds a
// dial to (#6028). configured takes a function's string parameter as
// configuration, so the function is a dialing function: each call to it
// in the package must pass, for that parameter, what configured accepts
// in the caller's file, and a caller passing its own string parameter is
// a dialing function too. Calls match by name (h, or any method m), so an
// interface or another type's method of the same name is held too; a
// dialing function taken as a value, called as a method expression, or
// handed arguments the lint cannot count fails closed. Callers outside
// the package are the composition root's wiring of its configuration.
func dialCallers(fs []*ast.File, rel string, at func(ast.Node, string)) {
	addr := map[string]map[int]bool{} // "h" or ".m" -> parameter index
	add := func(e ast.Expr, f *ast.File) bool {
		key, i, ok := stringParam(e, f)
		if !ok || addr[key][i] {
			return false
		}
		if addr[key] == nil {
			addr[key] = map[int]bool{}
		}
		addr[key][i] = true
		return true
	}
	for _, f := range fs {
		dialAddrs(f, func(e ast.Expr) { add(e, f) })
	}
	types := map[string]bool{}
	for _, f := range fs {
		for name := range typeDecls(f) {
			types[name] = true
		}
	}
	for grew := true; grew; {
		grew = false
		for _, f := range fs {
			imported := map[string]bool{}
			for _, im := range f.Imports {
				p, _ := strconv.Unquote(im.Path.Value)
				n := p[strings.LastIndex(p, "/")+1:]
				if im.Name != nil {
					n = im.Name.Name
				}
				imported[n] = true
			}
			// key is the dialing function e names, or "".
			key := func(e ast.Expr) string {
				switch x := e.(type) {
				case *ast.Ident:
					return x.Name
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && id.Obj == nil && imported[id.Name] {
						return ""
					}
					return "." + x.Sel.Name
				}
				return ""
			}
			called, named := map[ast.Node]bool{}, map[ast.Node]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncDecl:
					named[n.Name] = true
				case *ast.SelectorExpr:
					named[n.Sel] = true
				case *ast.KeyValueExpr:
					named[n.Key] = true
				case *ast.CallExpr:
					called[n.Fun] = true
					k := key(n.Fun)
					if len(addr[k]) == 0 {
						return true
					}
					if se, ok := n.Fun.(*ast.SelectorExpr); ok && methodExpr(se.X, types) {
						at(n, k[1:]+", a dialing function, called as a method expression")
						return true
					}
					for i := range addr[k] {
						if n.Ellipsis.IsValid() || i >= len(n.Args) {
							at(n, strings.TrimPrefix(k, ".")+", a dialing function, with arguments the lint cannot check")
							continue
						}
						if !configured(n.Args[i], rel, f) {
							at(n, "passes "+strings.TrimPrefix(k, ".")+" an address not taken from configuration")
						} else if add(n.Args[i], f) {
							grew = true
						}
					}
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				var k string
				switch x := n.(type) {
				case *ast.Ident:
					if named[x] {
						return true
					}
					k = x.Name
				case *ast.SelectorExpr:
					if k = key(x); k == "" {
						return true
					}
				default:
					return true
				}
				if len(addr[k]) > 0 && !called[n] {
					at(n, strings.TrimPrefix(k, ".")+", a dialing function, used as a value")
				}
				return true
			})
		}
	}
}

// stringParam returns the function (as "h" or ".m") and index of the
// by-value string parameter e names, which configured accepts.
func stringParam(e ast.Expr, f *ast.File) (string, int, bool) {
	id, ok := e.(*ast.Ident)
	if !ok || id.Obj == nil {
		return "", 0, false
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		i := 0
		for _, p := range fd.Type.Params.List {
			for _, nm := range p.Names {
				if t, ok := p.Type.(*ast.Ident); ok && t.Name == "string" && nm.Obj == id.Obj {
					if fd.Recv != nil {
						return "." + fd.Name.Name, i, true
					}
					return fd.Name.Name, i, true
				}
				i++
			}
			if len(p.Names) == 0 {
				i++
			}
		}
	}
	return "", 0, false
}

// methodExpr reports x as a type (T.m or (*T).m), so a call's arguments
// start with the receiver.
func methodExpr(x ast.Expr, types map[string]bool) bool {
	switch x := x.(type) {
	case *ast.Ident:
		return types[x.Name] || x.Obj != nil && x.Obj.Kind == ast.Typ
	case *ast.ParenExpr, *ast.StarExpr, *ast.IndexExpr:
		return true
	}
	return false
}

// typeDecls are f's type declarations, by name.
func typeDecls(f *ast.File) map[string]*ast.TypeSpec {
	m := map[string]*ast.TypeSpec{}
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				m[ts.Name.Name] = ts
			}
		}
	}
	return m
}

// fieldStores backs the configuredFields claim, that the package never
// stores into a listed field, over the package's go/types types, so it
// does not guess at any expression (#6028 re-plan after three Security
// rounds on #6119). A listed field is a slot: a field index in a struct
// shape, so any struct type identical to its owner's (tags aside), named
// or not, has the same slot, and a conversion between them changes
// nothing. In a listed package, it reports:
//   - a write or & of a slot (assignment, op-assignment, ++, range);
//   - a composite literal that sets a slot, by key or by position;
//   - a value of a type that reaches a slot (holds), wherever it may end
//     up in an interface or in code outside the package: converted to an
//     interface (assignment, call argument, return, literal element, send,
//     map key, range), handed to a function or method of another package,
//     or a type argument of any generic. Only those reach it by
//     reflection (decoders, fmt, reflect itself), since another package
//     cannot name the package's types, and unsafe stays an escape. Every
//     place a value can go is listed in use; any other is reported, so a
//     form it does not know fails closed.
//
// The rule is about types, not order: where in the program a store would
// run does not matter, so no flow is followed (Security B1 round 3 on
// #6119).
func fieldStores(t *testing.T, fset *token.FileSet, fs []*ast.File, rel string, at func(ast.Node, string)) {
	t.Helper()
	if len(configuredFields[rel]) == 0 {
		return
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "gc", exportData(t, fs))}
	pkg, err := conf.Check(module+rel, fset, fs, info)
	if err != nil {
		at(fs[0], "does not type-check, so its configuredFields stores cannot be checked: "+err.Error())
		return
	}
	// The slots: each listed field's struct and index, through embedding.
	type slot struct {
		st *types.Struct
		i  int
	}
	var slots []slot
	for tf := range configuredFields[rel] {
		typ, field, _ := strings.Cut(tf, ".")
		tn, ok := pkg.Scope().Lookup(typ).(*types.TypeName)
		if !ok {
			continue // a type the package does not declare holds nothing
		}
		obj, idx, _ := types.LookupFieldOrMethod(tn.Type(), true, pkg, field)
		if _, ok := obj.(*types.Var); !ok {
			at(fs[0], "configuredFields lists "+tf+", which is not a field")
			continue
		}
		st := structOf(tn.Type())
		for _, i := range idx[:len(idx)-1] {
			st = structOf(st.Field(i).Type())
		}
		slots = append(slots, slot{st, idx[len(idx)-1]})
	}
	// listed is the slots st has, as field indices.
	listed := func(st *types.Struct) map[int]bool {
		m := map[int]bool{}
		for _, s := range slots {
			if st != nil && types.IdenticalIgnoreTags(st, s.st) {
				m[s.i] = true
			}
		}
		return m
	}
	// holds reports a type from which a slot can be reached: through
	// pointers, elements, keys, fields, a function's parameters or
	// results, or an exported method of the type or any method of an
	// interface. A copy counts as much as a reference: a copy hands over
	// the type, from which other code can mint a value (reflect.New,
	// gob.Register) that dials (Security B1 on #6123).
	memo := map[types.Type]bool{}
	var holders []types.Type
	var reach func(t types.Type, seen map[types.Type]bool) bool
	reach = func(t types.Type, seen map[types.Type]bool) bool {
		if r, ok := memo[t]; ok {
			return r
		}
		if t == nil || seen[t] {
			return false
		}
		seen[t] = true
		r := false
		in := func(t types.Type) { r = r || reach(t, seen) }
		switch x := t.(type) {
		case *types.Alias:
			in(types.Unalias(x))
		case *types.Named:
			for _, ms := range []*types.MethodSet{types.NewMethodSet(x), types.NewMethodSet(types.NewPointer(x))} {
				for i := range ms.Len() {
					if ms.At(i).Obj().Exported() {
						in(ms.At(i).Type())
					}
				}
			}
			in(x.Underlying())
		case *types.Pointer:
			in(x.Elem())
		case *types.Slice:
			in(x.Elem())
		case *types.Chan:
			in(x.Elem())
		case *types.Map:
			in(x.Key())
			in(x.Elem())
		case *types.Array:
			in(x.Elem())
		case *types.Struct:
			r = len(listed(x)) > 0
			for i := range x.NumFields() {
				in(x.Field(i).Type())
			}
		case *types.Signature:
			in(x.Params())
			in(x.Results())
		case *types.Tuple:
			for i := range x.Len() {
				in(x.At(i).Type())
			}
		case *types.Interface:
			for i := range x.NumMethods() {
				in(x.Method(i).Type())
			}
			// An interface a holder implements holds: its values' dynamic
			// type is a holder's, which reflect.TypeOf hands out.
			for _, h := range holders {
				r = r || x.NumMethods() > 0 && types.Implements(h, x)
			}
		}
		if len(seen) == 1 || r {
			memo[t] = r // a false inside a cycle may be a partial answer
		}
		return r
	}
	holds := func(t types.Type) bool { return reach(t, map[types.Type]bool{}) }
	// holders are the package's named types, in any scope, that hold a
	// slot, and their pointers, grown to a fixed point: a type that holds
	// only through an interface a holder implements is a holder too.
	for grew := true; grew; {
		grew = false
		for _, obj := range info.Defs {
			tn, ok := obj.(*types.TypeName)
			if ok && !tn.IsAlias() && !slices.Contains(holders, tn.Type()) && holds(tn.Type()) {
				holders = append(holders, tn.Type(), types.NewPointer(tn.Type()))
				clear(memo)
				grew = true
			}
		}
	}
	name := func(t types.Type) string { return types.TypeString(t, types.RelativeTo(pkg)) }
	// Each node's parent, and each return's function signature.
	parent := map[ast.Node]ast.Node{}
	sigOf := map[*ast.ReturnStmt]*types.Signature{}
	for _, f := range fs {
		var stack []ast.Node
		var sigs []*types.Signature
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				switch stack[len(stack)-1].(type) {
				case *ast.FuncDecl, *ast.FuncLit:
					sigs = sigs[:len(sigs)-1]
				}
				stack = stack[:len(stack)-1]
				return true
			}
			if len(stack) > 0 {
				parent[n] = stack[len(stack)-1]
			}
			switch x := n.(type) {
			case *ast.FuncDecl:
				sigs = append(sigs, info.Defs[x.Name].Type().(*types.Signature))
			case *ast.FuncLit:
				sigs = append(sigs, info.Types[x].Type.(*types.Signature))
			case *ast.ReturnStmt:
				sigOf[x] = sigs[len(sigs)-1]
			}
			stack = append(stack, n)
			return true
		})
	}
	// reviewed reports an interface handOK lists, by name or package.
	reviewed := func(t types.Type) bool {
		n, ok := types.Unalias(t).(*types.Named)
		return handOK[rel][types.TypeString(t, nil)] != "" || ok && n.Obj().Pkg() != nil && handOK[rel][n.Obj().Pkg().Path()] != ""
	}
	// into reports v, of a type that holds a slot, going to a place of
	// type to: an interface or a type parameter could hand it on.
	into := func(v ast.Node, from, to types.Type) {
		if to != nil && types.IsInterface(to) && holds(from) && !reviewed(to) {
			at(v, "hands "+name(from)+", which reaches a configuredFields field, to "+name(to))
		}
	}
	// spread checks a value list against the places it goes, a single
	// multi-value call included.
	spread := func(vals []ast.Expr, to func(int) types.Type) {
		if len(vals) == 1 {
			if tu, ok := info.TypeOf(vals[0]).(*types.Tuple); ok {
				for i := range tu.Len() {
					into(vals[0], tu.At(i).Type(), to(i))
				}
				return
			}
		}
		for i, v := range vals {
			into(v, info.TypeOf(v), to(i))
		}
	}
	// use checks where e, whose type holds a slot, goes.
	use := func(e ast.Expr) {
		p := parent[e]
		for pe, ok := p.(*ast.ParenExpr); ok; pe, ok = p.(*ast.ParenExpr) {
			e, p = pe, parent[pe]
		}
		switch p := p.(type) {
		case *ast.SelectorExpr, *ast.StarExpr, *ast.UnaryExpr, *ast.BinaryExpr, *ast.SliceExpr, *ast.TypeAssertExpr,
			*ast.ExprStmt, *ast.IncDecStmt, *ast.SwitchStmt, *ast.CaseClause, *ast.IndexListExpr:
			return // read in place, compared, or written whole
		case *ast.IndexExpr:
			if e == p.Index {
				if m, ok := info.TypeOf(p.X).Underlying().(*types.Map); ok {
					into(e, info.TypeOf(e), m.Key())
				}
			}
			return
		case *ast.CallExpr:
			if e == p.Fun {
				return
			}
			fun := ast.Unparen(p.Fun)
			if tv := info.Types[fun]; tv.IsType() {
				into(e, info.TypeOf(e), tv.Type)
				return
			}
			if ix, ok := fun.(*ast.IndexExpr); ok {
				fun = ix.X
			} else if ix, ok := fun.(*ast.IndexListExpr); ok {
				fun = ix.X
			}
			var obj types.Object
			switch f := fun.(type) {
			case *ast.Ident:
				obj = info.Uses[f]
			case *ast.SelectorExpr:
				obj = info.Uses[f.Sel]
			}
			if fn, ok := obj.(*types.Func); ok && fn.Pkg() != pkg {
				if !holds(info.TypeOf(e)) || handOK[rel][fn.FullName()] != "" || handOK[rel][fn.Pkg().Path()] != "" {
					return
				}
				at(e, "hands "+name(info.TypeOf(e))+", which reaches a configuredFields field, to "+fn.FullName()+" outside the package")
				return
			}
			sig := info.TypeOf(p.Fun).Underlying().(*types.Signature)
			spread(p.Args, func(i int) types.Type {
				n := sig.Params().Len()
				if sig.Variadic() && i >= n-1 {
					if p.Ellipsis.IsValid() {
						return sig.Params().At(n - 1).Type()
					}
					return sig.Params().At(n - 1).Type().(*types.Slice).Elem()
				}
				if i < n {
					return sig.Params().At(i).Type()
				}
				return nil
			})
			return
		case *ast.AssignStmt:
			if slices.Contains(p.Lhs, e) {
				return
			}
			spread(p.Rhs, func(i int) types.Type { return info.TypeOf(p.Lhs[i]) })
			return
		case *ast.ValueSpec:
			spread(p.Values, func(i int) types.Type { return info.Defs[p.Names[i]].Type() })
			return
		case *ast.ReturnStmt:
			sig := sigOf[p]
			spread(p.Results, func(i int) types.Type { return sig.Results().At(i).Type() })
			return
		case *ast.CompositeLit:
			i := slices.Index(p.Elts, e)
			switch u := litType(info.TypeOf(p)).(type) {
			case *types.Struct:
				into(e, info.TypeOf(e), u.Field(i).Type())
			case *types.Slice:
				into(e, info.TypeOf(e), u.Elem())
			case *types.Array:
				into(e, info.TypeOf(e), u.Elem())
			}
			return
		case *ast.KeyValueExpr:
			switch u := litType(info.TypeOf(parent[p].(*ast.CompositeLit))).(type) {
			case *types.Struct:
				for i := range u.NumFields() {
					if k, ok := p.Key.(*ast.Ident); ok && e == p.Value && u.Field(i).Name() == k.Name {
						into(e, info.TypeOf(e), u.Field(i).Type())
					}
				}
			case *types.Slice:
				into(e, info.TypeOf(e), u.Elem())
			case *types.Array:
				into(e, info.TypeOf(e), u.Elem())
			case *types.Map:
				if e == p.Key {
					into(e, info.TypeOf(e), u.Key())
				} else {
					into(e, info.TypeOf(e), u.Elem())
				}
			}
			return
		case *ast.SendStmt:
			if e == p.Value {
				into(e, info.TypeOf(e), coreType(info.TypeOf(p.Chan)).(*types.Chan).Elem())
			}
			return
		case *ast.RangeStmt:
			if e == p.X && p.Tok == token.ASSIGN {
				k, v := rangeTypes(info.TypeOf(e))
				for _, x := range [][2]any{{p.Key, k}, {p.Value, v}} {
					if l, _ := x[0].(ast.Expr); l != nil && x[1] != nil {
						into(e, x[1].(types.Type), info.TypeOf(l))
					}
				}
			}
			return
		case *ast.GoStmt, *ast.DeferStmt:
			return
		}
		at(e, "a "+name(info.TypeOf(e))+", which reaches a configuredFields field, goes where the lint cannot check")
	}
	for e, tv := range info.Types {
		if tv.IsValue() && holds(tv.Type) {
			use(e)
		}
	}
	for id, inst := range info.Instances {
		if fn, ok := info.Uses[id].(*types.Func); ok && (handOK[rel][fn.FullName()] != "" || handOK[rel][fn.Pkg().Path()] != "") {
			continue
		}
		for i := range inst.TypeArgs.Len() {
			if ta := inst.TypeArgs.At(i); holds(ta) {
				at(id, "instantiates "+id.Name+" with "+name(ta)+", which reaches a configuredFields field")
			}
		}
	}
	// outOf reports a value taken out of an interface as a type that
	// reaches a slot (an interface a holder implements included): another
	// package's code may have made it (Security B1 on #6123).
	outOf := func(n ast.Node, t types.Type) {
		if t == nil || types.Identical(t, types.Typ[types.UntypedNil]) {
			return
		}
		if holds(t) {
			at(n, "takes a "+name(t)+", which reaches a configuredFields field, out of an interface")
		}
	}
	// Stores into a slot, literals that set one, and values taken out of
	// an interface as a type that reaches one: another package's code may
	// have made them, from a copy it was handed (#6028).
	for _, f := range fs {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.TypeAssertExpr:
				if n.Type != nil {
					outOf(n, info.TypeOf(n.Type))
				}
			case *ast.TypeSwitchStmt:
				for _, cc := range n.Body.List {
					for _, e := range cc.(*ast.CaseClause).List {
						outOf(e, info.TypeOf(e))
					}
				}
			case *ast.SelectorExpr:
				sel := info.Selections[n]
				if sel == nil || sel.Kind() != types.FieldVal {
					return true
				}
				st, idx := structOf(sel.Recv()), sel.Index()
				for _, i := range idx[:len(idx)-1] {
					st = structOf(st.Field(i).Type())
				}
				if !listed(st)[idx[len(idx)-1]] {
					return true
				}
				var e ast.Node = n
				p := parent[e]
				for pe, ok := p.(*ast.ParenExpr); ok; pe, ok = p.(*ast.ParenExpr) {
					e, p = pe, parent[pe]
				}
				write := false
				switch p := p.(type) {
				case *ast.AssignStmt:
					write = slices.Contains(p.Lhs, e.(ast.Expr))
				case *ast.UnaryExpr:
					write = p.Op == token.AND
				case *ast.IncDecStmt:
					write = true
				case *ast.RangeStmt:
					write = e == p.Key || e == p.Value
				}
				if write {
					at(n, "stores into "+n.Sel.Name+", a configuredFields field")
				}
			case *ast.CompositeLit:
				st, _ := litType(info.TypeOf(n)).(*types.Struct)
				slotsHere := listed(st)
				for i, el := range n.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						if slotsHere[i] {
							at(n, "sets a configuredFields field by position here")
						}
						continue
					}
					if k, isID := kv.Key.(*ast.Ident); isID {
						for j := range slotsHere {
							if st.Field(j).Name() == k.Name {
								at(n, "sets "+k.Name+", a configuredFields field, here")
							}
						}
					}
				}
			}
			return true
		})
	}
}

// handOK are the functions of other packages (by go/types full name)
// that a listed package may hand a value reaching a configuredFields
// field, or instantiate with its type, and the interfaces (by full type
// name) it may convert one to, by package, and why each neither stores
// into the field nor mints a value of the type: a claim a reviewer
// accepts, as configuredFields' entries are.
var handOK = map[string]map[string]string{
	"kernel/proc": {
		"maps.Keys":       "ranges over a map's keys; writes nothing (kernelmain.go, the clerk names)",
		module + "backup": "the backup set and writer: it calls the methods of the Targets it is handed (*pendingPut, dirTarget, inFlight) and keeps them, nothing else; it imports no reflect, unsafe or gob, and its json decodes target only its own manifest and table types",
		"io.ReadCloser":   "logSource (backup.go) returns the log file as a section reader and its *os.File closer; the type counts only because *Kernel is an io.Closer, and backup only reads and closes what Open returns",
		module + "kernel": "the kernel: it calls Do and Probe on the Clerks it is handed and keeps them, and the backup Set it opens; its one reflect use is DeepEqual of two Plans, it imports no unsafe or gob, and its json decodes target only its own log types",
	},
}

// structOf is the struct a field selection steps through: t's, or its
// pointee's, or its type parameter's core type's.
func structOf(t types.Type) *types.Struct {
	if p, ok := types.Unalias(t).Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	st, _ := coreType(t).(*types.Struct)
	return st
}

// litType is a composite literal's core type; go/types gives an elided
// &T{} element the type *T.
func litType(t types.Type) types.Type {
	if p, ok := coreType(t).(*types.Pointer); ok {
		return coreType(p.Elem())
	}
	return coreType(t)
}

// coreType is t's underlying type, or a type parameter's single one.
func coreType(t types.Type) types.Type {
	tp, ok := types.Unalias(t).(*types.TypeParam)
	if !ok {
		return types.Unalias(t).Underlying()
	}
	var core types.Type
	iface := tp.Constraint().Underlying().(*types.Interface)
	for i := range iface.NumEmbeddeds() {
		var terms []*types.Term
		switch e := iface.EmbeddedType(i).(type) {
		case *types.Union:
			for j := range e.Len() {
				terms = append(terms, e.Term(j))
			}
		default:
			terms = append(terms, types.NewTerm(false, e))
		}
		for _, term := range terms {
			if u := term.Type().Underlying(); core == nil {
				core = u
			} else if !types.Identical(core, u) {
				return nil
			}
		}
	}
	return core
}

// rangeTypes are a range clause's key and value types over t.
func rangeTypes(t types.Type) (k, v types.Type) {
	switch u := coreType(t).(type) {
	case *types.Slice:
		return types.Typ[types.Int], u.Elem()
	case *types.Array:
		return types.Typ[types.Int], u.Elem()
	case *types.Pointer:
		if a, ok := u.Elem().Underlying().(*types.Array); ok {
			return types.Typ[types.Int], a.Elem()
		}
	case *types.Map:
		return u.Key(), u.Elem()
	case *types.Chan:
		return u.Elem(), nil
	case *types.Signature:
		if u.Params().Len() == 1 {
			yield := u.Params().At(0).Type().Underlying().(*types.Signature)
			if yield.Params().Len() > 0 {
				k = yield.Params().At(0).Type()
			}
			if yield.Params().Len() > 1 {
				v = yield.Params().At(1).Type()
			}
		}
	}
	return k, v
}

// exports maps an import path to its export data file, from go list.
var exports sync.Map

// exportData is the lookup go/importer's gc importer reads fs's imports
// (and theirs) through: the export data go list -export builds for them.
func exportData(t *testing.T, fs []*ast.File) func(string) (io.ReadCloser, error) {
	t.Helper()
	var need []string
	for _, f := range fs {
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if _, ok := exports.Load(p); !ok && p != "unsafe" && !slices.Contains(need, p) {
				need = append(need, p)
			}
		}
	}
	if len(need) > 0 {
		cmd := exec.Command("go", append([]string{"list", "-e", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}"}, need...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -export: %v\n%s", err, stderr.String())
		}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if p, file, ok := strings.Cut(l, "\t"); ok && file != "" {
				exports.Store(p, file)
			}
		}
	}
	return func(path string) (io.ReadCloser, error) {
		file, ok := exports.Load(path)
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file.(string))
	}
}

// imports are f's import names, and the path each names.
func imports(f *ast.File) (map[string]bool, map[string]string) {
	imp, local := map[string]bool{}, map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		nm := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			nm = im.Name.Name
		}
		imp[nm], local[nm] = true, p
	}
	return imp, local
}

// linkCalls are the calls that make, move or replace a directory entry,
// so a configured socket path, or its directory, could come to name
// another socket (Security 4 on #6035).
var linkCalls = map[string]bool{
	"os.Symlink": true, "os.Link": true, "os.Rename": true,
	"syscall.Symlink": true, "syscall.Link": true, "syscall.Rename": true,
	"syscall.Symlinkat": true, "syscall.Linkat": true, "syscall.Renameat": true,
	"golang.org/x/sys/unix.Symlink": true, "golang.org/x/sys/unix.Link": true, "golang.org/x/sys/unix.Rename": true,
	"golang.org/x/sys/unix.Symlinkat": true, "golang.org/x/sys/unix.Linkat": true, "golang.org/x/sys/unix.Renameat": true,
	"golang.org/x/sys/unix.Renameat2": true,
}

// linkOK are the linkCalls (or linkMethods, as ".Name") each file of a
// package that dials may make, called or taken as a value, and why; a
// file that dials makes none. Any other file owes an entry by review.
var linkOK = map[string]map[string]string{
	"kernel/proc/backup.go":  {"os.Link": "links a backup's content file into its snapshot, under the kernel's backup dir; also held as backups.link, its only use"},
	"kernel/proc/restore.go": {"os.Rename": "moves a restore's staged content into the content dir"},
}

// linkMethods are the method names that make, move or replace a directory
// entry (os.Root's, and any wrapper's); a method of that name on any value
// counts.
var linkMethods = map[string]bool{"Symlink": true, "Link": true, "Rename": true}

// links refuses a linkCall or linkMethods method, called or taken as a
// value, and os.OpenRoot or os.OpenInRoot, in a package that dials a unix
// socket, except a linkOK use in its own file, which does not dial
// (Security 4 on #6035, B2 and B3 on #6119).
func links(fs []*ast.File, names []string, rel string, at func(ast.Node, string)) {
	if !unixDialers[rel] && unixDialCalls[rel] == nil {
		return
	}
	for i, f := range fs {
		_, local := imports(f)
		dialsHere := false
		dialAddrs(f, func(ast.Expr) { dialsHere = true })
		ok := linkOK[rel+"/"+names[i]]
		ast.Inspect(f, func(n ast.Node) bool {
			se, isSel := n.(*ast.SelectorExpr)
			if !isSel {
				return true
			}
			full := "." + se.Sel.Name
			if id, isID := se.X.(*ast.Ident); isID && id.Obj == nil && local[id.Name] != "" {
				full = local[id.Name] + "." + se.Sel.Name
				if full == "os.OpenRoot" || full == "os.OpenInRoot" {
					at(se, "opens an os.Root ("+full+"), whose methods link and rename, in a package that dials a unix socket")
					return true
				}
				if !linkCalls[full] {
					return true
				}
			} else if !linkMethods[se.Sel.Name] {
				return true
			}
			if dialsHere || ok[full] == "" {
				at(se, "links or renames ("+strings.TrimPrefix(full, ".")+") in a package that dials a unix socket")
			}
			return true
		})
	}
}

// setsChecked reports that a client literal sets field key to a value the
// test can see: DialContext to a function literal, and Transport to a
// checked &http.Transport{} literal or an identifier bound to one.
func setsChecked(c *ast.CompositeLit, key string, sel func(ast.Expr) string, transports map[string]bool) bool {
	for _, e := range c.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != key {
			continue
		}
		switch key {
		case "DialContext":
			_, ok := kv.Value.(*ast.FuncLit)
			return ok
		case "Transport":
			if id, ok := kv.Value.(*ast.Ident); ok {
				return transports[id.Name]
			}
			return transportLit(kv.Value, sel)
		}
	}
	return false
}

// transportLit reports &http.Transport{...}, which the inspection checks
// as a literal of its own.
func transportLit(e ast.Expr, sel func(ast.Expr) string) bool {
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return false
	}
	c, ok := u.X.(*ast.CompositeLit)
	return ok && sel(c.Type) == "net/http.Transport"
}

// The checks themselves catch what they are for, including the probes L3
// on #83 got past earlier versions: clients reached through other standard
// packages, renamed imports, raw sockets, a dial to anything but a unix
// socket, client values built outside a checked literal, and dial methods
// taken as values.
func TestImportCheckCatchesARouter(t *testing.T) {
	if !providerSDK.MatchString("github.com/anthropics/anthropic-sdk-go") || !providerSDK.MatchString("github.com/sashabaranov/go-openai") {
		t.Fatal("provider pattern misses an SDK")
	}
	if !contains(forbidden, "route") {
		t.Fatal("route is not forbidden")
	}
	if !contains(forbidden, "cmd/agentos-infer") {
		t.Fatal("the inference service is not forbidden")
	}
	if !contains(forbidden, "cmd/agentos-vision") {
		t.Fatal("the vision service is not forbidden")
	}
	src := func(imports, body string) string { return "package p\nimport (" + imports + ")\n" + body + "\n" }
	for _, c := range []struct{ rel, src string }{
		{"guest", src(`nh "net/http"`, `var c = &nh.Client{}`)},
		{"guest", src(`. "net/http"`, `var c = DefaultClient`)},
		{"loops", src(`"net/http/httputil"`, `var p = httputil.NewSingleHostReverseProxy(nil)`)},
		{"meter", src(`"net/http/httptest"`, `var c = httptest.NewServer(nil).Client()`)},
		{"loops", src(`"crypto/tls"`, `var c, _ = tls.Dial("tcp", "x:443", nil)`)},
		{"journal", src(`"syscall"`, `var fd, _ = syscall.Socket(2, 1, 0)`)},
		{"guest", src(`"net"`, `var c, _ = net.ListenPacket("udp", ":0")`)},
		{"guest", src(`"net"`, `var a, _ = net.LookupHost("x")`)},
		{"guest", src(`"net"`, `var l, _ = net.Listen("tcp", ":0")`)},
		{"modelroute", src(`"net"`, `var c, _ = (&net.Dialer{}).Dial("tcp", "x:443")`)},
		{"modelroute", src(`"net/http"`, `var c = &http.Client{}`)},
		{"modelroute", src(`"net/http"`, `var c = &http.Client{Transport: nil}`)},
		{"modelroute", src(`"net/http"`, `var c = new(http.Client)`)},
		{"modelroute", src(`"net/http"`, `var tr http.Transport`)},
		{"modelroute", src(`"net/http"`, `var tr = &http.Transport{}`)},
		{"modelroute", src(`"net/http/httputil"`, `var p = &httputil.ReverseProxy{}`)},
		{"modelroute", src(`"net/http"`, `var r, _ = http.Get("http://x")`)},
		{"modelroute", src(`"net"`, `var d net.Dialer; var f = d.DialContext`)},
		{"modelroute", src(`"net"`, `func g() { d := &net.Dialer{}; f := d.DialContext; f(nil, "tcp", "x:443") }`)},
		{"modelroute", src(`"net/http"`, `var rt http.RoundTripper; var c = &http.Client{Transport: rt}`)},
		{"modelroute", src(`"net/http"; "net/http/httputil"`, `var rt http.RoundTripper; var p = httputil.ReverseProxy{Transport: rt}`)},
		{"modelroute", src(`"net/http"`, `var c = &http.Client{Transport: http.RoundTripper(nil)}`)},
		{"modelroute", src(`"net/http"`, `var none func(); var tr = &http.Transport{DialContext: none}`)},
		{"vm/overlay", src(`"syscall"`, `var a, b, e = syscall.Syscall(41, 2, 1, 0)`)},
		{"loops", src(`"os"`, `var p, _ = os.StartProcess("/bin/sh", nil, nil)`)},
		{"modelroute", src(`"net"`, `var c, _ = (&net.Dialer{}).Dial("unix", "/run/proxy.sock")`)},
		{"modelroute", src(`"net"; "path/filepath"`, `var c, _ = (&net.Dialer{}).Dial("unix", filepath.Join("/run", "p.sock"))`)},
		{"modelroute", src(`"net"`, `const sock = "/run/proxy.sock"; var c, _ = (&net.Dialer{}).Dial("unix", sock)`)},
		{"modelroute", src(`"net"`, `var sock = "/run/proxy.sock"; var c, _ = (&net.Dialer{}).Dial("unix", sock)`)},
		{"modelroute", src(`"net"`, `func g() { (&net.Dialer{}).Dial("unix", otherFileSock) }`)},
		{"modelroute", src(`"net"; "os"`, `func g() { (&net.Dialer{}).Dial("unix", os.DevNull) }`)},
		{"mail/mailsock", src(`"net"`, `func g() { (&net.Dialer{}).DialContext(nil, "tcp", "imap.example.com:993") }`)},
		{"mail/mailsock", src(`"net"`, `func g() { (&net.Dialer{}).DialContext(nil, "unix", "/run/agentos-egress/mail.sock") }`)},
		{"mail/mailsock", src(`"net"`, `var c, _ = net.Dial("tcp", "smtp.example.com:465")`)},
		// A local bound to a literal is not configuration, whichever dial
		// names it (#5775).
		{"kernel/proc", src(`"net"`, `func g() { sock := "/run/proxy.sock"; net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"}) }`)},
		// A multi-value call spread into a dial hides both its network and
		// its address, so the lint refuses it (#6090).
		{"modelroute", src(`"context"; "net"`, `func t(ctx context.Context) (context.Context, string, string) { return ctx, "tcp", "evil.example:443" }; func g(ctx context.Context) { (&net.Dialer{}).DialContext(t(ctx)) }`)},
		{"modelroute", src(`"net"`, `func t() (string, string) { return "tcp", "evil.example:443" }; func g() { (&net.Dialer{}).Dial(t()) }`)},
		{"modelroute", src(`"net"; "time"`, `func t() (string, string, time.Duration) { return "tcp", "evil.example:443", 0 }; func g() { net.DialTimeout(t()) }`)},
		{"modelroute", src(`"net"`, `func t() (string, string) { return "tcp", ":0" }; func g() { net.Listen(t()) }`)},
	} {
		path := filepath.Join(t.TempDir(), "p.go")
		if err := os.WriteFile(path, []byte(c.src), 0o600); err != nil {
			t.Fatal(err)
		}
		if len(sourceUse(t, path, "p.go", c.rel)) == 0 {
			t.Errorf("missed in %s:\n%s", c.rel, c.src)
		}
	}
	// A local, a named result, or a parameter written here is not
	// configuration, nor is a name built in a directory this function did
	// not make, and each is reported for its address (#5775).
	for _, c := range []string{
		src(`"net"`, `func g() { sock := "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"`, `func g() { sock := "/run/proxy.sock"; net.Dial("unix", sock) }`),
		src(`"net"`, `func g() { var sock string; sock = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"`, `func g() (sock string) { sock = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", sock); return }`),
		src(`"net"`, `func g(sock string) { sock = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"`, `type cfg struct{ s string }; func g(c cfg) { c.s = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", c.s) }`),
		src(`"net"`, `func g(sock string) { for sock = range map[string]int{"/run/proxy.sock": 0} {}; (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"`, `func g(sock string) { p := &sock; *p = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"`, `func g(n int) { n++; (&net.Dialer{}).Dial("unix", n) }`),
		src(`"net"; "path/filepath"`, `func g(dir string) { sock := filepath.Join(dir, "s.sock"); (&net.Dialer{}).Dial("unix", sock) }`),
		// A field written through another name, and a func literal's
		// parameter given a literal (#6030 B1, Lens R1).
		src(`"net"`, `type client struct{ path string }; func (c *client) setup() { c.path = "/run/proxy.sock" }; func (c *client) dial() { (&net.Dialer{}).Dial("unix", c.path) }`),
		src(`"net"`, `type cfg struct{ s string }; func g(c *cfg) { d := c; d.s = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", c.s) }`),
		src(`"net"`, `type cfg struct{ s string }; func (x *cfg) set() { x.s = "/run/proxy.sock" }; func g(c cfg) { c.set(); (&net.Dialer{}).Dial("unix", c.s) }`),
		src(`"net"`, `type cfg struct{ s string }; func (x *cfg) set() { *x = cfg{"/run/proxy.sock"} }; func g(c *cfg) { c.set(); (&net.Dialer{}).Dial("unix", c.s) }`),
		src(`"net"`, `type cfg struct{ s string }; func h(c *cfg) { (&net.Dialer{}).Dial("unix", c.s) }; func g(l []cfg) { l[0] = cfg{"/run/proxy.sock"}; h(&l[0]) }`),
		src(`"net"`, `type cfg struct{ s string }; func g(c *cfg) { p := &c.s; *p = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", c.s) }`),
		src(`"net"`, `type in struct{ s string }; type cfg struct{ in in }; func g(c *cfg) { c.in = in{"/run/proxy.sock"}; (&net.Dialer{}).Dial("unix", c.in.s) }`),
		src(`"net"`, `func g() { func(s string) { (&net.Dialer{}).Dial("unix", s) }("/run/proxy.sock") }`),
		// The field's struct built or written in the package, whatever the
		// route (#6030 B1, second round).
		src(`"net"`, `type in struct{ s string }; type cfg struct{ in }; func (x *cfg) set() { x.in = in{"/run/proxy.sock"} }; func g(c *cfg) { c.set(); (&net.Dialer{}).Dial("unix", c.s) }`),
		src(`"net"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g(l []cfg) { l[0] = cfg{"/run/proxy.sock"}; l[0].dial() }`),
		src(`"net"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g(a *[1]cfg) { a[0] = cfg{s: "/run/proxy.sock"}; a[0].dial() }`),
		src(`"net"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g(l []cfg) { copy(l, []cfg{{"/run/proxy.sock"}}); l[0].dial() }`),
		src(`"net"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g(l []cfg) { l = append(l[:0], cfg{"/run/proxy.sock"}); l[0].dial() }`),
		src(`"net"`, `type cfg struct{ s string }; type list []cfg; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g() { l := list{{"/run/proxy.sock"}}; l[0].dial() }`),
		src(`"net"`, `type cfg struct{ s string }; type alias = cfg; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g() { (&alias{"/run/proxy.sock"}).dial() }`),
		src(`"net"`, `type cfg struct{ s string }; type u struct{ s string }; func g(c *cfg) { *(*u)(c) = u{"/run/proxy.sock"}; (&net.Dialer{}).Dial("unix", c.s) }`),
		src(`"net"`, `type cfg struct{ s string }; type u struct{ s string }; func (c cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g() { cfg(u{"/run/proxy.sock"}).dial() }`),
		src(`"net"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g(c *cfg) { c.s += "/../proxy.sock"; c.dial() }`),
		src(`"net"; "fmt"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g(c *cfg) { fmt.Sscan("/run/proxy.sock", &c.s); c.dial() }`),
		src(`"net"`, `type in struct{ s string }; type cfg struct{ in }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g() { (&cfg{in{"/run/proxy.sock"}}).dial() }`),
		src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); dir = "/run"; sock := filepath.Join(dir, "proxy.sock"); (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); sock := filepath.Join(dir, "s.sock"); sock = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); sock := filepath.Join(dir, "..", "proxy.sock"); (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); sock := filepath.Join(dir, "../../run/proxy.sock"); (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); sock := filepath.Join(dir, ".."); (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"; "os"; "path/filepath"`, `func g(s string) { dir, _ := os.MkdirTemp("", "x"); sock := filepath.Join(dir, s); (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); sock := filepath.Join(dir, "s.sock"); p := &sock; *p = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", sock) }`),
		src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); _, sock := filepath.Split(dir); (&net.Dialer{}).Dial("unix", sock) }`),
		// A field counts only when configuredFields lists its parameter's
		// type and its name for the package, and it is read through a
		// parameter or receiver nothing here writes (#6030 re-plan).
		src(`"net"`, `type client struct{ path string }; func (c *client) dial() { (&net.Dialer{}).Dial("unix", c.path) }`),
		src(`"net"`, `type Config struct{ Socket, Alt string }; func g(c Config) { (&net.Dialer{}).Dial("unix", c.Alt) }`),
		src(`"net"`, `type Conn struct{ Socket string }; func g(c Conn) { (&net.Dialer{}).Dial("unix", c.Socket) }`),
		src(`"net"`, `type Config struct{ In struct{ Socket string } }; func g(c Config) { (&net.Dialer{}).Dial("unix", c.In.Socket) }`),
		src(`"net"`, `type Config struct{ Socket string }; func g() { c := Config{Socket: "/run/proxy.sock"}; (&net.Dialer{}).Dial("unix", c.Socket) }`),
		src(`"net"`, `type Config struct{ Socket string }; func g() { var c Config = struct{ Socket string }{"/run/proxy.sock"}; (&net.Dialer{}).Dial("unix", c.Socket) }`),
		src(`"net"`, `type Config struct{ Socket string }; var c = Config{"/run/proxy.sock"}; func g() { (&net.Dialer{}).Dial("unix", c.Socket) }`),
		src(`"net"`, `type Config struct{ Socket string }; func g() (c Config) { (&net.Dialer{}).Dial("unix", c.Socket); return }`),
		src(`"net"`, `type Config struct{ Socket string }; func g() { func(c Config) { (&net.Dialer{}).Dial("unix", c.Socket) }(Config{"/run/proxy.sock"}) }`),
		src(`"net"`, `type Config struct{ Socket string }; func g(c Config) { c.Socket = "/run/proxy.sock"; (&net.Dialer{}).Dial("unix", c.Socket) }`),
		src(`"net"`, `type Config struct{ Socket string }; func g(c *Config) { *c = struct{ Socket string }{"/run/proxy.sock"}; (&net.Dialer{}).Dial("unix", c.Socket) }`),
		src(`"net"`, `type Config struct{ Socket string }; func set(p **Config) {}; func g(c *Config) { set(&c); (&net.Dialer{}).Dial("unix", c.Socket) }`),
		// A string parameter counts only as itself, by value.
		src(`"net"`, `type path string; func g(s path) { (&net.Dialer{}).Dial("unix", s) }`),
		src(`"net"`, `func g(s *string) { (&net.Dialer{}).Dial("unix", *s) }`),
		src(`"net"`, `func g(s ...string) { (&net.Dialer{}).Dial("unix", s[0]) }`),
		src(`"net"`, `func g(s [1]string) { (&net.Dialer{}).Dial("unix", s[0]) }`),
		// A D built without naming D, which round 3 got past a rule over
		// syntax (#6030 S1).
		src(`"net"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func g(p *cfg) { *p = struct{ s string }{"/run/proxy.sock"}; p.dial() }`),
		src(`"net"`, `type cfg struct{ s string }; func (c cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func mk() cfg { return struct{ s string }{"/run/proxy.sock"} }; func g() { mk().dial() }`),
		src(`"net"`, `type cfg struct{ s string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.s) }; func set[T ~struct{ s string }](p *T) { *p = T{"/run/proxy.sock"} }; func g(c *cfg) { set(c); c.dial() }`),
		src(`"net"`, `type cfg struct{ s string }; func use(c cfg) { (&net.Dialer{}).Dial("unix", c.s) }; func g() { use(struct{ s string }{"/run/proxy.sock"}) }`),
		src(`"net"`, `type cfg struct{ s string }; type x = struct{ s string }; func use(c cfg) { (&net.Dialer{}).Dial("unix", c.s) }; func g() { use(x{"/run/proxy.sock"}) }`),
		src(`"net"; "reflect"`, `type cfg struct{ S string }; func (c *cfg) dial() { (&net.Dialer{}).Dial("unix", c.S) }; func g(c *cfg) { reflect.ValueOf(c).Elem().Field(0).SetString("/run/proxy.sock"); c.dial() }`),
	} {
		path := filepath.Join(t.TempDir(), "p.go")
		if err := os.WriteFile(path, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(sourceUse(t, path, "p.go", "modelroute"), "\n"); !strings.Contains(got, "not taken from configuration") {
			t.Errorf("an unconfigured address passed: %q\n%s", got, c)
		}
	}
	// What a dialing function's callers pass, what a listed package stores
	// into a configuredFields field, and links or renames that could swap
	// the socket under a configured path, are package-wide (#6028). Each
	// case is one package of modelroute (Config.Socket listed), or of the
	// named package.
	dial := `func h(s string) { (&net.Dialer{}).Dial("unix", s) }; `
	cfgDial := `type Config struct{ Socket string }; func (c *Config) dial() { (&net.Dialer{}).Dial("unix", c.Socket) }; `
	for _, c := range []struct {
		rel, want string
		srcs      []string
	}{
		// A literal passed to a dialing function's parameter, directly,
		// through another dialing function, or from another file.
		{"modelroute", "passes h an address not taken from configuration", []string{src(`"net"`, dial+`func g() { h("/run/proxy.sock") }`)}},
		{"modelroute", "passes k an address not taken from configuration", []string{src(`"net"`, dial+`func k(s string) { h(s) }; func g() { k("/run/proxy.sock") }`)}},
		{"modelroute", "passes h an address not taken from configuration", []string{src(`"net"`, dial), src(``, `func g() { h("/run/proxy.sock") }`)}},
		{"modelroute", "passes h an address not taken from configuration", []string{src(`"net"`, dial+`func g() { s := "/run/proxy.sock"; h(s) }`)}},
		{"modelroute", "passes d an address not taken from configuration", []string{src(`"net"`, `type c struct{}; func (c) d(s string) { (&net.Dialer{}).Dial("unix", s) }; func g(x c) { x.d("/run/proxy.sock") }`)}},
		{"modelroute", "passes d an address not taken from configuration", []string{src(`"net"`, `type c struct{}; func (c) d(s string) { (&net.Dialer{}).Dial("unix", s) }; type i interface{ d(string) }; func g(x i) { x.d("/run/proxy.sock") }`)}},
		{"modelroute", "passes h an address not taken from configuration", []string{src(`"net"`, `func h(n int, s string) { (&net.Dialer{}).Dial("unix", s) }; func g() { h(0, "/run/proxy.sock") }`)}},
		// A dialing function taken as a value, or called so that the lint
		// cannot match its arguments.
		{"modelroute", "h, a dialing function, used as a value", []string{src(`"net"`, dial+`var f = h; func g() { f("/run/proxy.sock") }`)}},
		{"modelroute", "d, a dialing function, used as a value", []string{src(`"net"`, `type c struct{}; func (c) d(s string) { (&net.Dialer{}).Dial("unix", s) }; func g(x c) { f := x.d; f("/run/proxy.sock") }`)}},
		{"modelroute", "d, a dialing function, called as a method expression", []string{src(`"net"`, `type c struct{}; func (c) d(s string) { (&net.Dialer{}).Dial("unix", s) }; func g() { c.d(c{}, "/run/proxy.sock") }`)}},
		{"modelroute", "h, a dialing function, with arguments the lint cannot check", []string{src(`"net"`, `func h(n int, s string) { (&net.Dialer{}).Dial("unix", s) }; func t() (int, string) { return 0, "/run/proxy.sock" }; func g() { h(t()) }`)}},
		// A literal stored in the listed field it dials: by key, by
		// position, through a method, a method value, another struct of
		// the same shape, an elided literal or a type parameter (Lens R1,
		// Security 5 on #6035).
		{"modelroute", "sets Socket, a configuredFields field, here", []string{src(`"net"`, cfgDial+`func g() { (&Config{Socket: "/run/proxy.sock"}).dial() }`)}},
		{"modelroute", "sets a configuredFields field by position here", []string{src(`"net"`, cfgDial+`func g() { (&Config{"/run/proxy.sock"}).dial() }`)}},
		{"modelroute", "stores into Socket, a configuredFields field", []string{src(`"net"`, cfgDial+`func (c *Config) fix() { c.Socket = "/run/proxy.sock" }; func g(c *Config) { c.fix(); c.dial() }`)}},
		{"modelroute", "stores into Socket, a configuredFields field", []string{src(`"net"`, cfgDial+`func (c *Config) fix() { c.Socket = "/run/proxy.sock" }; func g(c *Config) { f := c.fix; f(); c.dial() }`)}},
		{"modelroute", "stores into Socket, a configuredFields field", []string{src(`"net"; "fmt"`, cfgDial+`func g(c *Config) { fmt.Sscan("/run/proxy.sock", &c.Socket); c.dial() }`)}},
		{"modelroute", "sets a configuredFields field by position here", []string{src(`"net"`, cfgDial+`func g(c *Config) { *c = struct{ Socket string }{"/run/proxy.sock"}; c.dial() }`)}},
		{"modelroute", "sets a configuredFields field by position here", []string{src(`"net"`, cfgDial+`type u struct{ Socket string }; func g(c *Config) { *c = Config(u{"/run/proxy.sock"}); c.dial() }`)}},
		{"modelroute", "sets a configuredFields field by position here", []string{src(`"net"`, cfgDial+`func g() { l := []Config{{"/run/proxy.sock"}}; l[0].dial() }`)}},
		{"modelroute", "sets a configuredFields field by position here", []string{src(`"net"`, cfgDial+`type list map[string]*Config; func g() { l := list{"a": {"/run/proxy.sock"}}; l["a"].dial() }`)}},
		{"modelroute", "sets a configuredFields field by position here", []string{src(`"net"`, cfgDial+`func set[T ~struct{ Socket string }](p *T) { *p = T{"/run/proxy.sock"} }; func g(c *Config) { set(c); c.dial() }`)}},
		{"modelroute", "sets Socket, a configuredFields field, here", []string{src(`"net"`, cfgDial), src(``, `func g() { (&Config{Socket: "/run/proxy.sock"}).dial() }`)}},
		// A decoder or reflect filling the listed field: a pointer to a
		// type that holds it handed to a call, however the value was made
		// (Lens on #6030), or a generic instantiated with such a type.
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "reflect"`, cfgDial+`func g(c *Config) { reflect.ValueOf(c).Elem().Field(0).SetString("/run/proxy.sock"); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(c *Config) { json.Unmarshal([]byte(`+"`"+`{"Socket":"/run/proxy.sock"}`+"`"+`), c); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(b []byte) { var d Config; json.Unmarshal(b, &d); d.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(b []byte) { d := new(Config); json.Unmarshal(b, d); d.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type outer struct{ In []Config }; func g(b []byte) { var o outer; json.Unmarshal(b, &o); o.In[0].dial() }`)}},
		{"modelroute", "instantiates dec with Config", []string{src(`"net"; "encoding/json"`, cfgDial+`func dec[T any](b []byte) (t T) { json.Unmarshal(b, &t); return }; func g(b []byte) { c := dec[Config](b); c.dial() }`)}},
		// A link or rename that could put another socket at the dialed
		// path or its directory, in a package that dials, called or taken
		// as a value (Security 4 on #6035).
		{"modelroute", "links or renames (os.Symlink)", []string{src(`"net"; "os"; "path/filepath"`, `func g() { dir, _ := os.MkdirTemp("", "x"); os.Symlink("/run/proxy.sock", filepath.Join(dir, "s.sock")); sock := filepath.Join(dir, "s.sock"); (&net.Dialer{}).Dial("unix", sock) }`)}},
		{"modelroute", "links or renames (os.Link)", []string{src(`"net"; "os"`, dial+`func g(s string) { os.Link("/run/proxy.sock", s) }`)}},
		{"modelroute", "links or renames (os.Rename)", []string{src(`"net"`, dial), src(`"os"`, `func g(s string) { os.Rename("/run/proxy.sock", s) }`)}},
		{"modelroute", "links or renames (syscall.Symlink)", []string{src(`"net"; "syscall"`, dial+`func g(s string) { syscall.Symlink("/run/proxy.sock", s) }`)}},
		{"modelroute", "links or renames (golang.org/x/sys/unix.Renameat2)", []string{src(`"net"; "golang.org/x/sys/unix"`, dial+`func g(s string) { unix.Renameat2(0, "/run/proxy.sock", 0, s, 0) }`)}},
		{"modelroute", "links or renames (golang.org/x/sys/unix.Linkat)", []string{src(`"net"; "golang.org/x/sys/unix"`, dial+`func g(s string) { unix.Linkat(0, "/run/proxy.sock", 0, s, 0) }`)}},
		{"modelroute", "links or renames (os.Symlink)", []string{src(`"net"; "os"`, dial+`var link = os.Symlink`)}},
		{"kernel/proc", "links or renames (os.Rename)", []string{src(`"net"; "os"`, `type Conn struct{ Socket string }; func (c *Conn) dial() { net.Dial("unix", c.Socket); os.Rename("/run/proxy.sock", c.Socket) }`)}},
		{"kernel/proc", "links or renames (os.Symlink)", []string{src(`"net"`, `type Conn struct{ Socket string }; func (c *Conn) dial() { net.Dial("unix", c.Socket) }`), src(`"os"`, `func g(s string) { os.Symlink("/run/proxy.sock", s) }`)}},
		// A writer's target the lint cannot show holds no listed field,
		// however it is reached (B1 on #6119).
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func get() *Config { return nil }; func g(b []byte) { c := get(); json.Unmarshal(b, c); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ C Config }; func g(b []byte, w *W) { json.Unmarshal(b, &w.C); w.C.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(b []byte, l []Config) { json.Unmarshal(b, &l[0]); l[0].dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func get() *Config { return nil }; func g(b []byte) { json.Unmarshal(b, get()) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(b []byte, c *Config) { var v any = c; json.Unmarshal(b, v); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(b []byte, x interface{ Get() *Config }) { json.Unmarshal(b, x.Get()); x.Get().dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"; "io"`, cfgDial+`func g(r io.Reader, c *Config) { json.NewDecoder(r).Decode(c); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "fmt"`, cfgDial+`func g(c *Config) { fmt.Sscan("/run/proxy.sock", c); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func load(b []byte, out any) { json.Unmarshal(b, out) }; func g(b []byte, c *Config) { load(b, c); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(b []byte, c *Config) { load(b, c); c.dial() }`), src(`"encoding/json"`, `func load(b []byte, out any) { json.Unmarshal(b, out) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func load(b []byte, out any) { json.Unmarshal(b, out) }; var f = load; func g(b []byte, c *Config) { f(b, c) }`)}},
		{"modelroute", "instantiates act with Config", []string{src(`"net"; "encoding/json"`, cfgDial+`func act[A any](f func(a A)) func([]byte) { return func(b []byte) { var a A; json.Unmarshal(b, &a); f(a) } }; var h = act(func(c Config) { c.dial() })`)}},
		{"modelroute", "instantiates act with Config", []string{src(`"net"; "encoding/json"`, cfgDial+`func act[A any](f func(a A)) func([]byte) { return func(b []byte) { var a A; json.Unmarshal(b, &a); f(a) } }; var h = act[Config]`)}},
		{"modelroute", "does not type-check", []string{src(`"net"; "example.com/fill"`, cfgDial+`func g(c *Config) { fill.In(c); c.dial() }`)}},
		// A writer's target passes only as a fresh zero value of a type
		// holding no listed field, and a writer taken as a value is
		// reported (B1 round 2 on #6119).
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(b []byte, c *Config) { f := json.Unmarshal; f(b, c); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"; "io"`, cfgDial+`func g(r io.Reader, c *Config) { d := json.NewDecoder(r); f := d.Decode; f(c); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func get() int { return 0 }; func g(b []byte, c *Config) { get := func() any { return c }; json.Unmarshal(b, get()); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type resp struct{ N int }; func g(b []byte, c *Config) { resp := func() any { return c }; json.Unmarshal(b, resp()); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func g(b []byte, c *Config) { w := W{V: c}; json.Unmarshal(b, &w); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func g(b []byte, c *Config) { var w W; w.V = c; json.Unmarshal(b, &w); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func (w *W) set(v any) { w.V = v }; func g(b []byte, c *Config) { var w W; w.set(c); json.Unmarshal(b, &w); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func g(b []byte, c *Config) { var w W; for i := 0; i < 2; i++ { json.Unmarshal(b, &w); w.V = c }; c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`func g(b []byte) (c Config) { json.Unmarshal(b, &c); c.dial(); return }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`var c0 = new(Config); func load(b []byte, out any) { out = c0; json.Unmarshal(b, out) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; . "encoding/json"`, cfgDial+`func g(b []byte, c *Config) { Unmarshal(b, c); c.dial() }`)}},
		// The re-plan (#6028 after #6119): types, not order. A value whose
		// type reaches the listed field goes into an interface, another
		// package's code or a generic only by review, wherever and
		// whenever the store would run (Security B1 round 3 on #6119).
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func g(b []byte, c *Config) { var w W; dec := func() { json.Unmarshal(b, &w) }; dec(); w.V = c; dec(); c.dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; var gw W; func decode(b []byte) { json.Unmarshal(b, &gw) }; func setup(c *Config) { gw.V = c }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func g(b []byte, c *Config) { var w W; defer func() { json.Unmarshal(b, &w) }(); w.V = c }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func g(b []byte, c *Config, ch chan bool) { var w W; go func() { <-ch; json.Unmarshal(b, &w) }(); w.V = c; ch <- true }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "encoding/json"`, cfgDial+`type W struct{ V any }; func g(b []byte) (func(), func(v *Config)) { var w W; return func() { json.Unmarshal(b, &w) }, func(v *Config) { w.V = v } }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) any { return c }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) { var v any; v = any(c); _ = v }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(l []*Config) { var v any; for _, v = range l {}; _ = v }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config, m map[any]int) { m[c] = 1 }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config, ch chan any) { ch <- c }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) { _ = append([]any{}, c) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) { panic(c) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "fmt"`, cfgDial+`func g(c *Config) { fmt.Println(c) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "fmt"`, cfgDial+`func g(l []Config) { fmt.Println(l) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "slices"`, cfgDial+`func g(l []Config) { slices.Reverse(l) }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"; "reflect"`, cfgDial+`func g() { reflect.New(reflect.TypeFor[Config]()).Interface().(*Config).dial() }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`type I interface{ Get() *Config }; type h struct{ c *Config }; func (x h) Get() *Config { return x.c }; func g(c *Config) any { return h{c} }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) any { return func() *Config { return c } }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) { var v struct{ V any }; v.V = c; _ = v }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) { _ = []any{c}; _ = map[string]any{"a": c}; _ = struct{ V any }{c} }`)}},
		{"modelroute", "reaches a configuredFields field", []string{src(`"net"`, cfgDial+`type W struct{ V any }; func g(c *Config) { _ = []*W{{V: c}} }`)}},
		{"modelroute", "takes a *Config, which reaches a configuredFields field, out of an interface", []string{src(`"net"`, cfgDial+`func g(v any) { v.(*Config).dial() }`)}},
		{"modelroute", "takes a Config, which reaches a configuredFields field, out of an interface", []string{src(`"net"`, cfgDial+`func g(v any, c *Config) { switch x := v.(type) { case Config: *c = x }; c.dial() }`)}},
		{"modelroute", "stores into Socket, a configuredFields field", []string{src(`"net"`, cfgDial+`type u struct{ Socket string }; func g(c *Config) { (*u)(c).Socket = "/run/proxy.sock"; c.dial() }`)}},
		{"modelroute", "stores into Socket, a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config) { c.Socket += ".x"; c.dial() }`)}},
		{"modelroute", "stores into Socket, a configuredFields field", []string{src(`"net"`, cfgDial+`func g(c *Config, l []string) { for _, c.Socket = range l {}; c.dial() }`)}},
		{"modelroute", "sets a configuredFields field by position here", []string{src(`"net"`, cfgDial+`type E struct{ Config }; func g() { (&E{Config{"/run/proxy.sock"}}).dial() }`)}},
		// A copy hands over the type, from which a value can be minted
		// that dials (Security B1 on #6123).
		{"modelroute", "hands Config, which reaches a configuredFields field, to encoding/gob.Register", []string{src(`"net"; "encoding/gob"; "io"`, `type Config struct{ Socket string }; func (c Config) dial() { (&net.Dialer{}).Dial("unix", c.Socket) }; type dialer interface{ dial() }; func g(r io.Reader) { gob.Register(Config{}); var x any; gob.NewDecoder(r).Decode(&x); x.(dialer).dial() }`)}},
		{"modelroute", "takes a dialer, which reaches a configuredFields field, out of an interface", []string{src(`"net"; "encoding/gob"; "io"`, `type Config struct{ Socket string }; func (c Config) dial() { (&net.Dialer{}).Dial("unix", c.Socket) }; type dialer interface{ dial() }; func g(r io.Reader) { gob.Register(Config{}); var x any; gob.NewDecoder(r).Decode(&x); x.(dialer).dial() }`)}},
		{"modelroute", "hands Config, which reaches a configuredFields field, to reflect.TypeOf", []string{src(`"net"; "reflect"`, `type Config struct{ Socket string }; func (c Config) dial() { (&net.Dialer{}).Dial("unix", c.Socket) }; type dialer interface{ dial() }; func g() { v := reflect.New(reflect.TypeOf(Config{})).Elem(); v.Field(0).SetString("/e"); v.Interface().(dialer).dial() }`)}},
		{"modelroute", "hands Config, which reaches a configuredFields field, to dialer", []string{src(`"net"; "reflect"`, `type Config struct{ Socket string }; func (c Config) dial() { (&net.Dialer{}).Dial("unix", c.Socket) }; type dialer interface{ dial() }; func g(c Config) { s := []dialer{c}; n := reflect.New(reflect.TypeOf(c)).Elem(); n.Field(0).SetString("/e"); reflect.ValueOf(s).Index(0).Set(n); s[0].dial() }`)}},
		{"modelroute", "hands Config, which reaches a configuredFields field, to fmt.Sprint", []string{src(`"fmt"`, `type Config struct{ Socket string }; func g(c Config) string { return fmt.Sprint(c, c.Socket) }`)}},
		{"modelroute", "takes a dialer, which reaches a configuredFields field, out of an interface", []string{src(`"net"`, `type Config struct{ Socket string }; func (c Config) dial() { (&net.Dialer{}).Dial("unix", c.Socket) }; type dialer interface{ dial() }; func g(v any) { switch x := v.(type) { case dialer: x.dial() } }`)}},
		// An interface a holder implements holds too: its values hand out
		// their dynamic type, and a type parameter can take one out
		// (Security B1 round 2 on #6123).
		{"modelroute", "hands map[string]clerk, which reaches a configuredFields field, to reflect.ValueOf", []string{src(`"net"; "reflect"`, `type Config struct{ Socket string }; type clerk interface{ Do() }; func (c Config) Do() { (&net.Dialer{}).Dial("unix", c.Socket) }; func g(m map[string]clerk, k clerk) { v := reflect.New(reflect.TypeOf(k)).Elem(); v.Field(0).SetString("/e"); reflect.ValueOf(m).SetMapIndex(reflect.ValueOf("a"), v); m["a"].Do() }`)}},
		{"modelroute", "instantiates get with clerk", []string{src(`"net"; "reflect"`, `type Config struct{ Socket string }; type clerk interface{ Do() }; func (c Config) Do() { (&net.Dialer{}).Dial("unix", c.Socket) }; func get[T any](x any) T { return x.(T) }; func g(k clerk) { v := reflect.New(reflect.TypeOf(k)).Elem(); get[clerk](v.Interface()).Do() }`)}},
		{"modelroute", "hands io.Reader, which reaches a configuredFields field, to reflect.TypeOf", []string{src(`"net"; "reflect"; "io"`, cfgDial+`func g(r io.Reader) { type w struct{ Config; io.Reader }; _ = w{}; reflect.TypeOf(r) }`)}},
		// os.Root's methods, and opening one (B2 on #6119).
		{"modelroute", "links or renames (Symlink)", []string{src(`"net"; "os"`, dial+`func g(s string) { r, _ := os.OpenRoot("/tmp"); r.Symlink("/run/proxy.sock", s) }`)}},
		{"modelroute", "links or renames (Rename)", []string{src(`"net"; "os"`, dial+`func g(r *os.Root, s string) { r.Rename("/run/proxy.sock", s) }`)}},
		{"modelroute", "opens an os.Root (os.OpenRoot)", []string{src(`"net"; "os"`, dial+`func g() { os.OpenRoot("/tmp") }`)}},
		// kernel/proc's allowance is per file and per call (B3 on #6119).
		{"kernel/proc", "links or renames (os.Link)", []string{src(`"net"`, `type Conn struct{ Socket string }; func (c *Conn) dial() { net.Dial("unix", c.Socket) }`), src(`"os"`, `func g(a, b string) { os.Link(a, b) }`)}},
	} {
		if got := useOf(t, c.rel, c.srcs...); !strings.Contains(got, c.want) {
			t.Errorf("in %s, not reported: %s; got %q\n%s", c.rel, c.want, got, strings.Join(c.srcs, "\n"))
		}
	}
	// Callers that pass configuration, a dialing function's own string
	// parameter, and kernel/proc's reviewed link and rename outside the
	// files that dial, pass.
	for _, c := range []struct {
		rel  string
		srcs []string
	}{
		{"modelroute", []string{src(`"net"`, `type Config struct{ Socket string }; `+dial+`func k(s string) { h(s) }; func g(c Config) { h(c.Socket); k(c.Socket) }`)}},
		{"modelroute", []string{src(`"encoding/json"`, `type Config struct{ Socket string }; type resp struct{ N int }; func load(b []byte, out any) { json.Unmarshal(b, out) }; func g(b []byte) { var r resp; load(b, &r); var n struct{ N int }; json.Unmarshal(b, &n) }`)}},
		{"modelroute", []string{src(`"encoding/json"; "io"`, `type Config struct{ Socket string }; type W struct{ V any; N int }; func load(b []byte, out any) error { return json.Unmarshal(b, out) }; func g(b []byte) (w W, err error) { err = load(b, &w); return }; func h(r io.Reader) W { var st W; if json.NewDecoder(r).Decode(&st) != nil { return W{} }; st.N = 1; return st }; func k(b []byte) { load(b, nil); p := new(W); json.Unmarshal(b, p); _ = p.N }`)}},
		{"modelroute", []string{src(`"encoding/json"`, `type Config struct{ Socket string }; var dec = json.Unmarshal`)}},
		{"modelroute", []string{src(`"encoding/json"`, `type Config struct{ Socket string }; type W struct{ V any }; func g(b []byte) { w := new(W); keep(w); json.Unmarshal(b, w) }; func keep(*W) {}`)}},
		{"modelroute", []string{src(`"encoding/json"`, `type Config struct{ Socket string }; type S interface{ X() }; type W struct{ V S }; func g(b []byte, w *W) { json.Unmarshal(b, w) }`)}},
		{"modelroute", []string{src(`"encoding/json"`, `type Config struct{ Socket string }; func g(b []byte, ch chan any) { json.Unmarshal(b, <-ch) }`)}},
		{"modelroute", []string{src(`"encoding/json"`, `type Config struct{ Socket string }; type W struct{ V any }; func g(b []byte, c *Config) (*Config, W) { var w W; json.Unmarshal(b, &w); keep := *c; return &keep, w }`)}},
	} {
		if got := useOf(t, c.rel, c.srcs...); got != "" {
			t.Errorf("in %s, flagged: %q\n%s", c.rel, got, strings.Join(c.srcs, "\n"))
		}
	}
	// A reviewed handOK entry lets a function or an interface take a
	// holding value: fmt.Sprint and a Clerk-like interface here.
	handOK["modelroute"] = map[string]string{"fmt.Sprint": "test", module + "modelroute.clerk": "test"}
	got := useOf(t, "modelroute", src(`"fmt"`, `type Config struct{ Socket string }; type clerk interface{ Do() }; func (Config) Do() {}; func g(c Config) (string, clerk) { return fmt.Sprint(c, c.Socket), c }`))
	delete(handOK, "modelroute")
	if got != "" {
		t.Errorf("handOK entries not honoured: %q", got)
	}
	ok := src(`"net"; "net/http"; "net/http/httputil"; "os"; "path/filepath"`, `type Config struct{ Socket string }
func g(sock string, cfg Config) {
	_, _ = (&net.Dialer{}).Dial("unix", cfg.Socket)
	tr := &http.Transport{DialContext: func() { (&net.Dialer{}).DialContext(nil, "unix", sock) }}
	_ = &httputil.ReverseProxy{Transport: tr}
	_ = &http.Client{Transport: &http.Transport{DialContext: func() {}}}
	dir, _ := os.MkdirTemp("", "x")
	s := filepath.Join(dir, "s.sock")
	_ = &http.Client{Transport: &http.Transport{DialContext: func() { (&net.Dialer{}).DialContext(nil, "unix", s) }}}
}`)
	path := filepath.Join(t.TempDir(), "ok.go")
	if err := os.WriteFile(path, []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sourceUse(t, path, "ok.go", "modelroute"); len(got) != 0 {
		t.Errorf("modelroute's unix dial flagged: %q", got)
	}
	// kernel/proc's remote reads Socket through its embedded Remote, and
	// keeps a Remote whole (*p = old): a listed field. The same source in
	// a package without the entry is refused.
	held := src(`"net"`, `type Remote struct{ Socket string }
type remote struct{ Remote }
func (r Remote) clerk() remote { return remote{r} }
func (c remote) call() { net.Dial("unix", c.Socket) }
func keep(p *Remote, old Remote) { *p = old }`)
	path = filepath.Join(t.TempDir(), "held.go")
	if err := os.WriteFile(path, []byte(held), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sourceUse(t, path, "held.go", "kernel/proc"); len(got) != 0 {
		t.Errorf("a handed Remote's dial flagged: %q", got)
	}
	if got := strings.Join(sourceUse(t, path, "held.go", "modelroute"), "\n"); !strings.Contains(got, "not taken from configuration") {
		t.Errorf("a field listed for another package passed: %q", got)
	}
	// kernel/proc's reviewed link and rename stand in their own files.
	files := map[string]string{
		"conn.go":    src(`"net"`, `type Conn struct{ Socket string }; func (c *Conn) dial() { net.Dial("unix", c.Socket) }`),
		"backup.go":  src(`"os"`, `type backups struct{ link func(a, b string) error }; var bk = backups{link: os.Link}; func g(a, b string) { os.Link(a, b) }`),
		"restore.go": src(`"os"`, `func h(a, b string) { os.Rename(a, b) }`),
	}
	if got := useFiles(t, "kernel/proc", files); got != "" {
		t.Errorf("kernel/proc's reviewed link and rename flagged: %q", got)
	}
	files["backup.go"] = src(`"os"`, `func g(a, b string) { os.Symlink(a, b) }`)
	if got := useFiles(t, "kernel/proc", files); !strings.Contains(got, "links or renames (os.Symlink)") {
		t.Errorf("a symlink in backup.go passed: %q", got)
	}
	// Imports: RPC, mail, raw sockets, and escape hatches.
	reach := httpReach([]listed{{path: "net/rpc", imports: []string{"net/http"}}, {path: "net/http"}})
	if !reach["net/rpc"] || !socketPkgs["net/smtp"] || !socketPkgs["syscall"] || !socketPkgs["golang.org/x/sys/unix"] {
		t.Fatal("socket-capable imports not caught")
	}
	for _, e := range []string{"C", "unsafe", "plugin", "os/exec"} {
		if !escapes[e] {
			t.Fatalf("%s is not an escape", e)
		}
	}
}

// useOf writes srcs as the files of one package and returns what
// packageUse reports for it as package rel.
func useOf(t *testing.T, rel string, srcs ...string) string {
	t.Helper()
	files := map[string]string{}
	for i, s := range srcs {
		files[fmt.Sprintf("p%d.go", i)] = s
	}
	return useFiles(t, rel, files)
}

// useFiles is useOf with the files named.
func useFiles(t *testing.T, rel string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var names []string
	for name, s := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(packageUse(t, dir, names, "p", rel), "\n")
}

// REQ: LOOP-7, LOOP-9
//
// P3-4b-3a: the probe runner starts children through childproc since
// P3-4b-3r-env-r8, which holds the reviewed os/exec entry (LOOP-7's fuzz
// runner, loop7, did too until #2787 deleted it); the runner has no
// entry of its own, and no other package of the
// graph gains one (vm/gvisor and clock keep theirs until
// P3-4b-3r-env-r8b).
func TestEscapeOKNamesTheLoopRunners(t *testing.T) {
	for _, p := range []string{"probecmd"} {
		if escapeOK[p]["os/exec"] != "" {
			t.Errorf("%s has its own os/exec entry; it starts children through childproc", p)
		}
	}
	if escapeOK["childproc"]["os/exec"] == "" {
		t.Error("childproc has no reviewed os/exec entry")
	}
	runners := map[string]bool{"vm/gvisor": true, "clock": true, "childproc": true}
	for p, es := range escapeOK {
		if es["os/exec"] != "" && !runners[p] {
			t.Errorf("%s has an os/exec entry no review named", p)
		}
	}
}

// envExempt are the functions in non-test broker code that start a child
// without an explicit environment, so it inherits the process's, and why
// each may. None remain: the last two, the test fixtures swtpm and
// quotatest, start through childproc since P3-4b-3r-env-r8b;
// TestEnvExemptionsAreTestFixturesOnly pins that no binary links one.
var envExempt = map[string]string{}

// vendorEnvExempt are the same in vendored third-party code, each with the
// decision that took it. TestVendorEnvExemptionsStayOutOfAgentosd pins
// that agentosd links none of them, and the walk drops an exemption no
// longer needed, as for envExempt.
var vendorEnvExempt = map[string]string{}

// launcherPkgs are the packages whose calls start a child or read the
// process's environment, with their default names.
var launcherPkgs = map[string]string{"os/exec": "exec", "os": "os", "syscall": "syscall", "golang.org/x/sys/unix": "unix", module + "childproc": "childproc"}

// childEnvCheck reads one Go source and returns the functions that start
// a child without an explicit environment (noEnv) and those that put the
// process's own environment into one (inherits). Imports count under any
// name, dot imports included. Every file is read, whatever it imports, so
// the Env-value rules below hold everywhere (P3-4b-3r-env-r8). Since
// P3-4b-3r-env-r8 this check is defence in depth: the boundary is
// childproc, which checks a child's environment at its start, and the
// gate that keeps every other package from starting one. Each function declaration, with the func literals inside it,
// is checked as one unit, and so is each package-level var or type spec;
// a flagged unit is named by its function, or by "var" or "type" and its
// names.
//
// Procedural, held by review (reviews/security/README.md, the row on a child inheriting the daemon's environment):
//   - an Env value the check cannot classify: a parameter, another
//     struct's field, a map lookup, a declaration in another file, a
//     multi-value call;
//   - order and flow: an Env set after the child starts, or only on some
//     paths (under a condition), counts as set;
//   - a nil Env the check does not trace: from a method, a func literal,
//     a slice or append of a nil value, or a conversion to a type of
//     another file; a slice declared nil and appended to only on some
//     paths; a nil Env set on a value not held as a command (a copy, a
//     parameter, a promoted field); and a command copied by dereference
//     (d := *c);
//   - a command constructed by a generic with an inferred type argument
//     (var z T or new(T) where T is inferred as *exec.Cmd), including one
//     inferred from its context (var mk func() *exec.Cmd = fresh);
//   - a *exec.Cmd held where the check does not look for a constructor:
//     a parameter, a function result, a type assertion (the deny-by-
//     default rule covers exec.Cmd by value; P3-4b-3r-env-r8);
//   - a command whose Env is set in another function (except for a
//     package-level declaration), or reached through a pointer the check
//     does not follow;
//   - an Environ helper behind a func value, an interface, another
//     package, or more than three calls, and Environ itself used as a
//     func value;
//   - deliberate evasion: reflection, unsafe, raw syscalls (SYS_EXECVE),
//     and an environment read from /proc/self/environ.
//
// Children and their environment, per command (P3-4b-3r-env-r1, #621):
//   - A command is an exec.Command or exec.CommandContext call, an exec.Cmd
//     literal without Env, new(exec.Cmd), or a var declared as exec.Cmd.
//     exec.Cmd as a type anywhere else (an alias or defined type, a struct
//     field, an element of a slice, array or map, a parameter) is flagged.
//     Deny by default (exec.Cmd by value, and either form inside a
//     container): exec.Cmd or *exec.Cmd anywhere inside a slice,
//     array, map (key or value) or channel type, a generic's type
//     argument or a type-parameter constraint, at any depth, or as the
//     definition of a named type or alias, is flagged as a holder the
//     check cannot follow; so is an Env reached through its address
//     (&c.Env). A ProcAttr passed to os.StartProcess, syscall.ForkExec or
//     syscall.StartProcess may not be nil, needs an Env key when it is a
//     literal, and otherwise counts as a command held in that variable.
//     The syscall launchers read a nil Env as empty, not inherited; they
//     are held to the same rule for uniformity.
//   - A command needs an Env set on the variable that holds it, after the
//     command is stored there and before the variable is stored to again:
//     a .Env assignment to the same identifier or selector chain (resolved
//     to its declaration, so a same-named variable in another scope does
//     not count), or a literal with an Env key stored with it. A command
//     stored by a package-level declaration may have its Env set anywhere
//     in the file; one stored later must have its own. An Env set
//     on any other value, a copy of the command included, does not count.
//     A command held in no variable (a call chained on the constructor, a
//     return, an argument) is flagged, as is any reference to a launcher
//     that is not a call (exec.Command as a function value), since the
//     call it makes cannot be followed. A parenthesised launcher,
//     (exec.Command)("x"), is the same call.
//   - An Env that is nil at run time counts as none and fails its command:
//     a literal nil; a nil converted to a slice type or a type of this
//     file ([]string(nil), E(nil)); a local var
//     declared without a value, or with a nil one, and not assigned (or
//     its address taken) before the Env takes it; a package-level var of
//     this file declared so and assigned nowhere in the file; a call to a
//     package function whose every return is one of those, or a bare
//     return of a named result it never assigns.
//   - Such a nil Env is flagged whatever holds it, a command or not: an
//     .Env assignment or an Env key of any literal (P3-4b-3r-env-r8, D4).
//
// inherits is a reference to any selector named Environ (os.Environ,
// syscall.Environ, unix.Environ, (*exec.Cmd).Environ) anywhere inside an
// Env value (a .Env assignment or an Env key of any literal) or Exec's
// environment argument, or anywhere in a unit that starts a child, which
// catches one passed through a local variable; or, in the same places, a
// call to a package function or method (by name, in any file of the
// package) whose return expression, or a local variable it returns, holds
// one, followed three calls deep; a package-level var is followed into
// its initializer and every assignment to it in its file. syscall.Exec and unix.Exec count as
// starting a child. An argument to childproc.NewEnv counts as an Env value
// (P3-4b-3r-env-r8). It has no exemption.
func childEnvCheck(t *testing.T, path string) (noEnv, inherits []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if name, ok := launcherPkgs[p]; ok {
			if im.Name != nil {
				name = im.Name.Name
			}
			names[p] = name
		}
	}
	// No early return for a file without a launcher import: the Env-value
	// rules (a nil Env on any receiver, an Environ in an Env) hold in
	// every file (P3-4b-3r-env-r8, brief D4).
	is := func(e ast.Expr, pkg string, sels ...string) bool {
		name := names[pkg]
		sel := ""
		// Unparen: (exec.Command)("x") is the same call (#621 delta
		// Security 4a point 1).
		switch e := ast.Unparen(e).(type) {
		case *ast.SelectorExpr:
			if id, ok := e.X.(*ast.Ident); !ok || name == "" || id.Name != name {
				return false
			}
			sel = e.Sel.Name
		case *ast.Ident:
			if name != "." {
				return false
			}
			sel = e.Name
		default:
			return false
		}
		for _, s := range sels {
			if sel == s {
				return true
			}
		}
		return false
	}
	command := func(e ast.Expr) bool { return is(e, "os/exec", "Command", "CommandContext") }
	attrLauncher := func(e ast.Expr) bool {
		return is(e, "os", "StartProcess") || is(e, "syscall", "ForkExec", "StartProcess")
	}
	execLauncher := func(e ast.Expr) bool { return is(e, "syscall", "Exec") || is(e, "golang.org/x/sys/unix", "Exec") }
	environ := func(e ast.Node) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			// Any selector named Environ: os.Environ and its kin, and
			// (*exec.Cmd).Environ, which returns the process's
			// environment while Env is nil (L3 on #587).
			if se, ok := n.(*ast.SelectorExpr); ok && se.Sel.Name == "Environ" {
				found = true
			}
			if x, ok := n.(ast.Expr); ok && (is(x, "os", "Environ") || is(x, "syscall", "Environ") || is(x, "golang.org/x/sys/unix", "Environ")) {
				found = true
			}
			return !found
		})
		return found
	}
	strip := func(e ast.Expr) ast.Expr {
		e = ast.Unparen(e)
		if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
			e = ast.Unparen(u.X)
		}
		return e
	}
	// isNil: a literal nil, bare or converted ([]string(nil)), which
	// exec.Cmd and os.StartProcess read as "inherit" (L3 on #587).
	isNil := func(e ast.Expr) bool {
		e = ast.Unparen(e)
		if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
			// A conversion: to a slice type, or to a type of this file
			// (E(nil); #621 delta Security 4a point 3).
			switch fn := ast.Unparen(c.Fun).(type) {
			case *ast.ArrayType:
				e = ast.Unparen(c.Args[0])
			case *ast.Ident:
				if fn.Obj != nil && fn.Obj.Kind == ast.Typ {
					e = ast.Unparen(c.Args[0])
				}
			}
		}
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "nil"
	}
	// key names the variable that holds a command or ProcAttr: the root
	// identifier's declaration and the selector chain under it, or "" if
	// it is held in none.
	key := func(e ast.Expr) string {
		e = strip(e)
		if s, ok := e.(*ast.StarExpr); ok {
			e = ast.Unparen(s.X)
		}
		chain := ""
		for {
			switch x := e.(type) {
			case *ast.SelectorExpr:
				chain, e = "."+x.Sel.Name+chain, ast.Unparen(x.X)
				continue
			case *ast.Ident:
				if x.Name == "_" || x.Name == "nil" {
					return ""
				}
				if x.Obj != nil {
					return fmt.Sprintf("%p", x.Obj) + chain
				}
				return x.Name + chain
			}
			return ""
		}
	}
	// helpers are the package's functions (by name) and methods (by
	// "."+name) that a call may reach, read from every file of the
	// package once a call needs them.
	var pkg *pkgDecls
	helpers := func(c *ast.CallExpr) []*ast.FuncDecl {
		var name string
		switch fn := ast.Unparen(c.Fun).(type) {
		case *ast.Ident:
			if fn.Obj != nil && fn.Obj.Kind != ast.Fun {
				return nil
			}
			name = fn.Name
		case *ast.SelectorExpr:
			if id, ok := fn.X.(*ast.Ident); ok && id.Obj == nil {
				return nil // another package's function
			}
			name = "." + fn.Sel.Name
		default:
			return nil
		}
		if pkg == nil {
			pkg = packageFuncs(t, filepath.Dir(path))
		}
		return pkg.funcs[name]
	}
	returns := func(d *ast.FuncDecl) (rs []*ast.ReturnStmt) {
		ast.Inspect(d.Body, func(n ast.Node) bool {
			if r, ok := n.(*ast.ReturnStmt); ok {
				rs = append(rs, r)
			}
			_, lit := n.(*ast.FuncLit)
			return !lit
		})
		return rs
	}
	// holds: e references Environ, or calls a helper whose return does,
	// depth calls deep (P3-4b-3r-env-r1 requirement 4).
	fileVars := varSources(f)
	var holds func(e ast.Node, depth int) bool
	holds = func(e ast.Node, depth int) bool {
		if environ(e) {
			return true
		}
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			if found || depth == 0 {
				return false
			}
			// A package-level var: its initializer and every assignment
			// to it in its file (#621 L3 point 1).
			if id, ok := n.(*ast.Ident); ok && id.Obj != nil && id.Obj.Kind == ast.Var {
				srcs := fileVars[id.Obj]
				if srcs == nil && pkg != nil {
					srcs = pkg.vars[id.Obj]
				}
				for _, x := range srcs {
					found = found || holds(x, depth-1)
				}
			}
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return !found
			}
			for _, d := range helpers(c) {
				if found || d.Body == nil {
					continue
				}
				objs := map[*ast.Object]bool{}
				for _, r := range returns(d) {
					for _, x := range r.Results {
						found = found || holds(x, depth-1)
						ast.Inspect(x, func(n ast.Node) bool {
							if id, ok := n.(*ast.Ident); ok && id.Obj != nil && id.Obj.Kind == ast.Var {
								objs[id.Obj] = true
							}
							return true
						})
					}
				}
				// A local the helper returns, assigned from one.
				ast.Inspect(d.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.AssignStmt:
						for i, l := range n.Lhs {
							if id, ok := ast.Unparen(l).(*ast.Ident); ok && objs[id.Obj] {
								r := n.Rhs[0]
								if len(n.Rhs) == len(n.Lhs) {
									r = n.Rhs[i]
								}
								found = found || holds(r, depth-1)
							}
						}
					case *ast.ValueSpec:
						for i, id := range n.Names {
							if objs[id.Obj] && i < len(n.Values) {
								found = found || holds(n.Values[i], depth-1)
							}
						}
					}
					return !found
				})
			}
			return !found
		})
		return found
	}
	top := map[*ast.ValueSpec]bool{}
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok {
			for _, s := range g.Specs {
				if vs, ok := s.(*ast.ValueSpec); ok {
					top[vs] = true
				}
			}
		}
	}
	// assignments: where each variable under n is assigned or has its
	// address taken.
	assignments := func(n ast.Node) map[*ast.Object][]token.Pos {
		m := map[*ast.Object][]token.Pos{}
		mark := func(e ast.Expr, at token.Pos) {
			if id, ok := ast.Unparen(e).(*ast.Ident); ok && id.Obj != nil {
				m[id.Obj] = append(m[id.Obj], at)
			}
		}
		ast.Inspect(n, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, l := range n.Lhs {
					mark(l, n.Pos())
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					mark(n.X, n.Pos())
				}
			case *ast.RangeStmt:
				for _, x := range []ast.Expr{n.Key, n.Value} {
					if x != nil {
						mark(x, n.Pos())
					}
				}
			}
			return true
		})
		return m
	}
	assigned := assignments(f)
	// bind maps a value to the variable it is stored in and where;
	// bindAt holds every position a variable is stored to. A package-level
	// declaration's order in the file says nothing about when its Env is
	// set.
	type binding struct {
		key string
		at  token.Pos
		top bool // a package-level var's declaration
	}
	bind, bindAt := map[ast.Expr]binding{}, map[string][]token.Pos{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				k := key(l)
				if k != "" {
					bindAt[k] = append(bindAt[k], n.Pos())
				}
				if len(n.Rhs) == len(n.Lhs) {
					bind[strip(n.Rhs[i])] = binding{k, n.Pos(), false}
				}
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				k := key(id)
				if k == "" {
					continue
				}
				bindAt[k] = append(bindAt[k], n.Pos())
				if i < len(n.Values) {
					bind[strip(n.Values[i])] = binding{k, n.Pos(), top[n]}
				}
			}
		}
		return true
	})
	// nilVar: e names a variable declared nil (with no value, nil, or a
	// typed nil) inside a node in accepts, and not assigned since, before
	// at; one declared at package level must be assigned nowhere.
	nilVar := func(e ast.Expr, at token.Pos, assigned map[*ast.Object][]token.Pos, in func(ast.Node) bool) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		if !ok || id.Obj == nil || id.Obj.Kind != ast.Var {
			return false
		}
		var decl ast.Node
		pkgLevel := false
		switch d := id.Obj.Decl.(type) {
		case *ast.ValueSpec:
			for i, n := range d.Names {
				if n.Name == id.Name && (len(d.Values) == 0 || len(d.Values) == len(d.Names) && isNil(d.Values[i])) {
					decl, pkgLevel = d, top[d]
				}
			}
		case *ast.AssignStmt:
			if d.Tok == token.DEFINE && len(d.Lhs) == len(d.Rhs) {
				for i, l := range d.Lhs {
					if lid, ok := l.(*ast.Ident); ok && lid.Name == id.Name && isNil(d.Rhs[i]) {
						decl = d
					}
				}
			}
		}
		if decl == nil || !in(decl) {
			return false
		}
		for _, p := range assigned[id.Obj] {
			if p != decl.Pos() && (pkgLevel || p < at) {
				return false
			}
		}
		return true
	}
	anywhere := func(ast.Node) bool { return true }
	// nilAt: an Env value that is nil when it is taken at pos at
	// (P3-4b-3r-env-r1 requirement 5; #621 Security 4a point 2).
	nilAt := func(e ast.Expr, at token.Pos) bool {
		if isNil(e) || nilVar(e, at, assigned, anywhere) {
			return true
		}
		x, ok := ast.Unparen(e).(*ast.CallExpr)
		if !ok {
			return false
		}
		if _, ok := ast.Unparen(x.Fun).(*ast.Ident); !ok {
			return false
		}
		// A package function whose every return is nil, or a nil local
		// of its own.
		ds := helpers(x)
		for _, d := range ds {
			rs := returns(d)
			if d.Body == nil || len(rs) == 0 {
				return false
			}
			local := assignments(d.Body)
			in := func(n ast.Node) bool { return n.Pos() > d.Body.Lbrace && n.End() < d.Body.Rbrace }
			for _, r := range rs {
				if len(r.Results) == 0 {
					// A bare return of one named result never assigned.
					res := d.Type.Results
					if res == nil || len(res.List) != 1 || len(res.List[0].Names) != 1 || len(local[res.List[0].Names[0].Obj]) > 0 {
						return false
					}
					continue
				}
				if len(r.Results) != 1 || !isNil(r.Results[0]) && !nilVar(r.Results[0], r.Pos(), local, in) {
					return false
				}
			}
		}
		return len(ds) > 0
	}
	hasEnv := func(lit *ast.CompositeLit) bool {
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Env" && !nilAt(kv.Value, kv.Pos()) {
					return true
				}
			}
		}
		return false
	}
	// cmdType: exec.Cmd itself, as a type.
	cmdType := func(e ast.Expr) bool { return is(ast.Unparen(e), "os/exec", "Cmd") }
	// holdsCmd: a type that is, or holds at any depth through pointers,
	// slices, arrays, maps, channels, type arguments and constraint
	// terms, an exec.Cmd.
	var holdsCmd func(e ast.Expr) bool
	holdsCmd = func(e ast.Expr) bool {
		switch t := ast.Unparen(e).(type) {
		case *ast.StarExpr:
			return holdsCmd(t.X)
		case *ast.ArrayType:
			return holdsCmd(t.Elt)
		case *ast.MapType:
			return holdsCmd(t.Key) || holdsCmd(t.Value)
		case *ast.ChanType:
			return holdsCmd(t.Value)
		case *ast.IndexExpr:
			return holdsCmd(t.Index)
		case *ast.IndexListExpr:
			for _, x := range t.Indices {
				if holdsCmd(x) {
					return true
				}
			}
			return false
		case *ast.UnaryExpr: // ~T in a constraint
			return t.Op == token.TILDE && holdsCmd(t.X)
		case *ast.BinaryExpr: // A | B in a constraint
			return t.Op == token.OR && (holdsCmd(t.X) || holdsCmd(t.Y))
		case *ast.InterfaceType:
			for _, m := range t.Methods.List {
				if len(m.Names) == 0 && holdsCmd(m.Type) {
					return true
				}
			}
			return false
		}
		return cmdType(e)
	}
	// typeParams: a type-parameter list whose constraint holds one.
	typeParams := func(fl *ast.FieldList) bool {
		if fl == nil {
			return false
		}
		for _, f := range fl.List {
			if holdsCmd(f.Type) {
				return true
			}
		}
		return false
	}
	type unit struct {
		name                 string
		node                 ast.Node
		starts, bad, inherit bool
	}
	var units []*unit
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			units = append(units, &unit{name: d.Name.Name, node: d})
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					var ns []string
					for _, id := range s.Names {
						ns = append(ns, id.Name)
					}
					units = append(units, &unit{name: "var " + strings.Join(ns, ","), node: s})
				case *ast.TypeSpec:
					units = append(units, &unit{name: "type " + s.Name.Name, node: s})
				}
			}
		}
	}
	// envAt and nilEnvAt hold where an Env is set on each variable, and
	// where it is set to a nil one; each command's variable is checked
	// against them once the whole file is read.
	envAt, nilEnvAt := map[string][]token.Pos{}, map[string][]token.Pos{}
	type held struct {
		u   *unit
		key string
		at  token.Pos // where the command was stored in key
		top bool      // stored by a package-level declaration
	}
	var children []held
	for _, u := range units {
		calls, skip, typeOK := map[ast.Expr]bool{}, map[*ast.Ident]bool{}, map[ast.Expr]bool{}
		ast.Inspect(u.node, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				skip[n.Name] = true
			case *ast.TypeSpec:
				skip[n.Name] = true
				// Deny by default (#621 delta Security 4a, 6085258468): a
				// command type in a container or a type's definition is a
				// holder the check cannot follow.
				if holdsCmd(n.Type) || typeParams(n.TypeParams) {
					u.starts, u.bad = true, true
				}
			case *ast.FuncType:
				if typeParams(n.TypeParams) {
					u.starts, u.bad = true, true
				}
			case *ast.IndexExpr:
				// A command type as a generic's type argument
				// (#621 delta Security 4a, 6085443650).
				if holdsCmd(n.Index) {
					u.starts, u.bad = true, true
				}
			case *ast.IndexListExpr:
				for _, x := range n.Indices {
					if holdsCmd(x) {
						u.starts, u.bad = true, true
					}
				}
			case *ast.ArrayType:
				if holdsCmd(n.Elt) {
					u.starts, u.bad = true, true
				}
			case *ast.MapType:
				if holdsCmd(n.Key) || holdsCmd(n.Value) {
					u.starts, u.bad = true, true
				}
			case *ast.ChanType:
				if holdsCmd(n.Value) {
					u.starts, u.bad = true, true
				}
			case *ast.UnaryExpr:
				// An Env reached through its address can be written
				// unseen: *(&c.Env) = nil, p := &c.Env.
				if se, ok := ast.Unparen(n.X).(*ast.SelectorExpr); ok && n.Op == token.AND && se.Sel.Name == "Env" {
					u.bad = true
				}
			case *ast.Field:
				for _, id := range n.Names {
					skip[id] = true
				}
			case *ast.StarExpr:
				typeOK[ast.Unparen(n.X)] = true
			case *ast.CallExpr:
				// Every paren level of the callee is the call, not a
				// function value.
				for fn := n.Fun; ; {
					calls[fn] = true
					p, ok := fn.(*ast.ParenExpr)
					if !ok {
						break
					}
					fn = p.X
				}
				if fn, ok := ast.Unparen(n.Fun).(*ast.Ident); command(n.Fun) || ok && fn.Name == "new" && fn.Obj == nil && len(n.Args) == 1 && cmdType(n.Args[0]) {
					if len(n.Args) == 1 {
						typeOK[ast.Unparen(n.Args[0])] = true
					}
					u.starts = true
					b := bind[n]
					children = append(children, held{u, b.key, b.at, b.top})
				}
				// syscall.Exec and unix.Exec run a new program with the
				// environment in their third argument (Security 4a on #587).
				if execLauncher(n.Fun) && len(n.Args) == 3 {
					u.starts = true
					u.inherit = u.inherit || holds(n.Args[2], 3)
				}
				if attrLauncher(n.Fun) && len(n.Args) == 3 {
					u.starts = true
					switch a := strip(n.Args[2]).(type) {
					case *ast.CompositeLit:
						u.bad = u.bad || !hasEnv(a)
					default:
						if k := key(a); k == "" {
							u.bad = true // nil, or a value no variable holds
						} else {
							// The ProcAttr last stored in k before the call.
							at := token.NoPos
							for _, p := range bindAt[k] {
								if p < n.Pos() && p > at {
									at = p
								}
							}
							children = append(children, held{u, k, at, false})
						}
					}
				}
			case *ast.SelectorExpr:
				skip[n.Sel] = true
			case *ast.KeyValueExpr:
				if id, ok := n.Key.(*ast.Ident); ok {
					skip[id] = true
					if id.Name == "Env" {
						u.inherit = u.inherit || holds(n.Value, 3)
						// A nil Env, whatever the literal's type (brief D4).
						u.bad = u.bad || nilAt(n.Value, n.Pos())
					}
				}
			case *ast.CompositeLit:
				typeOK[ast.Unparen(n.Type)] = true
				if cmdType(n.Type) {
					u.starts = true
					if !hasEnv(n) {
						b := bind[n]
						children = append(children, held{u, b.key, b.at, b.top})
					}
				}
				if b := bind[n]; b.key != "" && hasEnv(n) {
					envAt[b.key] = append(envAt[b.key], b.at)
				}
			case *ast.ValueSpec:
				for _, id := range n.Names {
					skip[id] = true
				}
				if len(n.Values) == 0 && n.Type != nil && cmdType(n.Type) {
					typeOK[ast.Unparen(n.Type)] = true
					u.starts = true
					for _, id := range n.Names {
						children = append(children, held{u, key(id), n.Pos(), top[n]})
					}
				}
			case *ast.AssignStmt:
				for i, l := range n.Lhs {
					// (c.Env) = nil is the same assignment (#621 delta
					// Security 4a, 6085186527).
					se, ok := ast.Unparen(l).(*ast.SelectorExpr)
					if !ok || se.Sel.Name != "Env" {
						continue
					}
					rhs, k := n.Rhs, key(se.X)
					if len(n.Rhs) == len(n.Lhs) {
						rhs = n.Rhs[i : i+1]
						if nilAt(rhs[0], n.Pos()) {
							nilEnvAt[k] = append(nilEnvAt[k], n.Pos())
							// Whatever the receiver (brief D4).
							u.bad = true
						}
					}
					envAt[k] = append(envAt[k], n.Pos())
					for _, r := range rhs {
						u.inherit = u.inherit || holds(r, 3)
					}
				}
			}
			// The process's environment given to childproc.NewEnv is
			// inherited, as in an Env (P3-4b-3r-env-r8 requirement 6).
			if c, ok := n.(*ast.CallExpr); ok && is(c.Fun, module+"childproc", "NewEnv") {
				for _, a := range c.Args {
					u.inherit = u.inherit || holds(a, 3)
				}
			}
			if x, ok := n.(ast.Expr); ok {
				id, isID := x.(*ast.Ident)
				named := !isID || !skip[id]
				// A launcher referenced but not called: its call cannot be
				// followed (P3-4b-3r-env-r1 requirement 2).
				if !calls[x] && named && (command(x) || attrLauncher(x) || execLauncher(x)) {
					u.starts, u.bad = true, true
				}
				// exec.Cmd as a type anywhere but a var, new or a literal:
				// an alias, a field, an element, a parameter (#621
				// Security 4a point 1).
				if !typeOK[x] && named && cmdType(x) {
					u.starts, u.bad = true, true
				}
			}
			return true
		})
	}
	// Each command needs an Env set on its variable after it is stored
	// there and before the variable is stored to again (#621 Security 4a
	// point 3), and no nil one in that span.
	for _, c := range children {
		if c.key == "" {
			c.u.bad = true
			continue
		}
		lo, hi := c.at, token.Pos(math.MaxInt)
		if c.top {
			lo = token.NoPos
		} else {
			for _, p := range bindAt[c.key] {
				if p > lo && p < hi {
					hi = p
				}
			}
		}
		within := func(ps []token.Pos) bool {
			for _, p := range ps {
				if p >= lo && p < hi {
					return true
				}
			}
			return false
		}
		if !within(envAt[c.key]) || within(nilEnvAt[c.key]) {
			c.u.bad = true
		}
	}
	for _, u := range units {
		u.inherit = u.inherit || u.starts && holds(u.node, 3)
		if u.bad {
			noEnv = append(noEnv, u.name)
		}
		if u.inherit {
			inherits = append(inherits, u.name)
		}
	}
	return noEnv, inherits
}

// pkgDecls are a package's function declarations, functions by name and
// methods by "."+name, and the values stored in its package-level vars.
type pkgDecls struct {
	funcs map[string][]*ast.FuncDecl
	vars  map[*ast.Object][]ast.Expr
}

// pkgCache caches packageFuncs by directory.
var pkgCache sync.Map

// packageFuncs reads the non-test Go files of dir, so childEnvCheck can
// follow a helper into another file of the package.
func packageFuncs(t *testing.T, dir string) *pkgDecls {
	t.Helper()
	if m, ok := pkgCache.Load(dir); ok {
		return m.(*pkgDecls)
	}
	m := &pkgDecls{funcs: map[string][]*ast.FuncDecl{}, vars: map[*ast.Object][]ast.Expr{}}
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				name := fn.Name.Name
				if fn.Recv != nil {
					name = "." + name
				}
				m.funcs[name] = append(m.funcs[name], fn)
			}
		}
		for o, xs := range varSources(f) {
			m.vars[o] = xs
		}
	}
	pkgCache.Store(dir, m)
	return m
}

// varSources maps each package-level var of f to the values stored in it
// in f: its initializer and the right-hand side of every assignment.
func varSources(f *ast.File) map[*ast.Object][]ast.Expr {
	m := map[*ast.Object][]ast.Expr{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if id.Obj == nil {
					continue
				}
				m[id.Obj] = []ast.Expr{}
				if len(vs.Values) == len(vs.Names) {
					m[id.Obj] = append(m[id.Obj], vs.Values[i])
				} else if len(vs.Values) == 1 {
					m[id.Obj] = append(m[id.Obj], vs.Values[0])
				}
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok {
			for i, l := range a.Lhs {
				if id, ok := ast.Unparen(l).(*ast.Ident); ok && id.Obj != nil && m[id.Obj] != nil {
					r := a.Rhs[0]
					if len(a.Rhs) == len(a.Lhs) {
						r = a.Rhs[i]
					}
					m[id.Obj] = append(m[id.Obj], r)
				}
			}
		}
		return true
	})
	return m
}

// P3-4b-3a requirement 2 (#515 Security 2, owed check), widened by
// P3-4b-3r-env requirements 2 and 3: every child the broker starts, by
// any launcher, gets an explicit environment, never an inherited one,
// unless envExempt names it with its reason; an exemption no longer
// needed fails too, so the list only shrinks. Putting os.Environ() into
// an Env fails with no exemption.
func TestEveryChildGetsAnExplicitEnvironment(t *testing.T) {
	seen := map[string]bool{}
	var bad, inherit []string
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && path != ".." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel("..", path)
		noEnv, inherits := childEnvCheck(t, path)
		for _, fn := range noEnv {
			key := filepath.ToSlash(rel) + ":" + fn
			seen[key] = true
			if envExempt[key] == "" && vendorEnvExempt[key] == "" {
				bad = append(bad, key)
			}
		}
		for _, fn := range inherits {
			inherit = append(inherit, filepath.ToSlash(rel)+":"+fn)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("child started without Env (it inherits the broker's environment); set Env to an explicit list (reviews/security/README.md, the row on a child inheriting the daemon's environment):\n%s", strings.Join(bad, "\n"))
	}
	if len(inherit) > 0 {
		sort.Strings(inherit)
		t.Errorf("os.Environ() in a child's Env (it inherits the broker's environment); name each variable the child needs instead (reviews/security/README.md, the row on a child inheriting the daemon's environment):\n%s", strings.Join(inherit, "\n"))
	}
	for k := range envExempt {
		if !seen[k] {
			t.Errorf("envExempt names %s, which now sets Env or is gone: drop it", k)
		}
	}
	for k := range vendorEnvExempt {
		if !seen[k] {
			t.Errorf("vendorEnvExempt names %s, which now sets Env or is gone: drop it", k)
		}
	}
}

// REQ: ARC-2
//
// P2-2w c3 (D-108): a vendored package with an exempt child is never in
// agentosd's graph.
func TestVendorEnvExemptionsStayOutOfAgentosd(t *testing.T) {
	linked := map[string]bool{}
	for _, p := range linkedDeps(t) {
		linked[p.path] = true
	}
	if !linked[module+"daemon"] {
		t.Fatalf("agentosd's graph lacks the daemon: %d packages", len(linked))
	}
	for k := range vendorEnvExempt {
		file, _, _ := strings.Cut(k, ":")
		if pkg := strings.TrimPrefix(filepath.ToSlash(filepath.Dir(file)), "vendor/"); linked[pkg] {
			t.Errorf("vendorEnvExempt names %s, but agentosd links %s", k, pkg)
		}
	}
}

// REQ: ARC-2, LOOP-7
//
// P3-4b-3r-env requirement 1: envExempt holds test fixtures only. No
// package any cmd/ binary links may hold an exempt child.
func TestEnvExemptionsAreTestFixturesOnly(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/...")
	cmd.Dir = ".."
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	linked := map[string]bool{}
	for _, p := range strings.Fields(string(out)) {
		linked[p] = true
	}
	if !linked[module+"daemon"] {
		t.Fatalf("go list ./cmd/... lacks the daemon: %d packages", len(linked))
	}
	for k := range envExempt {
		file, _, _ := strings.Cut(k, ":")
		if pkg := module + filepath.ToSlash(filepath.Dir(file)); linked[pkg] {
			t.Errorf("envExempt names %s, but a cmd/ binary links %s", k, pkg)
		}
	}
}

// REQ: ARC-2, LOOP-7
//
// The check catches a planted child without Env, renamed imports and
// literals included, every launcher's shape (P3-4b-3r-env requirement 3),
// and os.Environ() inside an Env (requirement 2); it passes children that
// set an explicit one.
func TestEnvCheckCatchesAnInheritedEnvironment(t *testing.T) {
	src := func(imports, body string) string { return "package p\nimport (" + imports + ")\n" + body + "\n" }
	check := func(c string) (noEnv, inherits []string) {
		path := filepath.Join(t.TempDir(), "p.go")
		if err := os.WriteFile(path, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		return childEnvCheck(t, path)
	}
	for _, c := range []string{
		src(`"os/exec"`, `func f() { exec.Command("x").Run() }`),
		src(`x "os/exec"`, `func f() { c := x.CommandContext(nil, "x"); c.Run() }`),
		src(`"os/exec"`, `func f() { c := &exec.Cmd{Path: "/x"}; c.Run() }`),
		src(`"os/exec"; "os"`, `func f() { c := exec.Command("x"); c.Run() }; func g() { var c exec.Cmd; c.Env = []string{}; os.Getenv("x") }`),
		// Requirement 3: os.StartProcess, syscall.ForkExec and
		// syscall.StartProcess with no Env (machprobe's shape is the second).
		src(`"os"`, `func f() { os.StartProcess("/x", nil, nil) }`),
		src(`"os"`, `func f() { os.StartProcess("/x", []string{"/x"}, &os.ProcAttr{}) }`),
		src(`p "os"`, `func f() { a := p.ProcAttr{Dir: "/"}; p.StartProcess("/x", nil, &a) }`),
		src(`"syscall"`, `func f() { syscall.ForkExec("/x", nil, &syscall.ProcAttr{}) }`),
		src(`"syscall"`, `func f() { syscall.ForkExec("/x", nil, nil) }`),
		src(`s "syscall"`, `func f() { s.StartProcess("/x", nil, &s.ProcAttr{Dir: "/"}) }`),
		src(`. "os"`, `func f() { StartProcess("/x", nil, (nil)) }`),
		src(`"os"`, `func f() { a := &os.ProcAttr{}; a.Env = []string{}; os.StartProcess("/x", nil, &os.ProcAttr{Dir: "/"}) }`),
		// An explicit nil Env is inheritance: exec.Cmd and os.StartProcess
		// give the child the process's environment (L3 on #587).
		src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = nil; c.Run() }`),
		src(`"os/exec"`, `func f() { (&exec.Cmd{Path: "/x", Env: nil}).Run() }`),
		src(`"os"`, `func f() { os.StartProcess("/x", nil, &os.ProcAttr{Env: (nil)}) }`),
	} {
		if noEnv, _ := check(c); len(noEnv) == 0 {
			t.Errorf("missed:\n%s", c)
		}
	}
	// Requirement 2: the process's environment inside any Env value, an
	// assignment or a literal key, under any import name.
	for _, c := range []string{
		src(`"os/exec"; "os"`, `func g() { var c exec.Cmd; c.Env = os.Environ() }`),
		src(`"os"; "os/exec"`, `func f() { c := exec.Command("x"); c.Env = append(os.Environ(), "A=1"); c.Run() }`),
		src(`o "os"; "os/exec"`, `func f() { (&exec.Cmd{Path: "/x", Env: append([]string{"A=1"}, o.Environ()...)}).Run() }`),
		src(`"syscall"; "os/exec"`, `func f() { c := exec.Command("x"); c.Env = syscall.Environ(); c.Run() }`),
		src(`"os"`, `func f() { os.StartProcess("/x", nil, &os.ProcAttr{Env: os.Environ()}) }`),
		src(`s "syscall"`, `func f() { var a s.ProcAttr; a.Dir, a.Env = "/", s.Environ(); s.ForkExec("/x", nil, &a) }`),
		src(`. "os"`, `type L struct{ Env []string }; func f() L { return L{Env: Environ()} }`),
		src(`u "golang.org/x/sys/unix"`, `func f(l *struct{ Env []string }) { l.Env = u.Environ() }`),
		src(`"os"; "os/exec"`, `func f() { env := append(os.Environ(), "A=1"); c := exec.Command("x"); c.Env = env; c.Run() }`),
		src(`"os"`, `func f() { e := os.Environ(); os.StartProcess("/x", nil, &os.ProcAttr{Env: e}) }`),
		// (*exec.Cmd).Environ, the os/exec docs' way to add a variable,
		// returns the process's environment while Env is nil (L3 on #587).
		src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = append(c.Environ(), "A=1"); c.Run() }`),
		// Exec replaces the process with the environment it is given.
		src(`"os"; "syscall"`, `func f() { syscall.Exec("/x", nil, os.Environ()) }`),
		src(`"os"; u "golang.org/x/sys/unix"`, `func f() { e := append(os.Environ(), "A=1"); u.Exec("/x", nil, e) }`),
	} {
		if _, inherits := check(c); len(inherits) == 0 {
			t.Errorf("os.Environ() missed:\n%s", c)
		}
	}
	ok := src(`"os/exec"; "os"; "syscall"`, `func f() { c := exec.Command("x"); c.Env = []string{"PATH=/bin"}; c.Run() }
func g() { (&exec.Cmd{Path: "/x", Env: []string{}}).Run() }
func h() { os.StartProcess("/x", nil, &os.ProcAttr{Env: []string{}}) }
func i() { var a syscall.ProcAttr; a.Env = []string{"PATH=/bin"}; syscall.ForkExec("/x", nil, &a) }
func j() { _ = os.Environ() }
func k() { a := &os.ProcAttr{Env: []string{}}; os.StartProcess("/x", nil, a) }
func l() { syscall.Exec("/x", nil, []string{"PATH=/bin"}) }`)
	if noEnv, inherits := check(ok); len(noEnv)+len(inherits) != 0 {
		t.Errorf("flagged %v %v", noEnv, inherits)
	}
}

// REQ: CRED-1, ARC-1
//
// P3-4b-3r-env-r1: the shapes the check passed before (#587 Security 4a
// point 1 and L3 point 3; runtime-nil Env, Security comment 6079549676;
// typed-nil conversion, L3 comment 6079546431). Each file set is one
// package; the first file is the one checked.
func TestEnvCheckCatchesTheShapesItPassed(t *testing.T) {
	src := func(imports, body string) string { return "package p\nimport (" + imports + ")\n" + body + "\n" }
	check := func(files ...string) (noEnv, inherits []string) {
		dir := t.TempDir()
		for i, c := range files {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("p%d.go", i)), []byte(c), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return childEnvCheck(t, filepath.Join(dir, "p0.go"))
	}
	for _, c := range [][]string{
		// Requirement 1: an exec.Cmd made without a constructor.
		{src(`"os/exec"`, `func f() { var c exec.Cmd; c.Path = "/x"; c.Args = []string{"x"}; c.Run() }`)},
		{src(`"os/exec"`, `func f() { c := new(exec.Cmd); c.Path = "/x"; c.Args = []string{"x"}; c.Start() }`)},
		{src(`x "os/exec"`, `func f() ([]byte, error) { var c *x.Cmd; c = new(x.Cmd); c.Path = "/x"; return c.Output() }`)},
		{src(`"os/exec"`, `var c exec.Cmd; func f() { c.Path = "/x"; c.Run() }`)},
		// Requirement 2: a launcher as a function value, wherever it is
		// referenced, and a call in a package-level var initializer or a
		// func literal.
		{src(`"os/exec"`, `func f() { run := exec.Command; c := run("x"); c.Env = []string{}; c.Run() }`)},
		{src(`x "os/exec"`, `func g(func(string, ...string) *x.Cmd) {}; func f() { g(x.Command) }`)},
		{src(`"os/exec"`, `var mk = exec.CommandContext`)},
		{src(`"os"`, `var start = os.StartProcess`)},
		{src(`. "os/exec"`, `func f() { _ = Command }`)},
		{src(`"os/exec"`, `var c = exec.Command("x")`)},
		{src(`"os/exec"`, `var run = func() error { return exec.Command("x").Run() }`)},
		{src(`"os/exec"`, `func f() { c := exec.Command("y"); c.Env = []string{}; c.Run(); go func() { d := exec.Command("x"); d.Run() }() }`)},
		// Requirement 3: Env belongs to the command it is set on.
		{src(`"os/exec"`, `func f() { a := exec.Command("a"); a.Env = []string{}; b := exec.Command("b"); a.Run(); b.Run() }`)},
		{src(`"os/exec"`, `type L struct{ Env []string }; func f() { var l L; l.Env = []string{"A=1"}; c := exec.Command("x"); c.Run(); _ = l }`)},
		{src(`"os/exec"`, `func f(b bool) { if b { c := exec.Command("x"); c.Env = []string{}; c.Run() } else { c := exec.Command("y"); c.Run() } }`)},
		{src(`"os/exec"`, `type R struct{ a, b *exec.Cmd }; func (r *R) f() { r.a = exec.Command("a"); r.b = exec.Command("b"); r.a.Env = []string{}; r.b.Run() }`)},
		{src(`"os"`, `func f() { a := os.ProcAttr{}; b := os.ProcAttr{}; b.Env = []string{}; os.StartProcess("/x", nil, &a); _ = b }`)},
		// Requirement 5: an Env that is nil at run time.
		{src(`"os/exec"`, `func f() { var e []string; c := exec.Command("x"); c.Env = e; c.Run() }`)},
		{src(`"os/exec"`, `var e []string; func f() { c := exec.Command("x"); c.Env = e; c.Run() }`)},
		{src(`"os/exec"`, `func env() []string { return nil }; func f() { c := exec.Command("x"); c.Env = env(); c.Run() }`)},
		{src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = []string(nil); c.Run() }`)},
		{src(`"os/exec"`, `func f() { (&exec.Cmd{Path: "/x", Env: ([]string)(nil)}).Run() }`)},
		{src(`"os"`, `func f() { var e []string; os.StartProcess("/x", nil, &os.ProcAttr{Env: e}) }`)},
		{src(`"os/exec"`, `func f() { var e []string; c := exec.Command("x"); c.Env = e; e = []string{"A=1"}; c.Run() }`)},
		// #621 Security 4a point 1: an exec.Cmd value made by any other
		// route (an alias, a field, an element, make, an elided literal).
		{src(`"os/exec"`, `type Cmd = exec.Cmd; func f() { var c Cmd; c.Path = "/x"; c.Run() }`)},
		{src(`x "os/exec"`, `type Cmd x.Cmd; func f() { c := new(Cmd); c.Path = "/x" }`)},
		{src(`"os/exec"`, `type R struct{ c exec.Cmd }; func f() { var r R; r.c.Path = "/x"; r.c.Run() }`)},
		{src(`"os/exec"`, `func f() { cs := make([]exec.Cmd, 1); cs[0].Path = "/x"; cs[0].Run() }`)},
		{src(`"os/exec"`, `func f() { var cs [1]exec.Cmd; cs[0].Path = "/x"; cs[0].Run() }`)},
		{src(`"os/exec"`, `func f(c exec.Cmd) { c.Run() }`)},
		{src(`"os/exec"`, `func f() { cs := []*exec.Cmd{{Path: "/x"}}; cs[0].Run() }`)},
		{src(`"os/exec"`, `func f() { m := map[string]*exec.Cmd{"a": {Path: "/x"}}; m["a"].Run() }`)},
		// #621 Security 4a point 2: nil by another spelling.
		{src(`"os/exec"`, `func f() { var e []string = nil; c := exec.Command("x"); c.Env = e; c.Run() }`)},
		{src(`"os/exec"`, `func f() { e := []string(nil); c := exec.Command("x"); c.Env = e; c.Run() }`)},
		{src(`"os/exec"`, `func f() { var e = []string(nil); c := exec.Command("x"); c.Env = e; c.Run() }`)},
		{src(`"os/exec"`, `func env() []string { var e []string; return e }; func f() { c := exec.Command("x"); c.Env = env(); c.Run() }`)},
		// #621 Security 4a point 3: a variable reused for a second command
		// needs an Env for each.
		{src(`"os/exec"`, `func f() { c := exec.Command("a"); c.Env = []string{}; c.Run(); c = exec.Command("b"); c.Run() }`)},
		{src(`"os"`, `func f() { a := os.ProcAttr{Env: []string{}}; os.StartProcess("/x", nil, &a); a = os.ProcAttr{}; os.StartProcess("/y", nil, &a) }`)},
		// #621 L3 points 2 and 3.
		{src(`"os/exec"`, `var c = exec.Command("x"); func init() { c.Env = []string{} }; func g() { c = exec.Command("y"); c.Run() }`)},
		{src(`"os/exec"`, `var e []string = nil; func f() { c := exec.Command("x"); c.Env = e; c.Run() }`)},
		{src(`"os/exec"`, `func env() (e []string) { return }; func f() { c := exec.Command("x"); c.Env = env(); c.Run() }`)},
		{src(`"os/exec"`, `func f() { var r struct{ exec.Cmd }; r.Path = "/x"; r.Run() }`)},
		{src(`"os/exec"`, `type C = exec.Cmd; func f() { (&C{Path: "/x"}).Run() }`)},
		// #621 delta Security 4a point 1: a parenthesised launcher, and
		// L3 point 1: the span ends at the variable's next store.
		{src(`"os/exec"`, `func f() { c := (exec.Command)("x"); c.Run() }`)},
		{src(`"os/exec"`, `func f() { (exec.Command)("x").Run() }`)},
		{src(`"os"`, `func f() { (os.StartProcess)("/x", nil, nil) }`)},
		{src(`"syscall"`, `func f() { (syscall.ForkExec)("/x", nil, nil) }`)},
		{src(`"os/exec"`, `func f() { ((exec.CommandContext))(nil, "x").Run() }`)},
		{src(`"os/exec"`, `func f() { c := exec.Command("a"); c.Run(); c = exec.Command("b"); c.Env = []string{}; c.Run() }`)},
		// #621 delta Security 4a point 3: a conversion to a named type.
		{src(`"os/exec"`, `type E []string; func f() { c := exec.Command("x"); c.Env = E(nil); c.Run() }`)},
		// #621 delta Security 4a (6085186527): a parenthesised Env target.
		{src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = []string{}; (c.Env) = nil; c.Run() }`)},
		{src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = []string{}; ((c).Env) = nil; c.Run() }`)},
		{src(`"os"`, `func f() { a := os.ProcAttr{Env: []string{}}; (a.Env) = nil; os.StartProcess("/x", nil, &a) }`)},
		// The same sweep: a parenthesised element type, and a helper's
		// local assigned through parens.
		{src(`"os/exec"`, `func f() { cs := [](*exec.Cmd){{Path: "/x"}}; cs[0].Run() }`)},
		// #621 delta Security 4a (6085258468): deny by default. A command
		// type inside a slice, array, map or channel at any depth, or as
		// a type's definition, is a holder the check cannot follow; and
		// so is an Env reached through its address.
		{src(`"os/exec"`, `func f() { m := map[*exec.Cmd]bool{{Path: "/x"}: true}; for c := range m { c.Run() } }`)},
		{src(`"os/exec"`, `func f() { cs := [][]*exec.Cmd{{{Path: "/x"}}}; cs[0][0].Run() }`)},
		{src(`"os/exec"`, `func f() { m := map[string][]*exec.Cmd{"a": {{Path: "/x"}}}; m["a"][0].Run() }`)},
		{src(`"os/exec"`, `type CS []*exec.Cmd; func f() { cs := CS{{Path: "/x"}}; cs[0].Run() }`)},
		{src(`"os/exec"`, `type P = *exec.Cmd; func f() { ps := []P{{Path: "/x"}}; ps[0].Run() }`)},
		{src(`"os/exec"`, `func f() { cs := []*exec.Cmd{{Path: "/x", Env: []string{}}}; cs[0].Run() }`)},
		{src(`"os/exec"`, `func f(ch chan *exec.Cmd) { (<-ch).Run() }`)},
		{src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = []string{}; *(&c.Env) = nil; c.Run() }`)},
		{src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = []string{}; p := &c.Env; *p = nil; c.Run() }`)},
		// #621 delta Security 4a (6085443650): a command type as a generic
		// type argument or in a type-parameter constraint.
		{src(`"os/exec"`, `type S[T any] []T; func f() { s := S[*exec.Cmd]{{Path: "/x"}}; s[0].Run() }`)},
		{src(`"os/exec"`, `func mk[E any]() E { return *new(E) }; func f() { c := mk[*exec.Cmd](); c.Run() }`)},
		{src(`"os/exec"`, `type B[T any] struct{ v T }; func f() { b := B[*exec.Cmd]{v: &exec.Cmd{Path: "/x", Env: []string{}}}; b.v.Env = nil; b.v.Run() }`)},
		{src(`"os/exec"`, `type M[K comparable, V any] map[K]V; func f() { m := M[string, *exec.Cmd]{}; m["a"].Run() }`)},
		{src(`"os/exec"`, `func g[T interface{ ~*exec.Cmd | *int }](t T) {}`)},
		{src(`"os/exec"`, `type W[T interface{ *exec.Cmd }] struct{ t T }`)},
	} {
		if noEnv, _ := check(c...); len(noEnv) == 0 {
			t.Errorf("missed:\n%s", strings.Join(c, "\n"))
		}
	}
	// Requirement 4: the process's environment through a same-package
	// helper's return value, followed three calls deep.
	for _, c := range [][]string{
		{src(`"os"; "os/exec"`, `func env() []string { return append(os.Environ(), "A=1") }; func f() { c := exec.Command("x"); c.Env = env(); c.Run() }`)},
		{src(`"os"; "os/exec"`, `func e1() []string { return os.Environ() }; func e2() []string { return e1() }; func e3() []string { return append(e2(), "A=1") }; func f() { c := exec.Command("x"); c.Env = e3(); c.Run() }`)},
		{src(`"os"; "os/exec"`, `func env() []string { e := os.Environ(); return append(e, "A=1") }; func f() { c := exec.Command("x"); c.Env = env(); c.Run() }`)},
		{src(`"os"; "os/exec"`, `type T struct{}; func (T) env() []string { return os.Environ() }; func f(t T) { c := exec.Command("x"); c.Env = t.env(); c.Run() }`)},
		{src(`"os"`, `func env() []string { return os.Environ() }; func f() { os.StartProcess("/x", nil, &os.ProcAttr{Env: env()}) }`)},
		{src(`"os"; "os/exec"`, `func env() []string { return os.Environ() }; func f() { e := env(); c := exec.Command("x"); c.Env = e; c.Run() }`)},
		{src(`"os/exec"`, `func f() { c := exec.Command("x"); c.Env = env(); c.Run() }`), src(`"os"`, `func env() []string { return os.Environ() }`)},
		// #621 L3 point 1: the process's environment held in a
		// package-level var of the file.
		{src(`"os"; "os/exec"`, `var base = append(os.Environ(), "A=1"); func f() { c := exec.Command("a"); c.Env = base; c.Run() }`)},
		{src(`"os"; "os/exec"`, `var base []string; func init() { base = os.Environ() }; func f() { c := exec.Command("a"); c.Env = base; c.Run() }`)},
		{src(`"os"; "os/exec"`, `var base = os.Environ(); func env() []string { return base }; func f() { c := exec.Command("a"); c.Env = env(); c.Run() }`)},
		{src(`"os"; "os/exec"`, `type cfg struct{ env []string }; var conf = cfg{env: os.Environ()}; func f() { c := exec.Command("a"); c.Env = conf.env; c.Run() }`)},
		{src(`"os"; "syscall"`, `func env() []string { return os.Environ() }; func f() { (syscall.Exec)("/x", nil, env()) }`)},
		{src(`"os"; "os/exec"`, `func env() []string { var e []string; (e) = os.Environ(); return e }; func f() { c := exec.Command("x"); c.Env = env(); c.Run() }`)},
	} {
		if _, inherits := check(c...); len(inherits) == 0 {
			t.Errorf("os.Environ() missed:\n%s", strings.Join(c, "\n"))
		}
	}
	ok := []string{src(`"os/exec"; "os"`, `func m() { var c exec.Cmd; c.Path = "/x"; c.Env = []string{}; c.Run() }
func n() { c := new(exec.Cmd); c.Path = "/x"; c.Env = []string{"PATH=/bin"}; c.Start() }
var pc = &exec.Cmd{Path: "/x", Env: []string{}}
var run = func() { c := exec.Command("x"); c.Env = []string{}; c.Run() }
func o() { go func() { c := exec.Command("x"); c.Env = []string{}; c.Run() }() }
type R struct{ cmd *exec.Cmd }
func (r *R) p() { r.cmd = exec.Command("x"); r.cmd.Env = []string{}; r.cmd.Run() }
func q() { c := exec.Command("x"); c.Env = explicit(); c.Run() }
func explicit() []string { return []string{"PATH=/bin"} }
var fixedEnv = []string{"PATH=/bin"}
func r() { c := exec.Command("x"); c.Env = fixedEnv; c.Run() }
func s(env []string) { c := exec.Command("x"); c.Env = env; c.Run() }
func u() { var e []string; e = append(e, "A=1"); c := exec.Command("x"); c.Env = e; c.Run() }
func v() { c := exec.Command("x"); c.Env = []string{}; go func() { c.Run() }() }
func w() { a := exec.Command("a"); b := exec.Command("b"); a.Env, b.Env = []string{}, []string{}; a.Run(); b.Run() }
func y() { a := os.ProcAttr{Env: []string{}}; os.StartProcess("/x", nil, &a) }
func z() { c := exec.Command("x"); c.Env = fixed2(); c.Run() }
func e2() { c := exec.Command("a"); c.Env = []string{}; c.Run(); c = exec.Command("b"); c.Env = []string{"A=1"}; c.Run() }
var initEnv []string
func init() { initEnv = []string{"PATH=/bin"} }
func e3() { c := exec.Command("x"); c.Env = initEnv; c.Run() }
func e4() { pcmd.Env = []string{}; pcmd.Run() }
var pcmd exec.Cmd
func e5() { e := []string{"A=1"}; e = nil; e = append(e, "B=1"); c := exec.Command("x"); c.Env = e; c.Run() }
func rec() []string { return rec() }
func e7() { c := exec.Command("x"); c.Env = rec(); c.Run() }
var pc2 = exec.Command("x")
func init() { pc2.Env = []string{} }
var loopA = loopB
var loopB = loopA
func e8() { c := exec.Command("x"); c.Env = loopA; c.Run() }
func e9() { c := (exec.Command)("x"); c.Env = []string{}; c.Run() }
func e11() { c := exec.Command("x"); (c.Env) = []string{}; c.Run() }
func e12() { c := exec.Command("x"); ((c).Env) = []string{}; (c).Run() }
func e10() { c := exec.Command("x"); c.Env = build(nil); c.Run() }
func build(extra []string) []string { return append([]string{"PATH=/bin"}, extra...) }`), src(``, `func fixed2() []string { return []string{"PATH=/bin"} }`)}
	if noEnv, inherits := check(ok...); len(noEnv)+len(inherits) != 0 {
		t.Errorf("flagged %v %v", noEnv, inherits)
	}
}

// REQ: CRED-1, ARC-1
//
// P3-4b-3r-env-r8 requirements 5 and 6 (brief D4): a nil Env is flagged
// outright, whatever holds it and whatever the file imports, and the
// process's environment given to childproc.NewEnv counts as inherited.
func TestEnvCheckFlagsANilEnvOnAnyReceiver(t *testing.T) {
	src := func(imports, body string) string { return "package p\nimport (" + imports + ")\n" + body + "\n" }
	check := func(c string) (noEnv, inherits []string) {
		path := filepath.Join(t.TempDir(), "p.go")
		if err := os.WriteFile(path, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		return childEnvCheck(t, path)
	}
	for _, c := range []string{
		src(``, `type T struct{ Env []string }; func f() { var t T; t.Env = nil; _ = t }`),
		src(``, `type T struct{ Env []string }; func f() T { return T{Env: []string(nil)} }`),
		src(``, `type T struct{ Env []string }; var unset []string; func f() T { return T{Env: unset} }`),
		src(``, `type T struct{ Env []string }; func none() []string { return nil }; func f(t *T) { t.Env = none() }`),
		src(`"fmt"`, `func f(x *struct{ Env []string }) { x.Env = nil; fmt.Println(x) }`),
	} {
		if noEnv, _ := check(c); len(noEnv) == 0 {
			t.Errorf("nil Env missed:\n%s", c)
		}
	}
	// Environ in an Env, in a file with no launcher import (closes
	// P3-4b-3r-env-r2; #651 UX 1).
	noImport := src(``, `type C struct{ Env []string }; func (C) Environ() []string { return nil }; func f(c *C) { c.Env = append(c.Environ(), "A=1") }`)
	if _, inherits := check(noImport); len(inherits) == 0 {
		t.Errorf("Environ in an Env missed in a file with no launcher import:\n%s", noImport)
	}
	noImportOK := src(``, `type C struct{ Env []string }; func f(c *C) { c.Env = append([]string{"PATH=/bin"}, "A=1") }`)
	if noEnv, inherits := check(noImportOK); len(noEnv)+len(inherits) != 0 {
		t.Errorf("flagged %v %v:\n%s", noEnv, inherits, noImportOK)
	}
	for _, c := range []string{
		src(`"os"; "github.com/ghbmrk/agentos/broker/childproc"`, `func f() childproc.Env { return childproc.NewEnv(os.Environ()...) }`),
		src(`"os"; cp "github.com/ghbmrk/agentos/broker/childproc"`, `func f() cp.Env { return cp.NewEnv(append([]string{"PATH=/bin"}, os.Environ()...)...) }`),
		src(`"os"; "github.com/ghbmrk/agentos/broker/childproc"`, `func env() []string { return os.Environ() }; func f() childproc.Env { return childproc.NewEnv(env()...) }`),
	} {
		if _, inherits := check(c); len(inherits) == 0 {
			t.Errorf("Environ into NewEnv missed:\n%s", c)
		}
	}
	ok := src(`"os"; "github.com/ghbmrk/agentos/broker/childproc"`, `type T struct{ Env []string }
func f() T { return T{Env: []string{}} }
func g(t *T) { t.Env = []string{"A=1"} }
func h() childproc.Env { return childproc.NewEnv("PATH=/bin", "HOME="+os.Getenv("X")) }`)
	if noEnv, inherits := check(ok); len(noEnv)+len(inherits) != 0 {
		t.Errorf("flagged %v %v", noEnv, inherits)
	}
}

// REQ: ARC-2
//
// An inference runtime's Go binding (the vision service's ONNX Runtime
// binding, a llama.cpp one) is reported wherever it sits in agentosd's
// graph, so only the untrusted services link one (#3774 Security 3).
func TestInferenceRuntimesAreReported(t *testing.T) {
	for _, p := range []string{"github.com/yalue/onnxruntime_go", "github.com/go-skynet/go-llama.cpp"} {
		bad := inferenceUse(t, []listed{{path: p}})
		if !slices.Contains(bad, p+": an inference runtime") {
			t.Errorf("%s not reported: %q", p, bad)
		}
	}
}
