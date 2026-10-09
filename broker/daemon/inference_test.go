package daemon

// REQ: ARC-2, LOOP-5, LOOP-6
//
// W3's gate (arbitrator, adopting potency PW1 on #56; L3 on #62): agentosd,
// and every package W3 links into it (the change pipeline, the loop
// scheduler, the replay evaluator, the grants gate), hold no
// inference-capable code. No model router or provider adapter, no egress
// proxy, and no network client except the modelroute proxy, which speaks
// only to the vault process's unix socket. A package that newly needs
// net/http, a socket-level import, or an escape hatch (cgo, unsafe, plugin,
// os/exec, assembly) must be added below, with its reason, by review.
//
// This is a tripwire against drift, not proof against an adversary (L3 on
// #83). Residuals it does not cover, held by review instead: the standard
// library's and third-party packages' own internals beyond their imports
// (only their socket-capable imports are checked); reflection; values
// built from the allowed types and handed across packages (modelroute's
// transport, once built, is only as good as the code that builds it, which
// this test reads); where a unix dial's address comes from (it must be a
// field or variable, so from configuration, but the configuration itself
// is the operator's); _test.go files, which are not linked; and code generated or
// loaded at run time (plugin, os/exec, and os.StartProcess are refused
// outside their allow-lists, so none is expected).

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// linked is the composition root and what W3 links into it.
// compile is named so a later import of it is checked even if agentosd
// stops linking it (arbitrator on W3 step 3a).
var linked = []string{compositionRoot, "change", "loops", "replay", "grants", "compile", "loopbuild"}

// forbidden broker packages: the model router and its provider adapters,
// and the egress proxy.
var forbidden = []string{"route", "egress", "cmd/agentos-egress"}

// providerSDK matches third-party model provider clients.
var providerSDK = regexp.MustCompile(`(?i)(anthropic|openai|genai|generativeai|mistral|cohere|ollama|bedrock)`)

// httpOK are the broker packages in the graph allowed to import net/http
// (or anything that depends on it), and why. None may hold an HTTP client
// except modelroute, whose every dial is to a unix socket (sourceUse).
var httpOK = map[string]string{
	"meter":      "wraps guest model handlers (OP-8); serves, never dials",
	"guest":      "serves the guest plane over the machine socket; never dials",
	"modelroute": "the one client: forwards model calls to the vault process's unix socket",
	"replay":     "serves replay machines' plane like guest; never dials",
	"loopbuild":  "serves Loop 1's builder machines their own socket (W3-builder); never dials",
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
	"sockets": {"unix listeners, SO_PEERCRED peer checks, and flock on the socket lock",
		[]string{"net.Conn", "net.ErrClosed", "net.Listen", "net.Listener", "net.UnixConn", "net.UnixListener",
			"syscall.EWOULDBLOCK", "syscall.Flock", "syscall.GetsockoptUcred", "syscall.LOCK_EX", "syscall.LOCK_NB",
			"syscall.SOL_SOCKET", "syscall.SO_PEERCRED", "syscall.Stat_t", "syscall.Ucred"}},
	"guest":      {"the guest plane's unix listeners", []string{"net.Conn", "net.ErrClosed", "net.Listen", "net.Listener"}},
	"modelroute": {"dials only the vault process's unix socket", []string{"net.Conn", "net.Dialer", "net.OpError"}},
	"loopbuild":  {"builder machines' unix listeners, capped (W3-builder)", []string{"net.Listen", "net.Listener", "net.Conn", "net.ErrClosed"}},
	"journal":    {"flock on the journal file", []string{"syscall.Flock", "syscall.LOCK_EX", "syscall.LOCK_NB"}},
	"update":     {"flock on the update store", []string{"syscall.Flock", "syscall.LOCK_EX"}},
	// Recall (CAP-3, #59): one broker per index, as for the journal.
	"recall": {"flock on the recall store", []string{"syscall.Flock", "syscall.LOCK_EX", "syscall.LOCK_NB"}},
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
	"quota": {"quotactl_fd and FS_IOC_FS[GS]ETXATTR on the machines' directories; capget/capset to drop CAP_SYS_RESOURCE on one thread; O_NOFOLLOW to tag a tree without following links; no network client",
		[]string{"golang.org/x/sys/unix.CAP_SYS_RESOURCE", "golang.org/x/sys/unix.CapUserData", "golang.org/x/sys/unix.CapUserHeader",
			"golang.org/x/sys/unix.Capget", "golang.org/x/sys/unix.Capset", "golang.org/x/sys/unix.LINUX_CAPABILITY_VERSION_3",
			"golang.org/x/sys/unix.SYS_IOCTL", "golang.org/x/sys/unix.SYS_QUOTACTL_FD", "golang.org/x/sys/unix.Syscall", "golang.org/x/sys/unix.Syscall6",
			"syscall.O_NOFOLLOW"}},
	// The box clock check (P2-9, W9 links it for question deadlines).
	"clock": {"read-only adjtimex (is NTP synced) and CLOCK_BOOTTIME; no network client",
		[]string{"golang.org/x/sys/unix.Adjtimex", "golang.org/x/sys/unix.CLOCK_BOOTTIME", "golang.org/x/sys/unix.ClockGettime", "golang.org/x/sys/unix.STA_UNSYNC", "golang.org/x/sys/unix.TIME_ERROR", "golang.org/x/sys/unix.Timespec", "golang.org/x/sys/unix.Timex"}},
	// LOOP-7's runners start children in a process group of their own and
	// kill the group on cancel (#515 Security 1). loop7's fuzz children
	// also start as an unprivileged user in an empty network namespace,
	// and Jail.Own reads owners and link counts (P3-4b-3r-confine).
	"loop7": {"process-group kill of its fuzz children; their jail's user and empty network namespace; owner and link-count checks",
		[]string{"syscall.CLONE_NEWNET", "syscall.Credential", "syscall.Kill", "syscall.SIGKILL", "syscall.Stat_t", "syscall.SysProcAttr"}},
	"probecmd": {"process-group kill of its probe children", []string{"syscall.Kill", "syscall.SIGKILL", "syscall.SysProcAttr"}},
	compositionRoot: {"SIGTERM for shutdown; O_NOFOLLOW, O_NONBLOCK, and Stat_t to open the launch file safely; read-only Getxattr for systemd's cgroup delegate mark (budget R13)",
		[]string{"syscall.Getxattr", "syscall.O_NOFOLLOW", "syscall.O_NONBLOCK", "syscall.SIGTERM", "syscall.Stat_t"}},
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
	"loop7":    {"os/exec": "runs the release-listed fuzz test binaries in /usr/lib/agentos/fuzz (loop7 TestABinaryOutsideTheReleaseIsRefused, TestALinkInTheReleaseIsNotExecuted)"},
	"probecmd": {"os/exec": "runs release-listed probe harnesses (probecmd TestACommandOutsideTheReleaseIsRefused); not linked until P3-4b-4c"},
}

// rawOK are the syscall numbers besides SYS_IOCTL a broker package may
// pass to a raw Syscall, and why: a raw call could otherwise open a socket.
var rawOK = map[string]map[string]string{
	"quota": {"golang.org/x/sys/unix.SYS_QUOTACTL_FD": "reads and sets project quotas (RES-4)"},
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

// clients are the names that hold or open a connection, by package. In
// modelroute the types are allowed only as composite literals that set
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
	args := []string{"list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .Imports \" \"}}\t{{join .GoFiles \" \"}}\t{{len .CgoFiles}}\t{{len .SFiles}}"}
	for _, p := range linked {
		args = append(args, module+p)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = ".."
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	var ps []listed
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 6 {
			t.Fatalf("go list line: %q", sc.Text())
		}
		cgo, _ := strconv.Atoi(f[4])
		asm, _ := strconv.Atoi(f[5])
		ps = append(ps, listed{path: f[0], dir: f[1], imports: strings.Fields(f[2]), files: strings.Fields(f[3]), cgo: cgo, asm: asm})
	}
	return ps
}

func TestAgentosdLinksNoInference(t *testing.T) {
	ps := linkedDeps(t)
	if len(ps) == 0 {
		t.Fatal("no packages listed")
	}
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
		for _, f := range p.files {
			bad = append(bad, sourceUse(t, filepath.Join(p.dir, f), p.path+"/"+f, rel)...)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("agentosd's import graph holds inference-capable code:\n%s", strings.Join(bad, "\n"))
	}
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
			if rel == "modelroute" {
				literalType[n.Type] = true
			}
		case *ast.StarExpr:
			// A pointer type (a field holding a built client) has no
			// value of its own but nil or a checked literal's.
			if _, isClient := clientTypes[sel(n.X)]; isClient && rel == "modelroute" {
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
			if !isDial || len(n.Args) <= i {
				return true
			}
			if lit, ok := n.Args[i].(*ast.BasicLit); !ok || lit.Value != `"unix"` {
				at(n, se.Sel.Name+" on a network other than \"unix\"")
			}
			// A unix socket can front a network proxy, so a dial's
			// address must come from configuration (a field or a
			// variable), never a literal or an expression built here.
			if se.Sel.Name != "Listen" && len(n.Args) > i+1 && !configured(n.Args[i+1], f) {
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
			case clients[pkg][id] && !literalType[n]:
				at(n, "network client ("+full+")")
			case socketPkgs[pkg] && !clients[pkg][id] && !uses[full]:
				at(n, full+" is outside this package's netOK uses")
			}
		}
		return true
	})
	return bad
}

// configured reports a dial address that comes from configuration: a
// parameter or local variable of this file, or a field of one (cfg.Socket).
// A constant, a literal, an expression, a package-qualified name, or an
// identifier this file does not declare (a package-level const or var in
// another file) is not (L3 S1 on #90).
func configured(e ast.Expr, f *ast.File) bool {
	for {
		se, ok := e.(*ast.SelectorExpr)
		if !ok {
			break
		}
		e = se.X
	}
	id, ok := e.(*ast.Ident)
	if !ok || id.Obj == nil || id.Obj.Kind != ast.Var {
		return false
	}
	// A package-level variable can be set at link time or by any file;
	// only function parameters and locals count.
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.VAR {
			for _, sp := range g.Specs {
				for _, n := range sp.(*ast.ValueSpec).Names {
					if n.Obj == id.Obj {
						return false
					}
				}
			}
		}
	}
	return true
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
	src := func(imports, body string) string { return "package p\nimport (" + imports + ")\n" + body + "\n" }
	for _, c := range []struct{ rel, src string }{
		{"guest", src(`nh "net/http"`, `var c = &nh.Client{}`)},
		{"guest", src(`. "net/http"`, `var c = DefaultClient`)},
		{"loops", src(`"net/http/httputil"`, `var p = httputil.NewSingleHostReverseProxy(nil)`)},
		{"replay", src(`"net/http/httptest"`, `var c = httptest.NewServer(nil).Client()`)},
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
	} {
		path := filepath.Join(t.TempDir(), "p.go")
		if err := os.WriteFile(path, []byte(c.src), 0o600); err != nil {
			t.Fatal(err)
		}
		if len(sourceUse(t, path, "p.go", c.rel)) == 0 {
			t.Errorf("missed in %s:\n%s", c.rel, c.src)
		}
	}
	ok := src(`"net"; "net/http"; "net/http/httputil"`, `type config struct{ Socket string }
func g(sock string, cfg config) {
	_, _ = (&net.Dialer{}).Dial("unix", cfg.Socket)
	tr := &http.Transport{DialContext: func() { (&net.Dialer{}).DialContext(nil, "unix", sock) }}
	_ = &httputil.ReverseProxy{Transport: tr}
	_ = &http.Client{Transport: &http.Transport{DialContext: func() {}}}
}`)
	path := filepath.Join(t.TempDir(), "ok.go")
	if err := os.WriteFile(path, []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sourceUse(t, path, "ok.go", "modelroute"); len(got) != 0 {
		t.Errorf("modelroute's unix dial flagged: %q", got)
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

// REQ: LOOP-7, LOOP-9
//
// P3-4b-3a requirement 1: agentosd links LOOP-7's fuzz runner, and its
// os/exec is the reviewed escapeOK entry; probecmd has the same entry for
// when P3-4b-4c links it. No other package of the graph gains one.
func TestEscapeOKNamesTheLoopRunners(t *testing.T) {
	for _, p := range []string{"loop7", "probecmd"} {
		if escapeOK[p]["os/exec"] == "" {
			t.Errorf("%s has no reviewed os/exec entry", p)
		}
	}
	runners := map[string]bool{"vm/gvisor": true, "clock": true, "loop7": true, "probecmd": true}
	for p, es := range escapeOK {
		if es["os/exec"] != "" && !runners[p] {
			t.Errorf("%s has an os/exec entry no review named", p)
		}
	}
	found := false
	for _, p := range linkedDeps(t) {
		found = found || p.path == module+"loop7"
	}
	if !found {
		t.Fatal("agentosd does not link loop7: the fuzz source is not wired")
	}
}

// envExempt are the functions in non-test broker code that start a child
// without an explicit environment, so it inherits the process's, and why
// each may. Only test fixtures outside the image remain (P3-4b-3r-env);
// TestEnvExemptionsAreTestFixturesOnly pins that no binary links one.
var envExempt = map[string]string{
	"tpmseal/swtpm/swtpm.go:start":    "the software TPM, a test fixture outside the image",
	"quota/quotatest/quotatest.go:On": "mkfs and mount in a test helper, outside the image",
}

// launcherPkgs are the packages whose calls start a child or read the
// process's environment, with their default names.
var launcherPkgs = map[string]string{"os/exec": "exec", "os": "os", "syscall": "syscall", "golang.org/x/sys/unix": "unix"}

// childEnvCheck reads one Go source and returns the functions that start
// a child without an explicit environment (noEnv) and those that put the
// process's own environment into one (inherits). Imports count under any
// name, dot imports included. Each function declaration, with the func
// literals inside it, is checked as one unit, and so is each package-level
// var spec, initializer and literals included; a flagged unit is named by
// its function, or by "var" and its names.
//
// Children and their environment, per command (P3-4b-3r-env-r1):
//   - A command is an exec.Command or exec.CommandContext call, an exec.Cmd
//     literal without Env, new(exec.Cmd), or a var declared as exec.Cmd.
//     A ProcAttr passed to os.StartProcess, syscall.ForkExec or
//     syscall.StartProcess may not be nil, needs an Env key when it is a
//     literal, and otherwise counts as a command held in that variable.
//   - A command needs an Env set on the variable that holds it: a .Env
//     assignment to the same identifier or selector chain (resolved to its
//     declaration, so a same-named variable in another scope does not
//     count), or a literal with an Env key bound to it. An Env set on any
//     other value, an unrelated struct's included, does not count. A
//     command held in no variable (a call chained on the constructor, a
//     return, an argument) is flagged, as is any reference to a launcher
//     that is not a call (exec.Command as a function value), since the
//     call it makes cannot be followed.
//   - An Env that is nil at run time counts as none and fails its command:
//     a literal nil; a typed-nil conversion ([]string(nil)); a local var
//     declared without a value and not assigned (or its address taken)
//     before the Env takes it; a package-level var of this file declared
//     without a value and assigned nowhere in the file; a call to a
//     package function whose every return is one of those literals.
//
// inherits is a reference to any selector named Environ (os.Environ,
// syscall.Environ, unix.Environ, (*exec.Cmd).Environ) anywhere inside an
// Env value (a .Env assignment or an Env key of any literal) or Exec's
// environment argument, or anywhere in a unit that starts a child, which
// catches one passed through a local variable; or, in the same places, a
// call to a package function or method (by name, in any file of the
// package) whose return expression, or a local variable it returns, holds
// one, followed three calls deep. syscall.Exec and unix.Exec count as
// starting a child. It has no exemption.
//
// Procedural, held by review (cmd/agentosd ASSUMPTIONS L7-2): an Env value
// the check cannot classify (a parameter, another struct's field, a map
// lookup, a package-level var or nil helper in another file, a
// multi-value call); a command copied to another variable, or whose Env
// is set in another function; an Environ helper reached through a func
// value, an interface, another package, or more than three calls; and
// reflection.
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
	if len(names) == 0 {
		return nil, nil
	}
	is := func(e ast.Expr, pkg string, sels ...string) bool {
		name := names[pkg]
		sel := ""
		switch e := e.(type) {
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
			if _, ok := ast.Unparen(c.Fun).(*ast.ArrayType); ok {
				e = ast.Unparen(c.Args[0])
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
	var pkg map[string][]*ast.FuncDecl
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
		return pkg[name]
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
	var holds func(e ast.Node, depth int) bool
	holds = func(e ast.Node, depth int) bool {
		if environ(e) {
			return true
		}
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || depth == 0 {
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
							if id, ok := l.(*ast.Ident); ok && objs[id.Obj] {
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
	// assigned: where each variable is assigned or has its address taken.
	assigned := map[*ast.Object][]token.Pos{}
	bind := map[ast.Expr]string{}
	mark := func(e ast.Expr, at token.Pos) {
		if id, ok := ast.Unparen(e).(*ast.Ident); ok && id.Obj != nil {
			assigned[id.Obj] = append(assigned[id.Obj], at)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				mark(l, n.Pos())
				if len(n.Rhs) == len(n.Lhs) {
					bind[strip(n.Rhs[i])] = key(l)
				}
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if i < len(n.Values) {
					bind[strip(n.Values[i])] = key(id)
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				mark(n.X, n.Pos())
			}
		case *ast.RangeStmt:
			if n.Tok == token.ASSIGN {
				for _, x := range []ast.Expr{n.Key, n.Value} {
					if x != nil {
						mark(x, n.Pos())
					}
				}
			}
		}
		return true
	})
	// nilAt: an Env value that is nil when it is taken at pos at
	// (P3-4b-3r-env-r1 requirement 5).
	nilAt := func(e ast.Expr, at token.Pos) bool {
		if isNil(e) {
			return true
		}
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			if x.Obj == nil || x.Obj.Kind != ast.Var {
				return false
			}
			vs, ok := x.Obj.Decl.(*ast.ValueSpec)
			if !ok || len(vs.Values) != 0 {
				return false
			}
			for _, p := range assigned[x.Obj] {
				if top[vs] || p < at {
					return false
				}
			}
			return true
		case *ast.CallExpr:
			if _, ok := ast.Unparen(x.Fun).(*ast.Ident); !ok {
				return false
			}
			ds := helpers(x)
			for _, d := range ds {
				rs := returns(d)
				if d.Body == nil || len(rs) == 0 {
					return false
				}
				for _, r := range rs {
					if len(r.Results) != 1 || !isNil(r.Results[0]) {
						return false
					}
				}
			}
			return len(ds) > 0
		}
		return false
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
	type unit struct {
		name                 string
		node                 ast.Node
		starts, bad, inherit bool
	}
	var units []*unit
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				units = append(units, &unit{name: d.Name.Name, node: d.Body})
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if vs, ok := s.(*ast.ValueSpec); ok && d.Tok == token.VAR {
					var ns []string
					for _, id := range vs.Names {
						ns = append(ns, id.Name)
					}
					units = append(units, &unit{name: "var " + strings.Join(ns, ","), node: vs})
				}
			}
		}
	}
	// envSet and nilEnv hold the variables an Env is set on, and those
	// set to a nil one; each command's variable is checked against them
	// once the whole file is read.
	envSet, nilEnv := map[string]bool{}, map[string]bool{}
	type held struct {
		u   *unit
		key string
	}
	var children []held
	for _, u := range units {
		calls, skip := map[ast.Expr]bool{}, map[*ast.Ident]bool{}
		ast.Inspect(u.node, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				calls[ast.Unparen(n.Fun)] = true
				if fn, ok := ast.Unparen(n.Fun).(*ast.Ident); command(n.Fun) || ok && fn.Name == "new" && fn.Obj == nil && len(n.Args) == 1 && is(n.Args[0], "os/exec", "Cmd") {
					u.starts = true
					children = append(children, held{u, bind[n]})
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
							children = append(children, held{u, k})
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
					}
				}
			case *ast.CompositeLit:
				if is(n.Type, "os/exec", "Cmd") {
					u.starts = true
					if !hasEnv(n) {
						children = append(children, held{u, bind[n]})
					}
				}
				if k := bind[n]; k != "" && hasEnv(n) {
					envSet[k] = true
				}
			case *ast.ValueSpec:
				for _, id := range n.Names {
					skip[id] = true
				}
				if len(n.Values) == 0 && n.Type != nil && is(n.Type, "os/exec", "Cmd") {
					u.starts = true
					for _, id := range n.Names {
						children = append(children, held{u, key(id)})
					}
				}
			case *ast.AssignStmt:
				for i, l := range n.Lhs {
					se, ok := l.(*ast.SelectorExpr)
					if !ok || se.Sel.Name != "Env" {
						continue
					}
					rhs, k := n.Rhs, key(se.X)
					if len(n.Rhs) == len(n.Lhs) {
						rhs = n.Rhs[i : i+1]
						if nilAt(rhs[0], n.Pos()) {
							nilEnv[k] = true
						}
					}
					envSet[k] = true
					for _, r := range rhs {
						u.inherit = u.inherit || holds(r, 3)
					}
				}
			}
			// A launcher referenced but not called: its call cannot be
			// followed (P3-4b-3r-env-r1 requirement 2).
			if x, ok := n.(ast.Expr); ok && !calls[x] && (command(x) || attrLauncher(x) || execLauncher(x)) {
				if id, ok := x.(*ast.Ident); !ok || !skip[id] {
					u.starts, u.bad = true, true
				}
			}
			return true
		})
	}
	for _, c := range children {
		if c.key == "" || nilEnv[c.key] || !envSet[c.key] {
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

// pkgFuncs caches each package directory's functions for packageFuncs.
var pkgFuncs sync.Map

// packageFuncs returns the function declarations in the non-test Go files
// of dir, functions by name and methods by "."+name, so childEnvCheck can
// follow a helper into another file of the package.
func packageFuncs(t *testing.T, dir string) map[string][]*ast.FuncDecl {
	t.Helper()
	if m, ok := pkgFuncs.Load(dir); ok {
		return m.(map[string][]*ast.FuncDecl)
	}
	m := map[string][]*ast.FuncDecl{}
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
				m[name] = append(m[name], fn)
			}
		}
	}
	pkgFuncs.Store(dir, m)
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
			if envExempt[key] == "" {
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
		t.Errorf("child started without Env (it inherits the broker's environment); set Env to an explicit list (cmd/agentosd ASSUMPTIONS L7-2):\n%s", strings.Join(bad, "\n"))
	}
	if len(inherit) > 0 {
		sort.Strings(inherit)
		t.Errorf("os.Environ() in a child's Env (it inherits the broker's environment); name each variable the child needs instead (cmd/agentosd ASSUMPTIONS L7-2):\n%s", strings.Join(inherit, "\n"))
	}
	for k := range envExempt {
		if !seen[k] {
			t.Errorf("envExempt names %s, which now sets Env or is gone: drop it", k)
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
func z() { c := exec.Command("x"); c.Env = fixed2(); c.Run() }`), src(``, `func fixed2() []string { return []string{"PATH=/bin"} }`)}
	if noEnv, inherits := check(ok...); len(noEnv)+len(inherits) != 0 {
		t.Errorf("flagged %v %v", noEnv, inherits)
	}
}
