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
	"vm/overlay": {"overlay files: xattrs, device nodes, stat, timestamps, and the FICLONE ioctl for copies",
		[]string{"syscall.EINVAL", "syscall.ENOTDIR", "syscall.ENXIO", "syscall.Getxattr", "syscall.Listxattr",
			"syscall.Mknod", "syscall.NsecToTimespec", "syscall.O_NOFOLLOW", "syscall.Removexattr", "syscall.SYS_IOCTL",
			"syscall.S_IFCHR", "syscall.Setxattr", "syscall.Stat_t", "syscall.Statfs", "syscall.Statfs_t",
			"syscall.Syscall", "syscall.Timespec", "syscall.TimespecToNsec", "syscall.UtimesNano"}},
	"vm/gvisor": {"mounts and cgroup directory handles for runsc, and its SysProcAttr",
		[]string{"syscall.Close", "syscall.EINVAL", "syscall.ENOENT", "syscall.MNT_DETACH", "syscall.MS_NODEV",
			"syscall.MS_NOSUID", "syscall.MS_PRIVATE", "syscall.Mount", "syscall.O_CLOEXEC", "syscall.O_DIRECTORY",
			"syscall.O_RDONLY", "syscall.Open", "syscall.SysProcAttr", "syscall.Unmount"}},
	// The box clock check (P2-9, W9 links it for question deadlines).
	"clock": {"read-only adjtimex (is NTP synced) and CLOCK_BOOTTIME; no network client",
		[]string{"golang.org/x/sys/unix.Adjtimex", "golang.org/x/sys/unix.CLOCK_BOOTTIME", "golang.org/x/sys/unix.ClockGettime", "golang.org/x/sys/unix.STA_UNSYNC", "golang.org/x/sys/unix.TIME_ERROR", "golang.org/x/sys/unix.Timespec", "golang.org/x/sys/unix.Timex"}},
	compositionRoot: {"SIGTERM for shutdown; O_NOFOLLOW, O_NONBLOCK, and Stat_t to open the launch file safely",
		[]string{"syscall.O_NOFOLLOW", "syscall.O_NONBLOCK", "syscall.SIGTERM", "syscall.Stat_t"}},
}

// escapeOK are the broker packages in the graph allowed an escape hatch
// import (escapes), and why.
var escapeOK = map[string]map[string]string{
	"vm/gvisor": {"os/exec": "starts runsc, the only executable (vm/gvisor TestOnlyRunscIsExecuted)"},
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
			if strings.HasPrefix(sel(se), "syscall.Syscall") || strings.HasPrefix(sel(se), "syscall.RawSyscall") {
				if len(n.Args) == 0 || sel(n.Args[0]) != "syscall.SYS_IOCTL" {
					at(n, sel(se)+" other than SYS_IOCTL")
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
