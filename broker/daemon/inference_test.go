package daemon

// REQ: ARC-2, LOOP-5, LOOP-6
//
// W3's gate (arbitrator, adopting potency PW1 on #56; L3 on #62): agentosd,
// and every package W3 links into it (the change pipeline, the loop
// scheduler, the replay evaluator, the grants gate), hold no
// inference-capable code. No model router or provider adapter, no egress
// proxy, and no network client except the modelroute proxy, which speaks
// only to the vault process's unix socket. A package that newly imports
// net/http must be added to httpOK below, with its reason, by review.

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
var linked = []string{compositionRoot, "change", "loops", "replay", "grants"}

// forbidden broker packages: the model router and its provider adapters,
// and the egress proxy.
var forbidden = []string{"route", "egress", "cmd/agentos-egress"}

// providerSDK matches third-party model provider clients.
var providerSDK = regexp.MustCompile(`(?i)(anthropic|openai|genai|generativeai|mistral|cohere|ollama|bedrock)`)

// httpOK are the broker packages in the graph allowed to import net/http
// (or anything that depends on it), and why. None may hold an HTTP client
// except modelroute, whose every dial is to a unix socket (clientUse).
var httpOK = map[string]string{
	"meter":      "wraps guest model handlers (OP-8); serves, never dials",
	"guest":      "serves the guest plane over the machine socket; never dials",
	"modelroute": "the one client: forwards model calls to the vault process's unix socket",
	"replay":     "serves replay machines' plane like guest; never dials",
}

// netOK are the broker packages in the graph allowed to import net,
// syscall, or golang.org/x/sys/unix directly, and why. Their dials are held
// to clientUse too.
var netOK = map[string]string{
	"sockets":       "unix listeners and SO_PEERCRED",
	"guest":         "the guest plane's unix listeners",
	"modelroute":    "dials only the vault process's unix socket",
	"journal":       "flock on the journal file",
	"update":        "flock on the update store",
	"vm/overlay":    "overlay mounts",
	"vm/gvisor":     "signals to runsc",
	compositionRoot: "signal numbers for shutdown",
}

// thirdPartyNet are the third-party packages in the graph allowed a
// socket-capable import, and which one.
var thirdPartyNet = map[string]string{
	"github.com/google/go-containerregistry/pkg/name": "net", // parses registry host names; dials nothing
	"golang.org/x/sys/unix":                           "syscall",
	"golang.org/x/term":                               "golang.org/x/sys/unix", // sigstore cryptoutils' terminal prompt
}

// sockets are the standard (and x/sys) packages that can open a network
// connection or raw socket; anything that depends on net/http counts too
// (httpReach).
var socketPkgs = map[string]bool{
	"net": true, "crypto/tls": true, "net/smtp": true, "net/rpc": true, "net/rpc/jsonrpc": true,
	"log/syslog": true, "syscall": true, "golang.org/x/sys/unix": true,
}

// dialers are the names that open a connection, by package. In modelroute
// they are allowed only in the forms clientUse checks.
var dialers = map[string]map[string]bool{
	"net/http":          {"Client": true, "DefaultClient": true, "DefaultTransport": true, "Transport": true, "Get": true, "Head": true, "Post": true, "PostForm": true},
	"net":               {"Dial": true, "DialTimeout": true, "DialTCP": true, "DialUDP": true, "DialIP": true, "DialUnix": true, "Dialer": true},
	"crypto/tls":        {"Dial": true, "DialWithDialer": true, "Dialer": true},
	"net/http/httptest": {"NewServer": true, "NewTLSServer": true, "NewUnstartedServer": true, "Server": true},
	"net/http/httputil": {"NewSingleHostReverseProxy": true, "ReverseProxy": true},
}

// modelrouteMay are the dialers modelroute may name, each held to its
// unix-only form by clientUse.
var modelrouteMay = map[string]bool{"net/http.Client": true, "net/http.Transport": true, "net.Dialer": true, "net/http/httputil.ReverseProxy": true}

type listed struct {
	path, dir string
	imports   []string
	files     []string
}

func linkedDeps(t *testing.T) []listed {
	t.Helper()
	args := []string{"list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .Imports \" \"}}\t{{join .GoFiles \" \"}}"}
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
		if len(f) != 4 {
			t.Fatalf("go list line: %q", sc.Text())
		}
		ps = append(ps, listed{path: f[0], dir: f[1], imports: strings.Fields(f[2]), files: strings.Fields(f[3])})
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
		for _, im := range p.imports {
			if strings.HasPrefix(im, module) {
				continue // checked as a package of its own
			}
			switch {
			case !ours && (reach[im] || socketPkgs[im]) && thirdPartyNet[p.path] != im:
				bad = append(bad, p.path+": third-party package imports "+im)
			case ours && reach[im] && httpOK[rel] == "":
				bad = append(bad, p.path+": imports "+im+", which reaches net/http; add it to httpOK with its reason, by review")
			case ours && socketPkgs[im] && !reach[im] && netOK[rel] == "":
				bad = append(bad, p.path+": imports "+im+"; add it to netOK with its reason, by review")
			}
		}
		if !ours {
			continue
		}
		for _, f := range p.files {
			bad = append(bad, clientUse(t, filepath.Join(p.dir, f), p.path+"/"+f, rel == "modelroute")...)
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

// clientUse reports the network clients in one source file, by what its
// imports are called there (renamed and dot imports included). In
// modelroute, http.Client, http.Transport, httputil.ReverseProxy, and
// net.Dialer are allowed only as literals that set their transport or
// dialer, and every dial names the "unix" network.
func clientUse(t *testing.T, path, name string, modelroute bool) []string {
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
		if dialers[p] == nil {
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
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			full := sel(n)
			if full == "" {
				return true
			}
			pkg, id := full[:strings.LastIndex(full, ".")], n.Sel.Name
			if dialers[pkg][id] && !(modelroute && modelrouteMay[full]) {
				at(n, "network client ("+full+")")
			}
		case *ast.CompositeLit:
			key := map[string]string{"net/http.Transport": "DialContext", "net/http.Client": "Transport", "net/http/httputil.ReverseProxy": "Transport"}[sel(n.Type)]
			if key != "" && !hasKey(n, key) {
				at(n, sel(n.Type)+" without its own "+key)
			}
		case *ast.CallExpr:
			se, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			arg := map[string]int{"Dial": 0, "DialTimeout": 0, "DialContext": 1}
			i, isDial := arg[se.Sel.Name]
			if !isDial || len(n.Args) <= i {
				return true
			}
			if lit, ok := n.Args[i].(*ast.BasicLit); !ok || lit.Value != `"unix"` {
				at(n, se.Sel.Name+" to a network other than \"unix\"")
			}
		}
		return true
	})
	return bad
}

func hasKey(c *ast.CompositeLit, key string) bool {
	for _, e := range c.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == key {
				return true
			}
		}
	}
	return false
}

// The checks themselves catch what they are for, including the probes
// L3 on #83 got past the first version: clients reached through other
// standard packages, a renamed import, raw sockets, and a dial to anything
// but a unix socket.
func TestImportCheckCatchesARouter(t *testing.T) {
	if !providerSDK.MatchString("github.com/anthropics/anthropic-sdk-go") || !providerSDK.MatchString("github.com/sashabaranov/go-openai") {
		t.Fatal("provider pattern misses an SDK")
	}
	if !contains(forbidden, "route") {
		t.Fatal("route is not forbidden")
	}
	for src, modelroute := range map[string]bool{
		"package p\nimport nh \"net/http\"\nvar c = &nh.Client{}\n":                                  false,
		"package p\nimport . \"net/http\"\nvar c = DefaultClient\n":                                  false,
		"package p\nimport \"net/http/httputil\"\nvar p = httputil.NewSingleHostReverseProxy(nil)\n": false,
		"package p\nimport \"net/http/httptest\"\nvar c = httptest.NewServer(nil).Client()\n":        false,
		"package p\nimport \"crypto/tls\"\nvar c, _ = tls.Dial(\"tcp\", \"x:443\", nil)\n":           false,
		"package p\nimport \"net\"\nvar c, _ = (&net.Dialer{}).Dial(\"tcp\", \"x:443\")\n":           true,
		"package p\nimport \"net/http\"\nvar c = &http.Client{}\n":                                   true,
		"package p\nimport \"net/http\"\nvar c = &http.Transport{}\n":                                true,
		"package p\nimport \"net/http/httputil\"\nvar p = &httputil.ReverseProxy{}\n":                true,
		"package p\nimport \"net/http\"\nvar r, _ = http.Get(\"http://x\")\n":                        true,
	} {
		path := filepath.Join(t.TempDir(), "p.go")
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		if len(clientUse(t, path, "p.go", modelroute)) == 0 {
			t.Errorf("missed (modelroute %v):\n%s", modelroute, src)
		}
	}
	ok := "package p\nimport (\"net\"; \"net/http\")\nvar t = &http.Transport{DialContext: func() { (&net.Dialer{}).DialContext(nil, \"unix\", \"s\") }}\n"
	path := filepath.Join(t.TempDir(), "ok.go")
	if err := os.WriteFile(path, []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := clientUse(t, path, "ok.go", true); len(got) != 0 {
		t.Errorf("modelroute's unix dial flagged: %q", got)
	}
	// Imports: an RPC, mail, or raw-socket package outside the lists.
	reach := httpReach([]listed{{path: "net/rpc", imports: []string{"net/http"}}, {path: "net/http"}})
	if !reach["net/rpc"] || !socketPkgs["net/smtp"] || !socketPkgs["syscall"] || !socketPkgs["golang.org/x/sys/unix"] {
		t.Fatal("socket-capable imports not caught")
	}
}
