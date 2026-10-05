package e2e

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// REQ: DEP-2

// localHosts are names that never leave the box: loopback, the guest's
// broker socket, the box's own Wi-Fi address, and the vault process's
// Unix socket.
var localHosts = map[string]bool{
	"127.0.0.1": true, "localhost": true, "broker": true, "broker.localhost": true,
	"agentos-egress": true, "10.42.0.1": true,
}

// thirdPartyHosts are services run by others that the owner chooses to
// use (model providers) or that build the image (package sources). None
// is run by the AgentOS project.
var thirdPartyHosts = map[string]bool{
	"api.openai.com": true, "api.anthropic.com": true,
	"nodejs.org": true, "registry.npmjs.org": true,
}

// projectHost names a domain the project could run: anything carrying
// its name, or its source repository used as a service.
var projectHost = regexp.MustCompile(`(?i)([a-z0-9-]+\.)*[a-z0-9-]*agentos[a-z0-9-]*\.(com|org|net|dev|io|app|ai|cloud|sh|co|me|xyz|info|tech|eu|uk|de)\b|github\.com/ghbmrk`)

var urlRe = regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^\s"'` + "`" + `<>)]*`)

// checkHost fails unless host is on the box or a third party's.
func checkHost(errorf func(string, ...any), where, raw string) {
	if strings.HasPrefix(raw, "otpauth:") {
		return // an authenticator-app label, not a network address
	}
	host := raw
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" {
		host = u.Hostname()
	}
	if host == "" || strings.ContainsAny(host, "{}%$") || strings.EqualFold(host, "Host.") {
		return // filled in at run time from a checked value
	}
	if !localHosts[host] && !thirdPartyHosts[host] {
		errorf("%s: %q reaches host %q, which is neither on the box nor a known third party's", where, raw, host)
	}
}

// shipped walks the files that become part of the box: the broker's own
// Go sources and the guest's build and configuration files. Tests,
// fixtures and vendored code are not shipped by this project.
func shipped(t *testing.T, f func(path string, b []byte)) {
	t.Helper()
	root := filepath.Join("..", "..")
	for _, top := range []string{"broker", "guest"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", "testdata", "e2e":
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, ".md") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			f(p, b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// DEP-2: no component requires a service the project operates. Every
// address the shipped code or configuration names is the box itself, a
// provider the owner chose, or a third-party package source; no name is
// the project's. Update mirrors come only from the owner's configuration
// (maintain.Config.Mirrors), so there is no project default to scan for.
func TestNoComponentNamesAProjectHost(t *testing.T) {
	var goFiles, other int
	shipped(t, func(p string, b []byte) {
		if m := projectHost.FindString(string(b)); m != "" && !strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "go.mod") {
			t.Errorf("%s names a project host: %q", p, m)
		}
		switch {
		case strings.HasSuffix(p, ".go"):
			goFiles++
			if err := checkGo(t.Errorf, p, b); err != nil {
				t.Fatal(err)
			}
		case filepath.Base(p) == "package-lock.json":
			other++
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, `"resolved"`) {
					for _, u := range urlRe.FindAllString(line, -1) {
						checkHost(t.Errorf, p, u)
					}
				}
			}
		case strings.HasSuffix(p, ".sh"), strings.HasSuffix(p, ".json"), strings.HasSuffix(p, ".json5"), strings.HasSuffix(p, ".service"), strings.HasSuffix(p, ".conf"):
			other++
			for _, u := range urlRe.FindAllString(string(b), -1) {
				checkHost(t.Errorf, p, u)
			}
		}
	})
	if goFiles < 100 || other < 3 {
		t.Fatalf("scanned too little to mean anything: %d Go files, %d others", goFiles, other)
	}
}

// checkGo checks every string literal outside import declarations, plus
// every Host field set from a literal (adapters, url.URL values).
func checkGo(errorf func(string, ...any), p string, b []byte) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, p, b, 0)
	if err != nil {
		return err
	}
	imports := map[*ast.BasicLit]bool{}
	for _, im := range f.Imports {
		imports[im.Path] = true
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.KeyValueExpr:
			if k, ok := n.Key.(*ast.Ident); ok && k.Name == "Host" {
				if v, ok := n.Value.(*ast.BasicLit); ok && v.Kind == token.STRING {
					s, _ := strconv.Unquote(v.Value)
					checkHost(errorf, fset.Position(v.Pos()).String(), s)
				}
			}
		case *ast.BasicLit:
			if n.Kind != token.STRING || imports[n] {
				return true
			}
			s, err := strconv.Unquote(n.Value)
			if err != nil {
				return true
			}
			pos := fset.Position(n.Pos()).String()
			if m := projectHost.FindString(s); m != "" {
				errorf("%s names a project host: %q", pos, m)
			}
			for _, u := range urlRe.FindAllString(s, -1) {
				checkHost(errorf, pos, u)
			}
		}
		return true
	})
	return nil
}

// The scan catches what it claims to: a project host in a literal or in an
// adapter's Host field, or any host it does not know.
func TestProjectHostScanCatchesPlants(t *testing.T) {
	scan := func(src string) (n int) {
		count := func(string, ...any) { n++ }
		if err := checkGo(count, "plant.go", []byte(src)); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, src := range []string{
		"package x\nvar u = \"https://updates.agentos.org/stable\"\n",
		"package x\nvar a = Adapter{Host: \"api.agentos.dev\"}\n",
		"package x\nvar u = \"https://mirror.example.net/x\"\n",
		"package x\nvar u = \"https://github.com/ghbmrk/agentos/releases\"\n",
	} {
		if scan(src) == 0 {
			t.Errorf("scan missed %q", src)
		}
	}
	ok := "package x\nimport _ \"github.com/ghbmrk/agentos/broker/journal\"\nvar u = \"http://127.0.0.1:18080/mcp\"\nvar s = \"agentos.slice\"\n"
	if n := scan(ok); n != 0 {
		t.Errorf("scan flags the module's import path, loopback or a unit name: %d", n)
	}
}
