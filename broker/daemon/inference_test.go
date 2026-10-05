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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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

// httpOK are the broker packages in the graph allowed to import net/http,
// and why. None may hold an HTTP client except modelroute.
var httpOK = map[string]string{
	"meter":      "wraps guest model handlers (OP-8); serves, never dials",
	"guest":      "serves the guest plane over the machine socket; never dials",
	"modelroute": "the one client: forwards model calls to the vault process's unix socket",
	"replay":     "serves replay machines' plane like guest; never dials",
}

// client matches code that can open a network connection.
var client = regexp.MustCompile(`http\.Client|http\.DefaultClient|http\.DefaultTransport|http\.Transport|http\.(Get|Head|Post|PostForm)\(|tls\.Dial|net\.Dial|DialContext`)

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
		if !ours {
			// Third-party code: none in the graph may import net/http.
			for _, im := range p.imports {
				if im == "net/http" && strings.Contains(p.path, ".") {
					bad = append(bad, p.path+": third-party package imports net/http")
				}
			}
			continue
		}
		http := false
		for _, im := range p.imports {
			http = http || im == "net/http"
		}
		if _, ok := httpOK[rel]; http && !ok {
			bad = append(bad, p.path+": imports net/http; add it to httpOK with its reason, by review")
		}
		if rel == "modelroute" {
			continue
		}
		for _, f := range p.files {
			b, err := os.ReadFile(filepath.Join(p.dir, f))
			if err != nil {
				t.Fatal(err)
			}
			if m := client.Find(b); m != nil {
				bad = append(bad, p.path+"/"+f+": network client ("+string(m)+")")
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("agentosd's import graph holds inference-capable code:\n%s", strings.Join(bad, "\n"))
	}
}

// The checks themselves catch what they are for.
func TestImportCheckCatchesARouter(t *testing.T) {
	if !client.MatchString("c := &http.Client{}") || !client.MatchString("net.Dial(\"tcp\", a)") {
		t.Fatal("client pattern misses a client")
	}
	if !providerSDK.MatchString("github.com/anthropics/anthropic-sdk-go") || !providerSDK.MatchString("github.com/sashabaranov/go-openai") {
		t.Fatal("provider pattern misses an SDK")
	}
	for _, f := range forbidden {
		if f == "route" {
			return
		}
	}
	t.Fatal("route is not forbidden")
}
