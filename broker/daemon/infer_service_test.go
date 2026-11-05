package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// REQ: ARC-2, INF-6

// The inference service (cmd/agentos-infer) is forbidden in agentosd, so
// TestAgentosdLinksNoInference never reads its source. Its llama.cpp build
// (infer_llamacpp, image/infer.sh) links net/http to talk to its own
// llama-server child. INF-6 rests on the service's empty network namespace
// (TestServiceHasNoNetwork); this guard holds its code too: under each build
// the image ships, every broker package in its graph keeps agentosd's
// import rules, and the binary's own dials are on "unix" to a configured
// address (#3771 item 7).
//
// The entries live here, beside their guard, rather than in netOK and
// httpOK's literals, and are added at init, before any test reads them.
const inferService = "cmd/agentos-infer"

func init() {
	netOK[inferService] = allowance{
		"serves on its inherited listener and dials only its llama-server child's unix socket (infer_llamacpp); stats and signals that child's leftover socket directories",
		[]string{"net.Conn", "net.Dialer", "net.Error", "net.FileListener", "net.Listener",
			"syscall.Kill", "syscall.ESRCH", "syscall.Stat_t", "syscall.SysProcAttr"},
	}
	httpOK[inferService] = "the llama.cpp adapter's client to its own llama-server child, every dial on unix to the child's private socket (infer_llamacpp; #3771 item 7); by review"
	unixDialers[inferService] = true
}

// inferTags are the builds of the service: the default (no runtime) and
// image/infer.sh's llama.cpp build.
var inferTags = []string{"", "infer_llamacpp"}

// REQ: ARC-2, INF-6
func TestInferServiceDialsOnlyUnix(t *testing.T) {
	for _, tags := range inferTags {
		t.Run("tags="+tags, func(t *testing.T) {
			t.Setenv("GOFLAGS", strings.TrimSpace(os.Getenv("GOFLAGS")+" -tags="+tags))
			ps := listDeps(t, "..", []string{module + inferService})
			if !slices.ContainsFunc(ps, func(p listed) bool { return p.path == module+inferService }) {
				t.Fatal("the service is not in its own graph")
			}
			if bad := inferServiceUse(t, ps); len(bad) > 0 {
				t.Fatalf("the inference service breaks the import rules:\n%s", strings.Join(bad, "\n"))
			}
		})
	}
}

// inferServiceUse is inferenceUse over the service's graph, less the one
// line that names the service itself as forbidden in agentosd.
func inferServiceUse(t *testing.T, ps []listed) []string {
	t.Helper()
	var bad []string
	for _, b := range inferenceUse(t, ps) {
		if b != module+inferService+": forbidden in agentosd" {
			bad = append(bad, b)
		}
	}
	return bad
}

// The guard sees the tagged file: a dial on tcp, or to an address built in
// place, in the llama.cpp adapter's source is reported.
func TestInferServiceGuardCatchesATCPDial(t *testing.T) {
	src := func(body string) string {
		return "//go:build infer_llamacpp\n\npackage main\n\nimport (\n\t\"context\"\n\t\"net\"\n)\n\nfunc dial(ctx context.Context, sock string) {\n\t" + body + "\n}\n"
	}
	for _, c := range []struct{ body, want string }{
		{`(&net.Dialer{}).DialContext(ctx, "tcp", "x:443")`, `on a network other than "unix"`},
		{`(&net.Dialer{}).DialContext(ctx, "unix", "/run/proxy.sock")`, "not taken from configuration"},
	} {
		path := writeTemp(t, src(c.body))
		got := strings.Join(sourceUse(t, path, "adapter.go", inferService), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.body, got, c.want)
		}
	}
	if got := sourceUse(t, writeTemp(t, src(`(&net.Dialer{}).DialContext(ctx, "unix", sock)`)), "adapter.go", inferService); len(got) > 0 {
		t.Errorf("the configured unix dial is reported: %q", got)
	}
}

func writeTemp(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adapter.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
