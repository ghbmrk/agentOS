package imagedest

// REQ: NET-2, CLK-14

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/enflist"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// kernelCode is the code that runs as the core's own, not for an account:
// the capability kernel, the core daemon, and the clock, update and
// follow packages they run (paths from broker/). The clerks' hosts are
// account declarations (known.json, Basis Declared) and the enforcer is
// another box, so neither is scanned.
var kernelCode = []string{"kernel", "cmd/agentos-kernel", "cmd/agentosd", "cmd/agentos-clock-boot", "clock", "update", "follow"}

// chronyConf is the image's time-source configuration (TIM-1).
const chronyConf = "../../clock/chrony/chrony.conf"

// TestShippedStatesEveryKernelDestination (#6432 acceptance 1): every
// host the kernel's code or its time configuration reaches is in the
// shipped statement with a non-zero figure, and the statement names no
// host nothing reaches, since each stated host is a destination the owner
// signs onto the core's list.
func TestShippedStatesEveryKernelDestination(t *testing.T) {
	tab, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	reached := chronyHosts(t, chronyConf)
	if len(reached) == 0 {
		t.Fatalf("%s names no time source", chronyConf)
	}
	for _, d := range kernelCode {
		reached = append(reached, codeHosts(t, filepath.Join("../..", d))...)
	}
	slices.Sort(reached)
	reached = slices.Compact(reached)
	stated := tab.Hosts()
	for _, h := range reached {
		if !slices.Contains(stated, h) {
			t.Errorf("the kernel reaches %s, which dests.json does not state", h)
		}
	}
	for _, d := range tab.Dests() {
		if !slices.Contains(reached, d.Host) {
			t.Errorf("dests.json states %s, which nothing in the kernel reaches", d.Host)
		}
		if d.DailyBytes == 0 {
			t.Errorf("%s states no daily bytes", d.Host)
		}
	}
}

// TestScanFindsAPlantedHost is the control for the scan above: a host in
// a URL or host:port literal in non-test Go source is found, and test
// files, loopback, address literals and reserved example names are not.
func TestScanFindsAPlantedHost(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package a\nvar u = \"https://mirror.agentos.dev/repo\"\nvar p = \"ntp.planted.net:4460\"\nvar l = \"http://127.0.0.1:80\"\nvar h = \"http://localhost/x\"\nvar e = \"https://box.example.org\"\nvar c = \"15:04\"\nvar f = \"a.json\"\n")
	write("a_test.go", "package a\nvar v = \"https://test-only.agentos.dev\"\n")
	got := codeHosts(t, dir)
	if want := []string{"mirror.agentos.dev", "ntp.planted.net"}; !slices.Equal(got, want) {
		t.Fatalf("scan found %q, want %q", got, want)
	}
	conf := filepath.Join(dir, "chrony.conf")
	write("chrony.conf", "# server commented.example.net\nserver a.planted.net iburst nts\npool b.planted.net iburst\nport 0\n")
	if got, want := chronyHosts(t, conf), []string{"a.planted.net", "b.planted.net"}; !slices.Equal(got, want) {
		t.Fatalf("chrony hosts %q, want %q", got, want)
	}
}

// TestImageDestsCarryBasisImage (#6432 acceptance 2): each of the
// kernel's own destinations goes to enflist with Basis Image and its
// stated figure, and Propose signs exactly that cap and basis.
func TestImageDestsCarryBasisImage(t *testing.T) {
	tab, err := Load([]byte(`{"destinations": [{"host": "time.agentos.dev", "daily_bytes": 2048}, {"host": "pool.agentos.dev", "daily_bytes": 1024}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []enflist.Dest{{Host: "time.agentos.dev", Basis: enflist.Image, DailyBytes: 2048}, {Host: "pool.agentos.dev", Basis: enflist.Image, DailyBytes: 1024}}
	if got := tab.Dests(); !slices.Equal(got, want) {
		t.Fatalf("Dests = %+v, want %+v", got, want)
	}
	n, err := enflist.Propose(policy.Document{Version: 1}, enflist.Inputs{Dests: tab.Dests(), EdgeDeclaredBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	figs := n.Figures()
	wantFigs := []enflist.Figure{{Host: "pool.agentos.dev", Bytes: 1024, Basis: enflist.Image}, {Host: "time.agentos.dev", Bytes: 2048, Basis: enflist.Image}, {Bytes: 1, Basis: enflist.Declared}}
	if !slices.Equal(figs, wantFigs) {
		t.Fatalf("Figures = %+v, want %+v", figs, wantFigs)
	}
	shipped, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enflist.Propose(policy.Document{Version: 1}, enflist.Inputs{Dests: shipped.Dests(), EdgeDeclaredBytes: 1}); err != nil {
		t.Fatalf("the shipped statement does not sign: %v", err)
	}
}

// TestJoinRefusesAHostInBoth (#6432 acceptance 3): a host both the kernel
// states and an account declares is refused by name; disjoint lists join,
// the kernel's first; a declared destination cannot claim the image's
// basis.
func TestJoinRefusesAHostInBoth(t *testing.T) {
	tab, err := Load([]byte(`{"destinations": [{"host": "time.agentos.dev", "daily_bytes": 2048}]}`))
	if err != nil {
		t.Fatal(err)
	}
	mail := enflist.Dest{Host: "mail.agentos.dev", Basis: enflist.Declared, DailyBytes: 64 << 20}
	got, err := tab.Join([]enflist.Dest{mail})
	if err != nil {
		t.Fatal(err)
	}
	if want := append(tab.Dests(), mail); !slices.Equal(got, want) {
		t.Fatalf("Join = %+v, want %+v", got, want)
	}
	_, err = tab.Join([]enflist.Dest{mail, {Host: "time.agentos.dev", Basis: enflist.Declared, DailyBytes: 1}})
	var sh *Shared
	if !errors.Is(err, ErrShared) || !errors.As(err, &sh) || sh.Host != "time.agentos.dev" {
		t.Fatalf("shared host: %v", err)
	}
	if !strings.Contains(err.Error(), `"time.agentos.dev"`) {
		t.Errorf("refusal %q does not name the host", err)
	}
	if _, err := tab.Join([]enflist.Dest{{Host: "other.agentos.dev", Basis: enflist.Image, DailyBytes: 1}}); !errors.Is(err, ErrTable) {
		t.Fatalf("declared Basis Image: %v", err)
	}
}

// TestLoadRefusesEachBrokenRule (#6432 acceptance 1): a missing or zero
// figure is *enflist.NoDailyBytes naming the host, as Propose would
// return; a bad host, a duplicate, an unknown field, trailing data and an
// empty list are ErrTable.
func TestLoadRefusesEachBrokenRule(t *testing.T) {
	for _, src := range []string{
		`{"destinations": [{"host": "time.agentos.dev"}]}`,
		`{"destinations": [{"host": "time.agentos.dev", "daily_bytes": 0}]}`,
	} {
		_, err := Load([]byte(src))
		var nd *enflist.NoDailyBytes
		if !errors.Is(err, enflist.ErrNoDailyBytes) || !errors.As(err, &nd) || nd.Host != "time.agentos.dev" {
			t.Errorf("%s: %v", src, err)
		}
	}
	for _, src := range []string{
		``,
		`{"destinations": []}`,
		`{}`,
		`{"destinations": [{"host": "Time.agentos.dev", "daily_bytes": 1}]}`,
		`{"destinations": [{"host": "time.agentos.dev.", "daily_bytes": 1}]}`,
		`{"destinations": [{"host": "https://time.agentos.dev", "daily_bytes": 1}]}`,
		`{"destinations": [{"host": "time.agentos.dev:4460", "daily_bytes": 1}]}`,
		`{"destinations": [{"host": "localhost", "daily_bytes": 1}]}`,
		`{"destinations": [{"host": "192.0.2.1", "daily_bytes": 1}]}`,
		`{"destinations": [{"host": "-a.agentos.dev", "daily_bytes": 1}]}`,
		`{"destinations": [{"host": "a.agentos.dev", "daily_bytes": 1}, {"host": "a.agentos.dev", "daily_bytes": 2}]}`,
		`{"destinations": [{"host": "a.agentos.dev", "daily_bytes": 1, "why": "x"}]}`,
		`{"destinations": [{"host": "a.agentos.dev", "daily_bytes": -1}]}`,
		`{"destinations": [{"host": "a.agentos.dev", "daily_bytes": 1}]} {}`,
		`{"destinations": [{"host": "a.agentos.dev", "daily_bytes": 1}], "more": 1}`,
	} {
		if _, err := Load([]byte(src)); !errors.Is(err, ErrTable) {
			t.Errorf("%q: %v, want ErrTable", src, err)
		}
	}
}

// chronyHosts is each server and pool host in a chrony configuration.
func chronyHosts(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var hs []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "server" || f[0] == "pool" || f[0] == "peer") {
			hs = append(hs, f[1])
		}
	}
	return hs
}

var (
	urlHost  = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://([^/?#@:\s]+)`)
	hostPort = regexp.MustCompile(`^([a-z0-9.-]+):[0-9]{1,5}$`)
)

// codeHosts is each internet host named in a URL or host:port string
// literal in dir's non-test Go source, recursively, testdata excluded.
// Loopback, address literals and reserved example names are skipped.
func codeHosts(t *testing.T, dir string) []string {
	t.Helper()
	var hs []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			var h string
			if m := urlHost.FindStringSubmatch(s); m != nil {
				h = m[1]
			} else if m := hostPort.FindStringSubmatch(s); m != nil {
				h = m[1]
			}
			if internet(h) {
				hs = append(hs, h)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(hs)
	return slices.Compact(hs)
}

// internet reports whether h names an internet host: a dotted name that
// is not loopback, an address literal or a reserved name (RFC 2606, 6761).
func internet(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if !strings.Contains(h, ".") || h == "localhost" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	for _, r := range []string{"example", "invalid", "test", "localhost", "local", "home.arpa", "example.com", "example.org", "example.net"} {
		if h == r || strings.HasSuffix(h, "."+r) {
			return false
		}
	}
	return true
}
