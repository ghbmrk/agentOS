package localui

// REQ: DEV-net-h, DEV-net-i, CH-7

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stub writes an executable shell script named name into a fresh
// directory and returns its path. The script appends its arguments and
// standard input to log, then runs body.
func stub(t *testing.T, name, body string) (path, log string) {
	t.Helper()
	dir := t.TempDir()
	path, log = filepath.Join(dir, name), filepath.Join(dir, "log")
	script := "#!/bin/sh\necho \"ARGS $*\" >>" + log + "\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, log
}

func readLog(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// nftStub answers `nft list tables inet` with tables and `nft list chain
// inet agentos_ap input` with chain (exit chainExit).
func nftStub(t *testing.T, tables, chain string, chainExit int) string {
	t.Helper()
	p, _ := stub(t, "nft", `case "$*" in
"list tables inet") printf '%s' '`+tables+`' ;;
"list chain inet agentos_ap input") printf '%s' '`+chain+`'; exit `+strconv.Itoa(chainExit)+` ;;
*) exit 9 ;;
esac`)
	return p
}

const apTables = "table inet agentos_inbound\ntable inet agentos_ap\n"

func apChain(lines ...string) string {
	return "table inet agentos_ap {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n" +
		"\t\t" + strings.Join(lines, "\n\t\t") + "\n\t}\n}\n"
}

func TestAPTableIfaceNamesTheDroppedInterface(t *testing.T) {
	chain := apChain(`iifname "wlan0" udp dport { 53, 67 } accept`, `iifname "wlan0" drop`,
		`iifname != "wlan0" tcp dport 80 ip daddr 10.42.0.1 drop`)
	h := ExecHost{NftPath: nftStub(t, apTables, chain, 0)}
	got, err := h.APTableIface(context.Background())
	if err != nil || got != "wlan0" {
		t.Fatalf("APTableIface = %q, %v; want wlan0", got, err)
	}
}

func TestAPTableIfaceIsEmptyOnlyWhenTheTableIsAbsent(t *testing.T) {
	h := ExecHost{NftPath: nftStub(t, "table inet agentos_inbound\n", "", 1)}
	got, err := h.APTableIface(context.Background())
	if err != nil || got != "" {
		t.Fatalf("absent table: APTableIface = %q, %v; want \"\", nil", got, err)
	}
	// A table whose name merely contains agentos_ap is not it.
	h = ExecHost{NftPath: nftStub(t, "table inet agentos_ap2\n", "", 1)}
	if got, err := h.APTableIface(context.Background()); err != nil || got != "" {
		t.Fatalf("other table: APTableIface = %q, %v; want \"\", nil", got, err)
	}
}

func TestAPTableIfaceErrsOnAnythingElse(t *testing.T) {
	for name, nft := range map[string]string{
		"list tables fails": func() string { p, _ := stub(t, "nft", "exit 1"); return p }(),
		"list chain fails":  nftStub(t, apTables, "", 1),
		"no drop line":      nftStub(t, apTables, apChain(`iifname "wlan0" tcp dport 53 accept`), 0),
		"two drop lines":    nftStub(t, apTables, apChain(`iifname "wlan0" drop`, `iifname "wlan1" drop`), 0),
		"drop with a match": nftStub(t, apTables, apChain(`iifname "wlan0" counter drop`), 0),
		"no nft":            filepath.Join(t.TempDir(), "absent"),
	} {
		t.Run(name, func(t *testing.T) {
			h := ExecHost{NftPath: nft}
			got, err := h.APTableIface(context.Background())
			if err == nil {
				t.Fatalf("APTableIface = %q, nil; want an error (DEV-net-i)", got)
			}
		})
	}
}

func TestNftPassesTheScriptOnStdin(t *testing.T) {
	p, log := stub(t, "nft", `cat >>"$(dirname "$0")/log"`)
	h := ExecHost{NftPath: p}
	if err := h.Nft(context.Background(), "delete table inet agentos_ap\n"); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, log); got != "ARGS -f -\ndelete table inet agentos_ap\n" {
		t.Fatalf("nft saw %q", got)
	}
	fail, _ := stub(t, "nft", "exit 1")
	if err := (ExecHost{NftPath: fail}).Nft(context.Background(), "x\n"); err == nil {
		t.Fatal("a failing nft returned nil")
	}
}

func TestUnitsRestartAndStop(t *testing.T) {
	p, log := stub(t, "systemctl", "")
	h := ExecHost{SystemctlPath: p}
	ctx := context.Background()
	if err := h.StartUnit(ctx, `agentos-ap-exempt@wlan0.service`); err != nil {
		t.Fatal(err)
	}
	if err := h.StopUnit(ctx, `agentos-ap-exempt@wlan0.service`); err != nil {
		t.Fatal(err)
	}
	want := "ARGS restart agentos-ap-exempt@wlan0.service\nARGS stop agentos-ap-exempt@wlan0.service\n"
	if got := readLog(t, log); got != want {
		t.Fatalf("systemctl saw %q, want %q", got, want)
	}
	fail, _ := stub(t, "systemctl", "exit 1")
	if err := (ExecHost{SystemctlPath: fail}).StartUnit(ctx, "x.service"); err == nil {
		t.Fatal("a failing systemctl returned nil")
	}
}

// Each nft and systemctl run is bounded by the host's own timeout, so a
// hung run cannot hold the loader's lock (DEV-net-h).
func TestEachRunIsBounded(t *testing.T) {
	hang, _ := stub(t, "hang", "exec sleep 30")
	h := ExecHost{NftPath: hang, SystemctlPath: hang, Timeout: 200 * time.Millisecond}
	ctx := context.Background()
	for name, run := range map[string]func() error{
		"Nft":          func() error { return h.Nft(ctx, "x\n") },
		"StartUnit":    func() error { return h.StartUnit(ctx, "x.service") },
		"StopUnit":     func() error { return h.StopUnit(ctx, "x.service") },
		"APTableIface": func() error { _, err := h.APTableIface(ctx); return err },
	} {
		start := time.Now()
		err := run()
		if err == nil {
			t.Errorf("%s: a hung run returned nil", name)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v; the timeout is 200ms", name, d)
		}
	}
}

func TestExecHostIsAnAPHost(t *testing.T) {
	var _ APHost = ExecHost{}
	var _ APHost = &ExecHost{}
}
