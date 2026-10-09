package clock

import (
	"bufio"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: HW-8, TIM-1

// chronycOut fakes chronyc: tracking, sources and authdata in -c -n form.
func chronycOut(tracking, sources, authdata string, authErr error) func(context.Context, ...string) ([]byte, error) {
	return func(_ context.Context, args ...string) ([]byte, error) {
		switch args[len(args)-1] {
		case "tracking":
			return []byte(tracking), nil
		case "sources":
			return []byte(sources), nil
		case "authdata":
			return []byte(authdata), authErr
		}
		return nil, errors.New("unexpected command")
	}
}

const (
	trackOK       = "C0000201,192.0.2.1,2,1791230000.123456789,-0.000001,0.000002,0.000003,-1.234,0.001,0.010,0.012,0.001,64.1,Normal\n"
	trackUnsynced = "00000000,,0,0.000000000,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,0.0,Not synchronised\n"
	trackStratum0 = "C0000201,192.0.2.1,0,1791230000.123456789,0,0,0,0,0,0,0,0,64.1,Normal\n"
	trackStratum6 = "C0000201,192.0.2.1,16,1791230000.123456789,0,0,0,0,0,0,0,0,64.1,Normal\n"
	srcNTS        = "^,*,192.0.2.1,1,6,377,12,-0.000010,-0.000011,0.000400\n^,?,198.51.100.7,2,6,0,-,0,0,0\n"
	srcThree      = "^,*,192.0.2.1,2,6,377,12,0,0,0\n^,+,192.0.2.2,2,6,377,12,0,0,0\n^,+,192.0.2.3,2,6,377,12,0,0,0\n^,-,192.0.2.4,2,6,377,12,0,0,0\n"
	srcTwo        = "^,*,192.0.2.1,2,6,377,12,0,0,0\n^,+,192.0.2.2,2,6,377,12,0,0,0\n^,-,192.0.2.3,2,6,377,12,0,0,0\n"
	authNTS       = "192.0.2.1,NTS,1,15,256,33m,0,0,8,100\n198.51.100.7,NTS,0,0,0,-,0,0,0,0\n"
	trackLeapOff  = "C0000201,192.0.2.1,2,1791230000.123456789,-0.000001,0.000002,0.000003,-1.234,0.001,0.010,0.012,0.001,64.1,Not synchronised\n"
	srcRefclock   = "#,*,PPS0,0,4,377,8,0,0,0\n=,+,192.0.2.9,2,6,377,12,0,0,0\n#,+,GPS,0,4,377,8,0,0,0\n^,+,192.0.2.2,2,6,377,12,0,0,0\n"
	authOtherNTS  = "192.0.2.1,-,0,0,0,-,0,0,0,0\n192.0.2.2,NTS,1,15,256,33m,0,0,8,100\n"
	authNTSKey0   = "192.0.2.1,NTS,0,15,256,33m,0,0,8,100\n"
	authNone      = "192.0.2.1,-,0,0,0,-,0,0,0,0\n"
)

// Security T4, T5: a sync is verified when chronyd is synchronised at a
// real stratum and its selected source is NTS-authenticated, or at least
// three sources are combined; a chronyc error, "Not synchronised", or
// stratum 0 or 16 is unsynced. Which kind it is decides whether the floor
// may be lowered (security R1 on #177); an NTS key ID of 0 is a working
// source (R2).
func TestHW8SyncedFromChrony(t *testing.T) {
	for _, c := range []struct {
		name                    string
		tracking, sources, auth string
		authErr                 error
		want                    SyncKind
	}{
		{"NTS selected", trackOK, srcNTS, authNTS, nil, SyncedNTS},
		{"NTS selected, key ID 0", trackOK, srcNTS, authNTSKey0, nil, SyncedNTS},
		{"NTS selected among three", trackOK, srcThree, authNTS, nil, SyncedNTS},
		{"three plain NTP agree", trackOK, srcThree, authNone, nil, SyncedPlain},
		{"three plain NTP, authdata refused", trackOK, srcThree, "", errors.New("501 Not authorised"), SyncedPlain},
		{"two plain NTP", trackOK, srcTwo, authNone, nil, NotSynced},
		{"plain selected, another source NTS", trackOK, srcThree, authOtherNTS, nil, SyncedPlain},
		{"one plain selected, another NTS", trackOK, srcTwo, authOtherNTS, nil, NotSynced},
		{"only non-NTP lines selected or combined", trackOK, srcRefclock, authNTS, nil, NotSynced},
		{"leap status not synchronised", trackLeapOff, srcThree, authNTS, nil, NotSynced},
		{"one plain NTP", trackOK, srcNTS, authNone, nil, NotSynced},
		{"NTS listed but authdata refused", trackOK, srcNTS, "", errors.New("501 Not authorised"), NotSynced},
		{"not synchronised", trackUnsynced, srcThree, authNTS, nil, NotSynced},
		{"stratum 0", trackStratum0, srcThree, authNone, nil, NotSynced},
		{"stratum 16", trackStratum6, srcThree, authNone, nil, NotSynced},
		{"garbage", "x\n", srcThree, authNone, nil, NotSynced},
		{"empty", "", "", "", nil, NotSynced},
	} {
		run := chronycOut(c.tracking, c.sources, c.auth, c.authErr)
		got, err := chronySync(context.Background(), run)
		if got != c.want {
			t.Errorf("%s: %v (%v), want %v", c.name, got, err, c.want)
		}
	}
	fail := func(context.Context, ...string) ([]byte, error) { return nil, errors.New("no chronyd") }
	if got, err := chronySync(context.Background(), fail); got != NotSynced || err == nil {
		t.Errorf("chronyc failing: %v, %v", got, err)
	}
}

// HW-8: the kernel's sync flag is what arms its 11-minute RTC write, so
// the box never reads it as "synced" (chronyd keeps it set); nothing in
// the package reads or sets adjtimex or the hardware clock device.
func TestHW8NoAdjtimexNoRTCWrite(t *testing.T) {
	paths, _ := filepath.Glob("*.go")
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), p, b, 0); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"Adjtimex", "STA_UNSYNC", "ClockSettime", "Settimeofday", "/dev/rtc", "RTC_SET", "hwclock", "systohc"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s mentions %s", p, bad)
			}
		}
	}
}

// The shipped chrony configuration (installed by P2-1 as
// /etc/chrony/chrony.conf): NTS sources first, the Debian pool as
// fallback, and nothing that makes chronyd or the kernel write the
// hardware clock or take sources from DHCP (security T1, T4).
func TestHW8ChronyConfig(t *testing.T) {
	f, err := os.Open("chrony/chrony.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var servers []string
	keys, values := map[string]bool{}, map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!") || strings.HasPrefix(l, ";") {
			continue
		}
		fs := strings.Fields(l)
		keys[fs[0]] = true
		values[fs[0]] = strings.Join(fs[1:], " ")
		if fs[0] == "server" || fs[0] == "pool" {
			servers = append(servers, l)
		}
	}
	for _, bad := range []string{"rtcsync", "rtcfile", "hwclockfile", "rtconutc", "rtcdevice", "rtcautotrim", "sourcedir", "confdir", "include", "allow", "local", "manual", "settime"} {
		if keys[bad] {
			t.Errorf("chrony.conf has %s", bad)
		}
	}
	want := []string{"server time.cloudflare.com", "server nts.netnod.se", "server ptbtime1.ptb.de", "pool 2.debian.pool.ntp.org"}
	if len(servers) != len(want) {
		t.Fatalf("sources %q", servers)
	}
	for i, w := range want {
		if !strings.HasPrefix(servers[i], w+" ") {
			t.Errorf("source %d = %q, want %q first", i, servers[i], w)
		}
		nts := false
		for _, opt := range strings.Fields(servers[i])[2:] {
			nts = nts || opt == "nts"
		}
		if nts != (i < 3) {
			t.Errorf("source %q: nts %v", servers[i], nts)
		}
	}
	// No NTP server or UDP command port (chronyc uses the root-only unix
	// socket); a start-up step only; slewing no faster than 500 ppm (about
	// 43 s a day, K9); unauthenticated sources only when no NTS one is
	// selectable (L3 on #177).
	for k, v := range map[string]string{"port": "0", "cmdport": "0", "makestep": "1 3", "maxslewrate": "500",
		"authselectmode": "prefer", "ntsdumpdir": "/var/lib/chrony"} {
		if got := values[k]; got != v {
			t.Errorf("%s %q, want %q", k, got, v)
		}
	}
}

// TestOnlyChronycIsExecuted: the one process the clock package may start
// is chronyc at its fixed path, from one call site, with -c -n and only the
// read-only queries Synced makes (the daemon's import check allows the
// package os/exec on this ground).
func TestOnlyChronycIsExecuted(t *testing.T) {
	launchers := map[string]bool{
		"childproc.Command": true, "exec.Command": true, "exec.CommandContext": true, "os.StartProcess": true,
		"syscall.ForkExec": true, "syscall.Exec": true, "syscall.StartProcess": true,
	}
	files, _ := filepath.Glob("*.go")
	n := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fs := token.NewFileSet()
		f, err := parser.ParseFile(fs, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		// Launchers are found by name, so the packages that have them may
		// not be imported under another (L3 on #177).
		for _, im := range f.Imports {
			switch strings.Trim(im.Path.Value, `"`) {
			case "os/exec", "os", "syscall", "golang.org/x/sys/unix", "github.com/ghbmrk/agentos/broker/childproc":
				if im.Name != nil {
					t.Errorf("%s imports %s as %s", path, im.Path.Value, im.Name.Name)
				}
			}
		}
		ast.Inspect(f, func(x ast.Node) bool {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !launchers[id.Name+"."+sel.Sel.Name] {
				return true
			}
			n++
			if path != "chrony.go" || id.Name+"."+sel.Sel.Name != "childproc.Command" || len(call.Args) < 4 {
				t.Errorf("%s: process started at %s", path, fs.Position(call.Pos()))
				return true
			}
			if a, ok := call.Args[3].(*ast.Ident); !ok || a.Name != "chronyc" {
				t.Errorf("%s: starts something other than chronyc", fs.Position(call.Pos()))
			}
			return true
		})
	}
	if n != 1 || chronyc != "/usr/bin/chronyc" {
		t.Fatalf("%d process starts, chronyc %q", n, chronyc)
	}
	if got := strings.Join(chronycArgv([]string{"tracking"}), " "); got != "-c -n tracking" {
		t.Errorf("chronyc %s", got)
	}
	var queries []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		queries = append(queries, args...)
		return nil, errors.New("not run")
	}
	chronySync(context.Background(), run)
	for _, q := range queries {
		if q != "tracking" && q != "sources" && q != "authdata" {
			t.Errorf("chronyc %s", q)
		}
	}
}
