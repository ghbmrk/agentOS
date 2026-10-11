package gvisor

// REQ: A14, ARC-6

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// A page can ask a model to fetch an internal address. The guest has no
// network, so that fetch cannot be dialed from the machine. The broker is
// the only process that dials, and it dials its own sockets.
func TestAGuestCannotDial(t *testing.T) {
	dir := t.TempDir()
	l := vm.Launch{ID: "m1", Dir: dir, Root: filepath.Join(dir, "root"), Argv: []string{"/bin/true"}, Services: filepath.Join(dir, "svc")}
	if err := writeBundle(filepath.Join(dir, "bundle"), l); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "bundle", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Annotations map[string]string
		Mounts      []struct {
			Destination, Type, Source string
			Options                   []string
		}
		Linux struct {
			Namespaces []struct{ Type, Path string }
		}
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	// With --allow-flag-override, runsc takes dev.gvisor.flag.<name>
	// annotations as flags, so dev.gvisor.flag.network could undo
	// --network=none. Neither may appear.
	for k := range spec.Annotations {
		if strings.HasPrefix(k, "dev.gvisor.flag.") {
			t.Fatalf("bundle overrides a runsc flag: %q", k)
		}
	}
	netns := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "network" {
			if ns.Path != "" {
				t.Fatalf("bundle joins an existing network namespace %q", ns.Path)
			}
			netns = true
		}
	}
	if !netns {
		t.Fatal("bundle has no private network namespace")
	}
	// --host-uds=open lets the guest connect to a host socket it can see,
	// so what it can see from the host is pinned too: the services
	// directory, read-only, and no other host path.
	services := 0
	for _, m := range spec.Mounts {
		switch {
		case m.Destination == "/proc" && m.Type == "proc", m.Destination == "/tmp" && m.Type == "tmpfs":
		case m.Destination == vm.ServicesMount && m.Source == l.Services && slices.Contains(m.Options, "ro"):
			services++
		default:
			t.Fatalf("bundle binds a host path into the guest: %+v", m)
		}
	}
	if services != 1 {
		t.Fatalf("bundle binds the services directory %d times, want once read-only", services)
	}
	r := &Runtime{Bin: "runsc", StateDir: dir}
	for sub, image := range map[string]string{"run": "", "restore": filepath.Join(dir, "image")} {
		args := r.launchArgs(l, image)
		// A flag before the subcommand is a global flag runsc applies.
		if args[0] != sub {
			t.Fatalf("%s: runsc gets %q before the subcommand", sub, args[0])
		}
		args = r.argv(args...)
		noNetwork(t, args)
		// open: the guest may connect to a host socket it can see. create
		// or all would also let it bind host sockets (ARC-6 "nothing else").
		if uds := lastFlag(args, "host-uds"); uds != "open" {
			t.Fatalf("%s: runsc --host-uds is %q, want open: %q", sub, uds, args)
		}
	}
}

// noNetwork fails unless runsc argv args leaves the guest without a
// network and cannot be overridden from the bundle.
func noNetwork(t *testing.T, args []string) {
	t.Helper()
	for _, a := range args {
		if name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "="); strings.HasPrefix(a, "-") && name == "allow-flag-override" {
			t.Fatalf("runsc lets the bundle override its flags: %q", args)
		}
	}
	if network := lastFlag(args, "network"); network != "none" {
		t.Fatalf("runsc is not started with --network=none (got %q): %q", network, args)
	}
}

// lastFlag is the value runsc takes for flag name from args. runsc parses
// flags with Go's flag package: the last occurrence wins, in the -name=x,
// --name=x, -name x and --name x forms.
func lastFlag(args []string, name string) string {
	v := ""
	for i, a := range args {
		switch {
		case a == "--"+name || a == "-"+name:
			if i+1 < len(args) {
				v = args[i+1]
			}
		case strings.HasPrefix(a, "--"+name+"=") || strings.HasPrefix(a, "-"+name+"="):
			v = a[strings.Index(a, "=")+1:]
		}
	}
	return v
}

// TestIntegrationGuestCannotDial starts a guest under runsc and has it try
// to reach the host over TCP and UDP on a non-loopback address the host
// itself can reach, and to resolve a name. Every attempt fails and the host
// listeners see nothing. The guest sees exactly the socket its services
// directory holds and nothing more (A14, ARC-6).
func TestIntegrationGuestCannotDial(t *testing.T) {
	svc := &services{t: t, root: t.TempDir(), srv: map[string]*http.Server{}}
	r := newRigWith(t, 4096, svc)
	ip := hostAddr(t)
	var reached atomic.Int32
	tl, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			reached.Add(1)
			bufio.NewReader(c).ReadString('\n')
			io.WriteString(c, "host\n")
			c.Close()
		}
	}()
	ul, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			_, from, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			reached.Add(1)
			ul.WriteTo([]byte("host\n"), from)
		}
	}()
	targets := map[string]string{"tcp": tl.Addr().String(), "udp": ul.LocalAddr().String()}
	// The listeners answer a dial from the host, so a failure in the guest
	// is the guest's network, not the listener.
	for network, addr := range targets {
		if got := hostDial(network, addr); got != "host" {
			t.Fatalf("host cannot reach its own %s listener at %s: %q", network, addr, got)
		}
	}
	reached.Store(0)

	r.create("m1", admission.Accepted)
	if got := r.ask("m1", "svc", svcSock, "/"); got != "200 OK machine m1" {
		t.Fatalf("guest is not up: services socket gave %q", got)
	}
	for network, addr := range targets {
		if got := r.ask("m1", "dial", network, addr); !strings.HasPrefix(got, "ERR") {
			t.Fatalf("guest dialed the host over %s at %s: %q", network, addr, got)
		} else {
			t.Logf("guest %s dial to %s: %s", network, addr, got)
		}
	}
	if got := r.ask("m1", "lookup", "example.com"); !strings.HasPrefix(got, "ERR") {
		t.Fatalf("guest resolved a name: %q", got)
	}
	time.Sleep(200 * time.Millisecond) // a late UDP datagram
	if n := reached.Load(); n != 0 {
		t.Fatalf("host listeners saw %d connections or datagrams from the guest", n)
	}
	// The guest sees what Services put in its directory, and only that.
	want, err := os.ReadDir(filepath.Join(svc.root, "m1"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range want {
		names = append(names, e.Name())
	}
	if got := r.ask("m1", "ls", vm.ServicesMount); got != strings.Join(names, " ") || got != "broker.sock" {
		t.Fatalf("guest sees %q in %s; the services directory holds %q", got, vm.ServicesMount, names)
	}
}

// hostAddr is a non-loopback IPv4 address of an up interface.
func hostAddr(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				return n.IP.String()
			}
		}
	}
	t.Fatal("no non-loopback IPv4 address on the host: the dial test would prove nothing")
	return ""
}

// hostDial is the guest's dial request, made from the host.
func hostDial(network, addr string) string {
	c, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		return "ERR " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "guest\n"); err != nil {
		return "ERR " + err.Error()
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "ERR " + err.Error()
	}
	return strings.TrimSpace(line)
}
