package gvisor

// REQ: RES-3, REV-1, HW-8, A14, ARC-6

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

// No host device, accelerators included, reaches a machine (Security C1 on
// #124): the bundle declares no devices and binds nothing from the host but
// the machine's own service directory, and runsc gets no device-passthrough
// flag. Accelerators stay with broker-run services that lease them (RES-3).
// The same check keeps every host disk node from every machine (HW-8,
// security H6 on HOST-1a): only the root-only agentos-hostdisk helper
// reads a host disk, and only its partition table.
func TestRES3NoHostDevicesReachAMachine(t *testing.T) {
	dir := t.TempDir()
	services := filepath.Join(dir, "svc")
	l := vm.Launch{ID: "m1", Dir: dir, Root: filepath.Join(dir, "root"), Services: services, Argv: []string{"/bin/true"}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(writeBundle(filepath.Join(dir, "bundle"), l))
	b, err := os.ReadFile(filepath.Join(dir, "bundle", "config.json"))
	must(err)
	var spec struct {
		Mounts []bundleMount
		Linux  map[string]json.RawMessage
	}
	must(json.Unmarshal(b, &spec))
	for _, k := range []string{"devices", "resources"} {
		if _, ok := spec.Linux[k]; ok {
			t.Errorf("bundle declares linux.%s: %s", k, spec.Linux[k])
		}
	}
	for _, mt := range foreignBinds(spec.Mounts, services) {
		t.Errorf("bundle binds host path %s at %s", mt.Source, mt.Destination)
	}
	for _, mt := range spec.Mounts {
		if strings.HasPrefix(mt.Source, "/dev") || strings.HasPrefix(mt.Destination, "/dev") {
			t.Errorf("bundle mounts a device path: %+v", mt)
		}
	}
	r := &Runtime{Bin: "runsc", StateDir: dir}
	if err := hostUDSOpen(r.argv("run")); err != nil {
		t.Error(err)
	}
	for _, a := range r.argv("run") {
		for _, bad := range []string{"--nvproxy", "--tpuproxy", "--dev", "--gpu"} {
			if strings.HasPrefix(a, bad) {
				t.Errorf("runsc gets device passthrough flag %q", a)
			}
		}
	}
}

// bundleMount is an OCI bundle mount as the guards read it.
type bundleMount struct {
	Destination, Type, Source string
	Options                   []string
}

// isBind reports whether m takes a host path into the guest: its type is
// bind, or an option binds whatever its type (OCI runtime spec; runsc
// reads a "bind" or "rbind" option on a typeless or "none" mount as a
// bind). Any type carrying the option counts, so the guard does not lean
// on how a runtime reads the type.
func isBind(m bundleMount) bool {
	return m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind")
}

// foreignBinds is every mount that binds a host path other than the
// machine's own services directory at its mount point. --host-uds=open
// reaches any host socket the guest can see, so these are the paths it
// would widen to (Security on #674).
func foreignBinds(mounts []bundleMount, services string) []bundleMount {
	var out []bundleMount
	for _, m := range mounts {
		if isBind(m) && (m.Source != services || m.Destination != vm.ServicesMount) {
			out = append(out, m)
		}
	}
	return out
}

// hostUDSOpen fails unless runsc takes --host-uds=open from args: connect
// to a host socket the guest can see, never create or all, which would let
// it bind host sockets too (ARC-6 "nothing else").
func hostUDSOpen(args []string) error {
	if uds := lastFlag(args, "host-uds"); uds != "open" {
		return fmt.Errorf("runsc --host-uds is %q, want open: %q", uds, args)
	}
	return nil
}

// TestA14HostBindGuardSeesOptionBinds: the OCI spec lets a mount of any
// type take a host path in through a "bind" or "rbind" option, and runsc
// turns a typeless or "none" mount carrying one into a bind. The guard the
// bundle tests use flags those too, and an allowed services bind only when
// it is the services directory (A14 r1, Security on #674).
func TestA14HostBindGuardSeesOptionBinds(t *testing.T) {
	const services = "/srv/svc"
	for _, c := range []struct {
		m    bundleMount
		want bool
	}{
		{bundleMount{Destination: "/run/x", Type: "none", Source: "/var/run", Options: []string{"rbind"}}, true},
		{bundleMount{Destination: "/run/x", Type: "", Source: "/var/run", Options: []string{"ro", "bind"}}, true},
		{bundleMount{Destination: "/proc", Type: "proc", Source: "/var/run", Options: []string{"rbind"}}, true},
		{bundleMount{Destination: "/run/x", Type: "bind", Source: "/var/run"}, true},
		{bundleMount{Destination: vm.ServicesMount, Type: "none", Source: services + "/..", Options: []string{"rbind", "ro"}}, true},
		{bundleMount{Destination: vm.ServicesMount, Type: "bind", Source: services, Options: []string{"rbind", "ro"}}, false},
		{bundleMount{Destination: "/proc", Type: "proc", Source: "proc"}, false},
		{bundleMount{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid"}}, false},
	} {
		if got := len(foreignBinds([]bundleMount{c.m}, services)) > 0; got != c.want {
			t.Errorf("foreignBinds flags %+v = %v, want %v", c.m, got, c.want)
		}
	}
}

// TestA14HostUDSGuardSeesWidening: the guard on --host-uds takes runsc's
// last value in every flag form, so a later create or all is caught.
func TestA14HostUDSGuardSeesWidening(t *testing.T) {
	base := (&Runtime{Bin: "runsc", StateDir: "/s"}).argv("run")
	if err := hostUDSOpen(base); err != nil {
		t.Fatalf("argv as built: %v", err)
	}
	for _, extra := range [][]string{{"--host-uds=all"}, {"-host-uds", "create"}, {"--host-uds", "all"}, {"-host-uds=create"}} {
		if hostUDSOpen(append(slices.Clone(base), extra...)) == nil {
			t.Errorf("guard passes argv widened by %q", extra)
		}
	}
}
