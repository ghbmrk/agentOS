package gvisor

// REQ: RES-3, REV-1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

// No host device, accelerators included, reaches a machine (Security C1 on
// #124): the bundle declares no devices and binds nothing from the host but
// the machine's own service directory, and runsc gets no device-passthrough
// flag. Accelerators stay with broker-run services that lease them (RES-3).
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
		Mounts []struct{ Destination, Type, Source string }
		Linux  map[string]json.RawMessage
	}
	must(json.Unmarshal(b, &spec))
	for _, k := range []string{"devices", "resources"} {
		if _, ok := spec.Linux[k]; ok {
			t.Errorf("bundle declares linux.%s: %s", k, spec.Linux[k])
		}
	}
	for _, mt := range spec.Mounts {
		if mt.Type == "bind" && mt.Source != services {
			t.Errorf("bundle binds host path %s at %s", mt.Source, mt.Destination)
		}
		if strings.HasPrefix(mt.Source, "/dev") || strings.HasPrefix(mt.Destination, "/dev") {
			t.Errorf("bundle mounts a device path: %+v", mt)
		}
	}
	r := &Runtime{Bin: "runsc", StateDir: dir}
	for _, a := range r.cmd(t.Context(), "run").Args {
		for _, bad := range []string{"--nvproxy", "--tpuproxy", "--dev", "--gpu"} {
			if strings.HasPrefix(a, bad) {
				t.Errorf("runsc gets device passthrough flag %q", a)
			}
		}
	}
}
