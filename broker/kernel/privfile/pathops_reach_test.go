package privfile

// REQ: KRN-2

// Fixtures for the root-side unit lint's reach (pathops_lint_test.go):
// what systemd reads, opens or creates as root beyond a service's own
// Exec lines (#4718), and what a root unit's EnvironmentFile= holds
// (#4699).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reachBase is a repository with one root unit and one user unit whose
// runtime directory another uid owns.
func reachBase() map[string]string {
	return map[string]string{
		"broker/cmd/agentos-side/main.go":  "package main\n\nfunc main() {}\n",
		"image/mkosi/agentos-side.service": "[Service]\nExecStart=/usr/lib/agentos/agentos-side\n",
		"image/mkosi/agentos-x.service":    "[Service]\nUser=agentos-x\nExecStart=/bin/true\nRuntimeDirectory=agentos-x\n",
	}
}

// TestRootSideLintReach: the rest of what systemd reads or opens as root
// for a unit, held to the root-side rules (#4718 items 1-7): a mount's and
// a swap's exec settings, the managers' default environment, a drop-in
// directory reached through a link, the credential stores, the paths the
// manager opens or creates for a socket or service, a unit's terminal, and
// root's user manager.
func TestRootSideLintReach(t *testing.T) {
	const ext = "image/mkosi/mkosi.extra/"
	for name, c := range map[string]struct{ path, text, want string }{
		// Item 1: mount(8) and swapon run as root with a unit's exec settings.
		"a mount drop-in's preload":     {"image/mkosi/tmp.mount.d/z.conf", "[Mount]\nEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n", `variable "LD_PRELOAD"`},
		"a mount's working directory":   {"image/mkosi/srv-x.mount", "[Mount]\nWhat=/dev/sda1\nWhere=/srv/x\nType=ext4\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"a mount type drop-in's env":    {"image/mkosi/mount.d/z.conf", "[Mount]\nEnvironmentFile=/var/tmp/e\n", `path "/var/tmp/e"`},
		"a swap type drop-in's preload": {"image/mkosi/swap.d/z.conf", "[Swap]\nEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n", `variable "LD_PRELOAD"`},
		"a swap drop-in's preload":      {"image/mkosi/dev-sda2.swap.d/z.conf", "[Swap]\nEnvironment=BASH_ENV=/tmp/x\n", `variable "BASH_ENV"`},
		"a swap unit's env file":        {"image/mkosi/dev-sda2.swap", "[Swap]\nWhat=/dev/sda2\nEnvironmentFile=/var/tmp/e\n", `path "/var/tmp/e"`},
		"a swap file another uid owns":  {"image/mkosi/agentos.swap", "[Swap]\nWhat=/var/lib/agentos-x/swap\n", `What=/var/lib/agentos-x/swap`},
		// Item 2: the system manager's environment reaches every root unit.
		"a default preload":            {ext + "usr/lib/systemd/system.conf.d/z.conf", "[Manager]\nDefaultEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n", `variable "LD_PRELOAD"`},
		"a manager preload":            {ext + "etc/systemd/system.conf", "[Manager]\nManagerEnvironment=LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		"a default PATH in /tmp":       {ext + "etc/systemd/system.conf.d/z.conf", "[Manager]\nDefaultEnvironment=PATH=/usr/bin:/tmp\n", `path "/tmp"`},
		"a quoted default environment": {ext + "etc/systemd/system.conf.d/z.conf", "[Manager]\nDefaultEnvironment=\"LD_PRELOAD=/tmp/x.so\"\n", `variable "LD_PRELOAD"`},
		// Item 7: root's user manager runs the user units and user.conf's
		// environment as root.
		"a user manager preload":    {ext + "usr/lib/systemd/user.conf.d/z.conf", "[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		"a user manager conf":       {ext + "etc/systemd/user.conf", "[Manager]\nDefaultEnvironment=BASH_ENV=/tmp/x\n", `variable "BASH_ENV"`},
		"a user unit's preload":     {ext + "usr/lib/systemd/user/agentos-u.service", "[Service]\nExecStart=/bin/true\nEnvironment=LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		"a user unit drop-in's env": {ext + "etc/systemd/user/agentos-side.service.d/z.conf", "[Service]\nEnvironment=LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		// Item 4: packaged root units import credentials from these.
		"a credential store grant":            {"image/mkosi/agentos-c.service", "[Service]\nUser=agentos-c\nExecStart=/bin/true\nRuntimeDirectory=credstore\n", `/run/credstore, in or above /run/credstore`},
		"an encrypted credential store grant": {"image/mkosi/agentos-c.service", "[Service]\nUser=agentos-c\nExecStart=/bin/true\nRuntimeDirectory=credstore.encrypted\n", `/run/credstore.encrypted, in or above /run/credstore.encrypted`},
		// Item 5: paths the manager opens or creates as root, whatever the
		// unit's User=.
		"a special file of ours":        {"image/mkosi/agentos-s.socket", "[Socket]\nListenSpecial=/run/agentos-x/f\n", `ListenSpecial=/run/agentos-x/f: a listen path of ours lies outside rootTrees`},
		"a FIFO of ours":                {"image/mkosi/agentos-s.socket", "[Socket]\nListenFIFO=/run/agentos-x/fifo\n", `ListenFIFO=/run/agentos-x/fifo: a listen path of ours lies outside rootTrees`},
		"a USB function of ours":        {"image/mkosi/agentos-s.socket", "[Socket]\nListenUSBFunction=/run/agentos-x/usb\n", `lies outside rootTrees`},
		"a stream below a grant":        {"image/mkosi/agentos-s.socket", "[Socket]\nListenStream=/run/agentos-x/a/s.sock\n", `/run/agentos-x/a/s.sock, below /run/agentos-x`},
		"a packet socket below a grant": {"image/mkosi/agentos-s.socket", "[Socket]\nListenSequentialPacket=/run/agentos-x/a/s.sock\n", `below /run/agentos-x`},
		"a link below a grant":          {"image/mkosi/agentos-s.socket", "[Socket]\nListenStream=/run/agentos-s/s.sock\nSymlinks=/run/agentos-x/a/l\n", `/run/agentos-x/a/l, below /run/agentos-x`},
		"a PID file another uid writes": {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nPIDFile=/run/agentos-x/pid\n", `PIDFile=/run/agentos-x/pid`},
		"a relative PID file":           {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nPIDFile=agentos-x/pid\n", `PIDFile=agentos-x/pid`},
		"USB descriptors":               {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nUSBFunctionDescriptors=/var/lib/agentos-x/d\n", `USBFunctionDescriptors=/var/lib/agentos-x/d`},
		"USB strings":                   {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nUSBFunctionStrings=/tmp/s\n", `USBFunctionStrings=/tmp/s`},
		// Item 6: of /dev, only the console and the virtual terminals.
		"a terminal in /dev/shm": {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/shm/x\n", `path "/dev/shm/x"`},
		"a pseudo terminal":      {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/pts/0\n", `path "/dev/pts/0"`},
		"a serial terminal":      {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/ttyS0\n", `path "/dev/ttyS0"`},
		"a console with a ..":    {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/../tmp/console\n", `path "/dev/../tmp/console"`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := reachBase()
			files[c.path] = c.text
			if _, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
		})
	}
	t.Run("passes what the image ships", func(t *testing.T) {
		files := reachBase()
		files["image/mkosi/tmp.mount.d/z.conf"] = "[Mount]\nOptions=mode=1777,strictatime,nosuid,nodev,noexec\n"
		files["image/mkosi/dev-sda2.swap"] = "[Swap]\nWhat=/dev/sda2\nEnvironment=GOMEMLIMIT=1\n"
		files[ext+"usr/lib/systemd/system.conf.d/z.conf"] = "[Manager]\nDefaultLimitCORE=0\nDefaultEnvironment=PATH=/usr/bin:/usr/sbin\n"
		files["image/mkosi/agentos-t.service"] = "[Service]\nExecStart=/bin/true\nTTYPath=/dev/console\n"
		files["image/mkosi/agentos-t2.service"] = "[Service]\nExecStart=/bin/true\nTTYPath=/dev/tty1\n"
		files["image/mkosi/agentos-s.socket"] = "[Socket]\nListenStream=/run/agentos-x/s.sock\nSymlinks=/run/agentos-x/l\n"
		files["image/mkosi/agentos-p.service"] = "[Service]\nUser=agentos-p\nExecStart=/bin/true\nPIDFile=/run/systemd/agentos-p.pid\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
	// Item 3: the scan does not descend a link; systemd and the image
	// build do.
	t.Run("refuses a linked drop-in directory", func(t *testing.T) {
		files := reachBase()
		files["image/elsewhere/z.conf"] = "[Service]\nEnvironment=LD_PRELOAD=/tmp/x.so\n"
		root := fakeRepo(t, files)
		if err := os.Symlink("../elsewhere", filepath.Join(root, "image/mkosi/agentos-side.service.d")); err != nil {
			t.Fatal(err)
		}
		if _, err := rootBinaries(root); err == nil || !strings.Contains(err.Error(), "image/mkosi/agentos-side.service.d: a link to a directory") {
			t.Fatalf("got %v, want a refusal of the link", err)
		}
	})
	t.Run("passes a linked unit file", func(t *testing.T) {
		root := fakeRepo(t, reachBase())
		if err := os.MkdirAll(filepath.Join(root, "image/mkosi/multi-user.target.wants"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../agentos-side.service", filepath.Join(root, "image/mkosi/multi-user.target.wants/agentos-side.service")); err != nil {
			t.Fatal(err)
		}
		if _, err := rootBinaries(root); err != nil {
			t.Fatal(err)
		}
	})
}

// builtRecs is the records of one unit read from a package's fragment and
// a drop-in of ours.
func builtRecs(t *testing.T, unit, pkg, ours string) unitRecords {
	t.Helper()
	files := []any{}
	if pkg != "" {
		files = append(files, map[string]any{"path": "/usr/lib/systemd/system/" + unit, "ours": false, "text": pkg})
	}
	files = append(files, map[string]any{"path": "/etc/systemd/system/" + unit + ".d/z.conf", "ours": true, "text": ours})
	b, err := json.Marshal(map[string]any{"units": []any{map[string]any{"unit": unit, "files": files}}})
	if err != nil {
		t.Fatal(err)
	}
	var recs unitRecords
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	return recs
}

// TestBuiltUnitsPackageMountLines: a mount of ours is held, but in a
// package's mount only our lines are, as in every other unit (#4718 item
// 9); a package's swap with a line of ours is read like a mount (item 1).
func TestBuiltUnitsPackageMountLines(t *testing.T) {
	for name, c := range map[string]struct {
		unit, pkg, ours, want string
	}{
		"a package's helper type":           {"srv-x.mount", "[Mount]\nWhat=srv:/x\nType=nfs\n", "[Mount]\nOptions=noexec\n", ""},
		"a package's open tmpfs":            {"usr-lib-x.mount", "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=mode=1777\n", "[Mount]\nLazyUnmount=yes\n", ""},
		"a package's held source":           {"usr-lib-x.mount", "[Mount]\nWhat=/var/lib/x.img\nType=ext4\n", "[Mount]\nOptions=ro\n", ""},
		"our helper type":                   {"srv-x.mount", "[Mount]\nWhat=/dev/sda1\nType=ext4\n", "[Mount]\nType=nfs\n", `Type=nfs`},
		"our options on a package's tmpfs":  {"usr-lib-x.mount", "[Mount]\nWhat=tmpfs\nType=tmpfs\nOptions=mode=0755\n", "[Mount]\nOptions=nosuid\n", `sets no mode=`},
		"our tmpfs over a package's mount":  {"usr-lib-x.mount", "[Mount]\nWhat=/dev/sda1\nType=ext4\nOptions=mode=0755\n", "[Mount]\nType=tmpfs\n", `with no Options=`},
		"our source over a root tree":       {"usr-lib-x.mount", "[Mount]\nWhat=/dev/sda1\nType=ext4\n", "[Mount]\nWhat=/var/lib/x.img\n", `What=/var/lib/x.img`},
		"our mount with no type":            {"srv-x.mount", "", "[Mount]\nWhat=/dev/sda1\n", `no Type=`},
		"our preload on a package's mount":  {"srv-x.mount", "[Mount]\nWhat=/dev/sda1\nType=ext4\n", "[Mount]\nEnvironment=LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		"our preload on a package's swap":   {"dev-sda2.swap", "[Swap]\nWhat=/dev/sda2\n", "[Swap]\nEnvironment=LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		"our swap file on a package's swap": {"dev-sda2.swap", "[Swap]\nWhat=/dev/sda2\n", "[Swap]\nWhat=/tmp/swap\n", `What=/tmp/swap`},
		"a package's swap file":             {"dev-sda2.swap", "[Swap]\nWhat=/var/swap\n", "[Swap]\nPriority=1\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := builtUnits(builtRecs(t, c.unit, c.pkg, c.ours), t.TempDir())
			switch {
			case c.want == "" && err != nil:
				t.Fatal(err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
		})
	}
}

// TestBuiltUnitsEndpointsInGrants: a path PID 1 opens for a socket of ours
// may not lie in a directory a package's unit hands its user, even in
// rootTrees; one it binds may lie right in it (#4718 item 5).
func TestBuiltUnitsEndpointsInGrants(t *testing.T) {
	pkg := map[string]any{"unit": "pkg-g.service", "files": []any{map[string]any{"path": "/usr/lib/systemd/system/pkg-g.service", "ours": false,
		"text": "[Service]\nUser=pkg\nExecStart=/usr/bin/pkg\nRuntimeDirectory=systemd/pkg-g agentos-g\n"}}}
	for name, c := range map[string]struct{ socket, want string }{
		"a FIFO in a package's grant":   {"[Socket]\nListenFIFO=/run/systemd/pkg-g/f\n", `/run/systemd/pkg-g/f, below /run/systemd/pkg-g`},
		"a stream below a package's":    {"[Socket]\nListenStream=/run/agentos-g/a/s.sock\n", `/run/agentos-g/a/s.sock, below /run/agentos-g`},
		"a stream in a package's grant": {"[Socket]\nListenStream=/run/agentos-g/s.sock\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(map[string]any{"units": []any{pkg, map[string]any{"unit": "agentos-f.socket", "files": []any{
				map[string]any{"path": "/usr/lib/systemd/system/agentos-f.socket", "ours": true, "text": c.socket}}}}})
			if err != nil {
				t.Fatal(err)
			}
			var recs unitRecords
			if err := json.Unmarshal(b, &recs); err != nil {
				t.Fatal(err)
			}
			err = builtUnits(recs, t.TempDir())
			switch {
			case c.want == "" && err != nil:
				t.Fatal(err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
		})
	}
}

// TestRootEnvFiles: what a root unit's EnvironmentFile= holds is held to
// the same rootEnv and PATH rules as its Environment= (#4699). A file the
// lint cannot find under image/ is refused, unless envFileReasons lists it.
func TestRootEnvFiles(t *testing.T) {
	const env = "image/mkosi/mkosi.extra/etc/agentos/y.env"
	const unit = "image/mkosi/agentos-e.service"
	const root = "[Service]\nExecStart=/bin/true\nEnvironmentFile=-/etc/agentos/y.env\n"
	for name, c := range map[string]struct{ path, unit, env, want string }{
		"a preload":                 {unit, root, "LD_PRELOAD=/var/lib/agentos-x/x.so\n", `variable "LD_PRELOAD"`},
		"a shell's env file":        {unit, root, "# c\nGOMEMLIMIT=1\nBASH_ENV=/tmp/x\n", `variable "BASH_ENV"`},
		"a PATH in a writable tree": {unit, root, "PATH=/usr/bin:/var/lib/agentos-x\n", `path "/var/lib/agentos-x"`},
		"a quoted value":            {unit, root, "GOMEMLIMIT=\"1\"\n", `y.env:1: "GOMEMLIMIT=\"1\""`},
		"a continued line":          {unit, root, "GOMEMLIMIT=1\\\nLD_PRELOAD=/tmp/x.so\n", `y.env:1:`},
		"an exported name":          {unit, root, "export GOMEMLIMIT=1\n", `y.env:1:`},
		"a blank around =":          {unit, root, "GOMEMLIMIT = 1\n", `y.env:1:`},
		"a substitution":            {unit, root, "PATH=${HOME}\n", `y.env:1:`},
		"a carriage return":         {unit, root, "GOMEMLIMIT=1\r\n", `y.env:1:`},
		"an unshipped file":         {unit, "[Service]\nExecStart=/bin/true\nEnvironmentFile=/etc/agentos/z.env\n", "GOMEMLIMIT=1\n", `/etc/agentos/z.env, which no file under image/ ships`},
		"a mount's env file":        {"image/mkosi/tmp.mount.d/z.conf", "[Mount]\nEnvironmentFile=/etc/agentos/y.env\n", "LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
		"a drop-in's env file":      {"image/mkosi/agentos-side.service.d/z.conf", "[Service]\nEnvironmentFile=/etc/agentos/y.env\n", "LD_PRELOAD=/tmp/x.so\n", `variable "LD_PRELOAD"`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := reachBase()
			files[c.path] = c.unit
			files[env] = c.env
			if _, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
		})
	}
	t.Run("passes", func(t *testing.T) {
		files := reachBase()
		files[unit] = root + "EnvironmentFile=/etc/agentos/agentosd.env\n"
		files[env] = "# comment\n; comment\n\n  GOMEMLIMIT=1\nPATH=/usr/bin:/usr/sbin\nAGENTOS_OWNER=\n"
		// A user unit's env file is its user's.
		files["image/mkosi/agentos-x.service"] = "[Service]\nUser=agentos-x\nExecStart=/bin/true\nEnvironmentFile=/var/lib/agentos-x/e.env\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("refuses a linked env file", func(t *testing.T) {
		files := reachBase()
		files[unit] = root
		r := fakeRepo(t, files)
		if err := os.MkdirAll(filepath.Join(r, filepath.Dir(env)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/passwd", filepath.Join(r, env)); err != nil {
			t.Fatal(err)
		}
		if _, err := rootBinaries(r); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("got %v, want a refusal of the link", err)
		}
	})
	// A built tree's unit of ours reads the file image/ ships (envLookup),
	// or none.
	t.Run("in a built tree", func(t *testing.T) {
		recs := builtRecs(t, "agentos-e.service", "", root)
		if err := builtUnits(recs, t.TempDir()); err == nil || !strings.Contains(err.Error(), "which no file under image/ ships") {
			t.Fatalf("no env file: got %v", err)
		}
		bad := func(string) (map[string]string, error) {
			return map[string]string{"image/x/etc/agentos/y.env": "LD_PRELOAD=/tmp/x.so\n"}, nil
		}
		if err := builtUnitsWith(recs, t.TempDir(), bad); err == nil || !strings.Contains(err.Error(), `variable "LD_PRELOAD"`) {
			t.Fatalf("a preload: got %v", err)
		}
		good := func(string) (map[string]string, error) {
			return map[string]string{"image/x/etc/agentos/y.env": "GOMEMLIMIT=1\n"}, nil
		}
		if err := builtUnitsWith(recs, t.TempDir(), good); err != nil {
			t.Fatal(err)
		}
	})
}
