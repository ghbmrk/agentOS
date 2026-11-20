package privfile

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuiltUserManagerUnits: on a built tree, root's user manager
// (user@0.service, at a root login) loads its units as root, so its unit
// files and drop-ins of ours reach the unit lint as the system manager's do,
// read by the tree's own systemd --user (#6002 item 1). A drop-in of ours
// on a packaged user unit is the failure path the issue names.
// REQ: KRN-2
func TestBuiltUserManagerUnits(t *testing.T) {
	const ulib, uetc = "/usr/lib/systemd/user/", "/etc/systemd/user/"
	const pkgUnit = "[Service]\nExecStart=/usr/bin/pkgx\n"
	const preload = "[Service]\nEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n"
	ourEtc := func(p string) bool { return strings.HasPrefix(p, "/etc/") || strings.HasPrefix(p, "/root/") }
	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"a drop-in of ours on a packaged user unit": {map[string]string{ulib + "pkg-x.service": pkgUnit, uetc + "pkg-x.service.d/z.conf": preload},
			`root's user manager: pkg-x.service: etc/systemd/user/pkg-x.service.d/z.conf: Environment=LD_PRELOAD=/var/lib/agentos-x/x.so: variable "LD_PRELOAD"`},
		"a user unit of ours a build step writes": {map[string]string{uetc + "agentos-x.service": "[Service]\nExecStart=/usr/bin/true\nEnvironment=BASH_ENV=/tmp/x\n"},
			`root's user manager: agentos-x.service: etc/systemd/user/agentos-x.service: Environment=BASH_ENV=/tmp/x: variable "BASH_ENV"`},
		"a user unit of ours in root's home": {map[string]string{"/root/.config/systemd/user/agentos-x.service": "[Service]\nExecStart=/usr/bin/true\nEnvironment=BASH_ENV=/tmp/x\n"},
			`root's user manager: agentos-x.service: root/.config/systemd/user/agentos-x.service`},
		"a drop-in of ours where no user unit loads": {map[string]string{uetc + "agentos-gone.service.d/z.conf": preload},
			`root's user manager: agentos-gone.service: etc/systemd/user/agentos-gone.service.d/z.conf`},
		"a type-wide user drop-in of ours": {map[string]string{ulib + "pkg-x.service": pkgUnit, uetc + "service.d/z.conf": preload},
			`variable "LD_PRELOAD"`},
		"a mask of ours on a package's user drop-in": {map[string]string{ulib + "pkg-x.service": pkgUnit, ulib + "pkg-x.service.d/p.conf": "[Service]\nNoNewPrivileges=yes\n", uetc + "pkg-x.service.d/p.conf": "-> /dev/null"},
			`/etc/systemd/user/pkg-x.service.d/p.conf: a file of ours hides a package's drop-in, /usr/lib/systemd/user/pkg-x.service.d/p.conf`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			if err := underSystemd(t, c.files, ourEtc); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
		})
	}
	t.Run("passes a packaged user unit with a drop-in of ours in rootEnv", func(t *testing.T) {
		files := map[string]string{ulib + "pkg-x.service": pkgUnit + "Environment=LD_LIBRARY_PATH=/usr/lib/pkgx\n", uetc + "pkg-x.service.d/z.conf": "[Service]\nEnvironment=GOMEMLIMIT=1\n"}
		if err := underSystemd(t, files, ourEtc); err != nil {
			t.Fatal(err)
		}
	})
}

// TestBuiltManagerConfig: a system.conf, user.conf or .conf.d file of ours
// in a built tree has its DefaultEnvironment= and ManagerEnvironment= held
// as a root unit's Environment= (managerEnv), as image/'s copies are in the
// source scan; a package's are not held (#6002 item 2).
// REQ: KRN-2
func TestBuiltManagerConfig(t *testing.T) {
	const bad = "[Manager]\nDefaultEnvironment=BASH_ENV=/tmp/x\n"
	ourEtc := func(p string) bool { return strings.HasPrefix(p, "/etc/") || strings.HasPrefix(p, "/root/") }
	for _, p := range []string{
		"/etc/systemd/user.conf.d/z.conf",
		"/etc/systemd/system.conf.d/z.conf",
		"/etc/systemd/user.conf",
		"/root/.config/systemd/user.conf",
		"/etc/xdg/systemd/user.conf.d/z.conf",
	} {
		t.Run("refuses "+p, func(t *testing.T) {
			err := underSystemd(t, map[string]string{p: bad}, ourEtc)
			if want := strings.TrimPrefix(p, "/") + `: DefaultEnvironment=BASH_ENV=/tmp/x: variable "BASH_ENV"`; err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want a refusal with %q", err, want)
			}
		})
	}
	t.Run("refuses a manager environment of ours", func(t *testing.T) {
		err := underSystemd(t, map[string]string{"/etc/systemd/system.conf.d/z.conf": "[Manager]\nManagerEnvironment=PATH=/var/lib/x\n"}, ourEtc)
		if want := `ManagerEnvironment=PATH=/var/lib/x: path "/var/lib/x"`; err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("got %v, want a refusal with %q", err, want)
		}
	})
	t.Run("passes a package's and one of ours in rootEnv", func(t *testing.T) {
		files := map[string]string{"/usr/lib/systemd/user.conf.d/p.conf": bad, "/etc/systemd/user.conf.d/z.conf": "[Manager]\nDefaultEnvironment=GOMEMLIMIT=1\n"}
		if err := underSystemd(t, files, ourEtc); err != nil {
			t.Fatal(err)
		}
	})
}

// TestBuiltEnvFiles: a root unit of ours, the system manager's or root's
// user manager's, is held to its env file as the built tree holds it, not
// only as image/ ships it (#6002 item 3).
// REQ: KRN-2
func TestBuiltEnvFiles(t *testing.T) {
	const unit = "[Service]\nExecStart=/usr/bin/true\nEnvironmentFile=-/etc/agentos/y.env\n"
	ourEtc := func(p string) bool { return strings.HasPrefix(p, "/etc/") }
	for name, dir := range map[string]string{"a system unit": "/etc/systemd/system/", "a user unit": "/etc/systemd/user/"} {
		t.Run("refuses "+name+"'s env file in the tree", func(t *testing.T) {
			files := map[string]string{dir + "agentos-e.service": unit, "/etc/agentos/y.env": "LD_PRELOAD=/var/lib/agentos-x/x.so\n"}
			if err := underSystemd(t, files, ourEtc); err == nil || !strings.Contains(err.Error(), `/etc/agentos/y.env:1: variable "LD_PRELOAD"`) {
				t.Fatalf("got %v, want the tree's env file refused", err)
			}
		})
		t.Run("refuses "+name+"'s env file reached through a link", func(t *testing.T) {
			files := map[string]string{dir + "agentos-e.service": unit, "/etc/agentos/y.env": "-> z.env", "/etc/agentos/z.env": "BASH_ENV=/tmp/x\n"}
			if err := underSystemd(t, files, ourEtc); err == nil || !strings.Contains(err.Error(), `/etc/agentos/y.env:1: variable "BASH_ENV"`) {
				t.Fatalf("got %v, want the linked env file refused", err)
			}
		})
		t.Run("passes "+name+"'s env file in rootEnv", func(t *testing.T) {
			files := map[string]string{dir + "agentos-e.service": unit, "/etc/agentos/y.env": "GOMEMLIMIT=1\n"}
			if err := underSystemd(t, files, ourEtc); err != nil {
				t.Fatal(err)
			}
		})
	}
	// What the tree holds under /run is not there at boot (BootView).
	t.Run("refuses an env file linked under a boot mount", func(t *testing.T) {
		files := map[string]string{"/etc/systemd/system/agentos-e.service": unit, "/etc/agentos/y.env": "-> /run/agentos/y.env", "/run/agentos/y.env": "GOMEMLIMIT=1\n"}
		if err := underSystemd(t, files, ourEtc); err == nil || !strings.Contains(err.Error(), `names /etc/agentos/y.env, which no file under image/ ships`) {
			t.Fatalf("got %v, want the env file unread", err)
		}
	})
	// The tree's copy and every copy the lookup finds are read: one bad
	// copy refuses the unit.
	t.Run("reads the tree's copy beside image/'s", func(t *testing.T) {
		recs := builtRecs(t, "agentos-e.service", "", unit)
		recs.Env = map[string]string{"/etc/agentos/y.env": "BASH_ENV=/tmp/x\n"}
		good := func(string, string) (map[string]string, error) {
			return map[string]string{"image/x/etc/agentos/y.env": "GOMEMLIMIT=1\n"}, nil
		}
		if err := builtUnitsWith(recs, t.TempDir(), good); err == nil || !strings.Contains(err.Error(), `/etc/agentos/y.env:1: variable "BASH_ENV"`) {
			t.Fatalf("got %v, want the tree's copy refused", err)
		}
		recs.Env["/etc/agentos/y.env"] = "GOMEMLIMIT=1\n"
		if err := builtUnitsWith(recs, t.TempDir(), good); err != nil {
			t.Fatal(err)
		}
	})
}

// TestBuiltRecordsFields: the records' user, managers and env fields
// decode as unit_rules.py prints them.
func TestBuiltRecordsFields(t *testing.T) {
	var recs unitRecords
	b := `{"units": [{"unit": "x.service", "user": true, "files": []}], "managers": [{"path": "/etc/systemd/user.conf", "text": "[Manager]\nDefaultEnvironment=BASH_ENV=/x\n"}], "env": {"/etc/x.env": "A=1\n"}}`
	if err := json.Unmarshal([]byte(b), &recs); err != nil {
		t.Fatal(err)
	}
	if !recs.Units[0].User || len(recs.Managers) != 1 || recs.Env["/etc/x.env"] != "A=1\n" {
		t.Fatalf("decoded %+v", recs)
	}
	if err := builtUnits(recs, t.TempDir()); err == nil || !strings.Contains(err.Error(), `etc/systemd/user.conf: DefaultEnvironment=BASH_ENV=/x: variable "BASH_ENV"`) {
		t.Fatalf("got %v, want the manager file refused", err)
	}
}
