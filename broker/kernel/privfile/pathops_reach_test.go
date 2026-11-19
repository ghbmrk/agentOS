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
		"a special file in a grant": {"image/mkosi/agentos-s.socket", "[Socket]\nListenSpecial=/run/agentos-x/f\n", `/run/agentos-x/f, below /run/agentos-x`},
		"a FIFO in a grant":         {"image/mkosi/agentos-s.socket", "[Socket]\nListenFIFO=/run/agentos-x/fifo\n", `/run/agentos-x/fifo, below /run/agentos-x`},
		"a USB function in a grant": {"image/mkosi/agentos-s.socket", "[Socket]\nListenUSBFunction=/run/agentos-x/usb\n", `/run/agentos-x/usb, below /run/agentos-x`},
		// An opened path stays under /run/agentos*: PID 1 hands the
		// service a root-only file's descriptor whatever its User=, or
		// makes a FIFO in /etc (#6003 Security 1).
		"a special file in /etc":        {"image/mkosi/agentos-s.socket", "[Socket]\nListenSpecial=/etc/shadow\n", `ListenSpecial=/etc/shadow: a listen path of ours lies outside /run/agentos*`},
		"a special file in credstore":   {"image/mkosi/agentos-s.socket", "[Socket]\nListenSpecial=/run/credstore/x\n", `ListenSpecial=/run/credstore/x: a listen path of ours lies outside /run/agentos*`},
		"a FIFO in /etc":                {"image/mkosi/agentos-s.socket", "[Socket]\nListenFIFO=/etc/agentos/fifo\n", `ListenFIFO=/etc/agentos/fifo: a listen path of ours lies outside /run/agentos*`},
		"a USB function in /root":       {"image/mkosi/agentos-s.socket", "[Socket]\nListenUSBFunction=/root/usb\n", `lies outside /run/agentos*`},
		"a stream below a grant":        {"image/mkosi/agentos-s.socket", "[Socket]\nListenStream=/run/agentos-x/a/s.sock\n", `/run/agentos-x/a/s.sock, below /run/agentos-x`},
		"a packet socket below a grant": {"image/mkosi/agentos-s.socket", "[Socket]\nListenSequentialPacket=/run/agentos-x/a/s.sock\n", `below /run/agentos-x`},
		"a link below a grant":          {"image/mkosi/agentos-s.socket", "[Socket]\nListenStream=/run/agentos-s/s.sock\nSymlinks=/run/agentos-x/a/l\n", `/run/agentos-x/a/l, below /run/agentos-x`},
		"a PID file another uid writes": {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nPIDFile=/run/agentos-x/pid\n", `PIDFile=/run/agentos-x/pid: the manager opens this path as root`},
		"a PID file names the fix":      {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nPIDFile=/run/agentos-x/pid\n", `drop PIDFile= and use Type=notify or Type=simple`},
		"a relative PID file":           {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nPIDFile=agentos-x/pid\n", `PIDFile=agentos-x/pid`},
		"USB descriptors":               {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nUSBFunctionDescriptors=/var/lib/agentos-x/d\n", `USBFunctionDescriptors=/var/lib/agentos-x/d`},
		"USB strings":                   {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nUSBFunctionStrings=/tmp/s\n", `USBFunctionStrings=/tmp/s`},
		// KRN-2-std-files (#4641): a file the manager opens for a unit,
		// as root before it drops to User=, is held on every unit, its
		// drop-ins too.
		"an appended output on a user unit": {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nStandardOutput=append:/var/tmp/l\n", `StandardOutput=append:/var/tmp/l: the manager opens this path as root whatever the unit's User=`},
		"an appended output in a drop-in":   {"image/mkosi/agentos-x.service.d/z.conf", "[Service]\nStandardOutput=append:/var/tmp/l\n", `path "/var/tmp/l"`},
		"a user unit's error file in /run":  {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nStandardError=file:/run/agentos-x/e\n", `path "/run/agentos-x/e"`},
		"a user unit's truncated error":     {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nStandardError=truncate:/dev/shm/e\n", `path "/dev/shm/e"`},
		"a user unit's input file":          {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nStandardInput=file:/tmp/i\n", `path "/tmp/i"`},
		"a dynamic user's output":           {"image/mkosi/agentos-p.service", "[Service]\nDynamicUser=yes\nExecStart=/bin/true\nStandardOutput=file:/var/tmp/o\n", `path "/var/tmp/o"`},
		"a user unit's env file":            {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nEnvironmentFile=-/var/lib/agentos-x/e.env\n", `path "/var/lib/agentos-x/e.env"`},
		"a user unit's credential":          {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nLoadCredential=c:/tmp/c\n", `path "/tmp/c"`},
		"a user unit's searched credential": {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nLoadCredentialEncrypted=c\n", `LoadCredentialEncrypted=c: the manager opens`},
		"a user unit's pseudo terminal":     {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nTTYPath=/dev/pts/0\n", `path "/dev/pts/0"; of /dev, a terminal the manager opens`},
		"a user unit's quoted output":       {"image/mkosi/agentos-p.service", "[Service]\nUser=agentos-p\nExecStart=/bin/true\nStandardOutput=\"file:/etc/x\"\n", `byte "\""`},
		// Item 6: of /dev, only the console, the virtual terminals and the
		// on-board serial ports (#6022 item 2), and the refusal names them.
		"a terminal in /dev/shm":  {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/shm/x\n", `path "/dev/shm/x"; of /dev, a terminal the manager opens is only /dev/console`},
		"a pseudo terminal":       {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/pts/0\n", `path "/dev/pts/0"; of /dev, a terminal the manager opens is only /dev/console, /dev/ttyN, /dev/ttySN or /dev/ttyAMAN`},
		"a USB serial terminal":   {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/ttyUSB0\n", `path "/dev/ttyUSB0"; of /dev`},
		"a serial port's link":    {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/serial0\n", `path "/dev/serial0"; of /dev`},
		"a serial port with a ..": {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/ttyS0/../../tmp/x\n", `path "/dev/ttyS0/../../tmp/x"`},
		"a console with a ..":     {"image/mkosi/agentos-t.service", "[Service]\nExecStart=/bin/true\nTTYPath=/dev/../tmp/console\n", `path "/dev/../tmp/console"`},
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
		files["image/mkosi/agentos-t3.service"] = "[Service]\nExecStart=/bin/true\nTTYPath=/dev/ttyS0\n"
		files["image/mkosi/agentos-t4.service"] = "[Service]\nExecStart=/bin/true\nTTYPath=/dev/ttyAMA0\n"
		files["image/mkosi/agentos-s.socket"] = "[Socket]\nListenStream=/run/agentos-x/s.sock\nSymlinks=/run/agentos-x/l\n"
		files["image/mkosi/agentos-p.service"] = "[Service]\nUser=agentos-p\nExecStart=/bin/true\nPIDFile=/run/systemd/agentos-p.pid\n" +
			"StandardInput=null\nStandardOutput=journal+console\nStandardError=file:/run/systemd/agentos-p.log\nEnvironmentFile=/usr/lib/agentos/p.env\nEnvironmentFile=-/etc/agentos/p.env\n" +
			"LoadCredential=c:/etc/agentos/c\nTTYPath=/dev/tty1\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
	// Item 3: the scan does not descend a link; systemd and the image
	// build do.
	// A link is resolved lexically, never on the runner. Outside every
	// overlay its target is a file beside it or beside its directory; in an
	// overlay it is only a unit linked to ../<its own name> or an instance
	// to ../<its template>, in its own overlay, answered by a file in one of
	// the image's overlays and by no directory, and in rootTrees in the
	// image (#6003 L3 and Security, #6022 item 1).
	const etc = ext + "etc/systemd/system/"
	const camCommon = "image/camnode/external/board/common/overlay/"
	const camQemu = "image/camnode/external/board/qemu/overlay/"
	const camCm4 = "image/camnode/external/board/cm4/overlay/"
	for name, c := range map[string]struct{ link, target, want string }{
		"a linked drop-in directory":                    {"image/mkosi/agentos-side.service.d", "../elsewhere", "a link to a directory"},
		"an absolute target":                            {"image/mkosi/agentos-side.service.d", "/usr/lib/agentos-l3/dropins", "not a file beside it"},
		"an absolute target that exists on the runner":  {"image/mkosi/agentos-side.service.d", "/etc", "not a file beside it"},
		"a dangling target":                             {"image/mkosi/agentos-side.service.d", "../nowhere", "no file"},
		"a link loop":                                   {"image/mkosi/agentos-side.service.d", "agentos-side.service.d", "another link"},
		"a chain of links":                              {"image/mkosi/agentos-q.service", "agentos-r.service", "another link"},
		"a target outside the repo":                     {"image/mkosi/agentos-side.service.d", "../../../outside", "outside every overlay that lands in one or outside image/"},
		"a climbing build link with a . step":           {"image/enforcer/mkosi/mkosi.configure", "../../mkosi/./agentos-z.service", "not a file beside it"},
		"a climbing build link with a .. step":          {"image/enforcer/mkosi/mkosi.configure", "../../mkosi/../go.mod", "not a file beside it"},
		"a climbing build link into an overlay":         {"image/enforcer/mkosi/mkosi.configure", "../../mkosi/mkosi.extra/x", "outside every overlay that lands in one"},
		"a climbing build link to a directory":          {"image/enforcer/mkosi/mkosi.configure", "../../elsewhere", "a link to a directory"},
		"a climbing link in an overlay":                 {etc + "agentos-y.service", "../../agentos-z.service", "not a file beside it"},
		"a climb through the runner's root":             {etc + "agentos-z.service", strings.Repeat("../", 15) + "ROOT/image/mkosi/agentos-z.service", "not a file beside it"},
		"a climb through /proc/self/root":               {etc + "agentos-z.service", strings.Repeat("../", 15) + "proc/self/root/ROOT/image/mkosi/agentos-z.service", "not a file beside it"},
		"a nested target":                               {etc + "agentos-z.service", "../../../run/agentos-x/agentos-z.service", "not a file beside it"},
		"a target in a grant":                           {ext + "var/lib/agentos-x/l.service", "../l.service", "/var/lib/agentos-x/l.service in the image, outside rootTrees"},
		"a link out of its overlay":                     {ext + "l.service", "../l.service", "leaves its overlay image/mkosi/mkosi.extra"},
		"an overlay link to another name":               {etc + "multi-user.target.wants/agentos-y.service", "../agentos-z.service", "other than a unit linked to ../agentos-y.service"},
		"an overlay unit linked to a non-unit":          {camCommon + "etc/systemd/system/agentos-z.service", "../agentos-z.txt", "other than a unit linked to ../agentos-z.service"},
		"an overlay link beside it":                     {etc + "agentos-y.service", "agentos-z.service", "other than a unit linked to ../agentos-y.service"},
		"a linked drop-in in an overlay":                {etc + "agentos-y.service.d/a.conf", "../a.conf", "other than a unit linked to ../a.conf"},
		"a linked overlay file of no unit type":         {etc + "x.target.wants/agentos-y.env", "../agentos-y.env", "other than a unit linked to ../agentos-y.env"},
		"an instance linked to another template":        {etc + "multi-user.target.wants/agentos-y@1.service", "../agentos-z@.service", "other than a unit linked to ../agentos-y@1.service"},
		"an instance linked to another instance":        {etc + "multi-user.target.wants/agentos-y@1.service", "../agentos-y@2.service", "other than a unit linked to ../agentos-y@1.service"},
		"a template linked to an instance":              {etc + "agentos-y@.service", "../agentos-y@1.service", "other than a unit linked to ../agentos-y@.service"},
		"an instance of no template linked":             {etc + "multi-user.target.wants/agentos-y.service", "../agentos-y@.service", "other than a unit linked to ../agentos-y.service"},
		"a timer linked to another name":                {etc + "timers.target.wants/agentos-y.timer", "../agentos-z.timer", "other than a unit linked to ../agentos-y.timer"},
		"a target linked out of its overlay":            {ext + "x.target", "../x.target", "leaves its overlay image/mkosi/mkosi.extra"},
		"a board link no overlay's file answers":        {camQemu + "etc/systemd/system/multi-user.target.wants/agentos-q.service", "../agentos-q.service", "no file"},
		"a board link another image answers":            {camQemu + "etc/systemd/system/multi-user.target.wants/agentos-m.service", "../agentos-m.service", "no file"},
		"a board link a directory answers":              {camQemu + "etc/systemd/system/multi-user.target.wants/agentos-d.service", "../agentos-d.service", "a link to a directory"},
		"a board link one copy of which is a directory": {camQemu + "etc/systemd/system/multi-user.target.wants/agentos-e.service", "../agentos-e.service", "a link to a directory"},
		"a link into an overlay":                        {"image/mkosi/sub/l.service", "../mkosi.extra", "a link to a directory"},
		"a build link out of image/":                    {"image/l.service", "../go.mod", "outside every overlay that lands in one or outside image/"},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := reachBase()
			files["image/elsewhere/z.conf"] = "[Service]\nEnvironment=LD_PRELOAD=/tmp/x.so\n"
			files["image/mkosi/mkosi.extra/usr/lib/agentos-l3/dropins/z.conf"] = "[Service]\nEnvironment=LD_PRELOAD=/tmp/x.so\n"
			files["image/mkosi/agentos-z.service"] = "[Service]\nUser=agentos-z\nExecStart=/bin/true\n"
			files[ext+"var/lib/agentos-x/agentos-z.service"] = "[Service]\nUser=agentos-z\nExecStart=/bin/true\n"
			files[ext+"run/agentos-x/agentos-z.service"] = "[Service]\nUser=agentos-z\nExecStart=/bin/true\n"
			files[ext+"var/lib/l.service"] = "[Service]\nUser=agentos-z\nExecStart=/bin/true\n"
			files[camCommon+"etc/systemd/agentos-z.txt"] = "[Service]\nExecStart=/bin/true\n"
			files[etc+"agentos-z@.service"] = "[Service]\nExecStart=/bin/true\n"
			files[etc+"agentos-z.timer"] = "[Timer]\nOnBootSec=1\n"
			files[ext+"etc/systemd/system/agentos-m.service"] = "[Service]\nExecStart=/bin/true\n"
			files[camCommon+"etc/systemd/system/agentos-d.service/x"] = ""
			files[camCommon+"etc/systemd/system/agentos-e.service/x"] = ""
			files[camCm4+"etc/systemd/system/agentos-e.service"] = "[Service]\nExecStart=/bin/true\n"
			files["image/mkosi/mkosi.extra/x"] = ""
			files["go.mod"] = "module x\n"
			root := fakeRepo(t, files)
			if err := os.MkdirAll(filepath.Join(filepath.Dir(root), "outside"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, c.link)), 0o755); err != nil {
				t.Fatal(err)
			}
			// A valid link, which a chain may pass through.
			if err := os.Symlink("agentos-side.service", filepath.Join(root, "image/mkosi/agentos-r.service")); err != nil {
				t.Fatal(err)
			}
			target := strings.ReplaceAll(c.target, "ROOT/", strings.TrimPrefix(root, "/")+"/")
			if err := os.Symlink(target, filepath.Join(root, c.link)); err != nil {
				t.Fatal(err)
			}
			if _, err := rootBinaries(root); err == nil || !strings.Contains(err.Error(), c.link+": ") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal of %s with %q", err, c.link, c.want)
			}
		})
	}
	// An image merges its overlays, and a later one's copy wins (camnode:
	// common, then the board's). A link in one overlay may land on another
	// overlay's copy, so that copy must be read too (#6003 L3 round 3).
	for name, c := range map[string]struct{ links [][2]string }{
		"a board's copy of a linked unit": {[][2]string{{camCommon + "etc/systemd/system/multi-user.target.wants/agentos-z.service", "../agentos-z.service"}}},
		"a board's link onward":           {[][2]string{{camCommon + "etc/systemd/system/multi-user.target.wants/agentos-z.service", "../agentos-z.service"}, {camQemu + "etc/systemd/system/agentos-z.service", "../agentos-z.service"}}},
		// A board's link may land on a copy only another overlay ships
		// (#6022 item 1); every copy of that name is still read.
		"a board link to another overlay's copy": {[][2]string{{camCm4 + "etc/systemd/system/multi-user.target.wants/agentos-z.service", "../agentos-z.service"}}},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := reachBase()
			files["image/mkosi/agentos-x.service"] = "[Service]\nUser=agentos-x\nExecStart=/bin/true\nStateDirectory=agentos-x\n"
			files[camCommon+"etc/systemd/system/agentos-z.service"] = "[Service]\nExecStart=/bin/true\n"
			evil := camQemu + "etc/systemd/system/agentos-z.service"
			if len(c.links) > 1 {
				evil = camQemu + "etc/systemd/agentos-z.service"
			}
			files[evil] = "[Service]\nExecStart=/var/lib/agentos-x/evil\n"
			root := fakeRepo(t, files)
			for _, l := range c.links {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(root, l[0])), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(l[1], filepath.Join(root, l[0])); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := rootBinaries(root); err == nil || !strings.Contains(err.Error(), "/var/lib/agentos-x") {
				t.Fatalf("got %v, want the board's copy refused for running from /var/lib/agentos-x", err)
			}
		})
	}
	// An instance linked to its template is read as the instance: each
	// overlay's copy of the template, with the instance's drop-ins (#6022
	// item 1).
	const tmplDropin = "[Service]\nExecStartPre=/var/lib/agentos-x/evil\n"
	for name, c := range map[string]struct {
		files map[string]string
		links [][2]string
	}{
		"an instance's drop-in": {
			map[string]string{camCommon + "etc/systemd/system/agentos-z@.service": "[Service]\nExecStart=/bin/true\n", camCommon + "etc/systemd/system/agentos-z@1.service.d/z.conf": tmplDropin},
			[][2]string{{camCommon + "etc/systemd/system/multi-user.target.wants/agentos-z@1.service", "../agentos-z@.service"}},
		},
		"a board's instance of a common template": {
			map[string]string{camCommon + "etc/systemd/system/agentos-z@.service": "[Service]\nExecStart=/bin/true\n", camQemu + "etc/systemd/system/agentos-z@1.service.d/z.conf": tmplDropin},
			[][2]string{{camQemu + "etc/systemd/system/multi-user.target.wants/agentos-z@1.service", "../agentos-z@.service"}},
		},
		"a board's copy of a linked template": {
			// The common copy runs as a user; the qemu copy, which wins
			// there, as root, so only the instance read of that copy
			// meets the drop-in as root's.
			map[string]string{camCommon + "etc/systemd/system/agentos-z@.service": "[Service]\nUser=agentos-z\nExecStart=/bin/true\n", camQemu + "etc/systemd/system/agentos-z@.service": "[Service]\nExecStart=/bin/true\n", camCommon + "etc/systemd/system/agentos-z@1.service.d/z.conf": tmplDropin},
			[][2]string{{camCommon + "etc/systemd/system/multi-user.target.wants/agentos-z@1.service", "../agentos-z@.service"}},
		},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := reachBase()
			files["image/mkosi/agentos-x.service"] = "[Service]\nUser=agentos-x\nExecStart=/bin/true\nStateDirectory=agentos-x\n"
			for p, text := range c.files {
				files[p] = text
			}
			if _, err := linkedRepo(t, files, c.links); err == nil || !strings.Contains(err.Error(), "/var/lib/agentos-x/evil") {
				t.Fatalf("got %v, want the instance's drop-in refused for running from /var/lib/agentos-x", err)
			}
		})
	}
	t.Run("passes the links systemctl enable makes", func(t *testing.T) {
		files := reachBase()
		files[etc+"agentos-y.service"] = "[Service]\nExecStart=/bin/true\n"
		files[etc+"agentos-y@.service"] = "[Service]\nExecStart=/bin/true\n"
		files[etc+"agentos-y.timer"] = "[Timer]\nOnBootSec=1\n"
		files[etc+"agentos-y.path"] = "[Path]\nPathExists=/run/agentos-y\n"
		files[etc+"agentos-y.target"] = "[Unit]\nDescription=y\n"
		files[camCommon+"etc/systemd/system/agentos-z.service"] = "[Service]\nExecStart=/bin/true\n"
		files[camCommon+"etc/systemd/system/agentos-z@.service"] = "[Service]\nExecStart=/bin/true\n"
		links := [][2]string{
			{etc + "multi-user.target.wants/agentos-y@1.service", "../agentos-y@.service"},
			{etc + "multi-user.target.wants/agentos-y@two.service", "../agentos-y@.service"},
			{etc + "timers.target.wants/agentos-y.timer", "../agentos-y.timer"},
			{etc + "paths.target.wants/agentos-y.path", "../agentos-y.path"},
			{etc + "multi-user.target.wants/agentos-y.target", "../agentos-y.target"},
			{etc + "agentos-y.target.wants/agentos-y.service", "../agentos-y.service"},
			{camQemu + "etc/systemd/system/multi-user.target.wants/agentos-z.service", "../agentos-z.service"},
			{camCm4 + "etc/systemd/system/multi-user.target.wants/agentos-z@1.service", "../agentos-z@.service"},
		}
		if _, err := linkedRepo(t, files, links); err != nil {
			t.Fatal(err)
		}
	})
	// A build script linked up the tree (IMG-keyring-spikes: each mkosi
	// tree's mkosi.configure names the one keyring check) is a build input.
	t.Run("passes a build input linked up the tree", func(t *testing.T) {
		files := reachBase()
		files["image/debian-archive-keyring.sh"] = "#!/bin/sh\n"
		links := [][2]string{{"image/enforcer/mkosi/mkosi.configure", "../../debian-archive-keyring.sh"}}
		if _, err := linkedRepo(t, files, links); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("passes a linked unit in an overlay", func(t *testing.T) {
		files := reachBase()
		files[etc+"agentos-y.service"] = "[Service]\nExecStart=/bin/true\n"
		root := fakeRepo(t, files)
		if err := os.MkdirAll(filepath.Join(root, etc, "multi-user.target.wants"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../agentos-y.service", filepath.Join(root, etc, "multi-user.target.wants/agentos-y.service")); err != nil {
			t.Fatal(err)
		}
		if _, err := rootBinaries(root); err != nil {
			t.Fatal(err)
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

// linkedRepo runs rootBinaries on a fake repository of files with each
// link (path, target) added.
func linkedRepo(t *testing.T, files map[string]string, links [][2]string) ([]string, error) {
	t.Helper()
	root := fakeRepo(t, files)
	for _, l := range links {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, l[0])), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(l[1], filepath.Join(root, l[0])); err != nil {
			t.Fatal(err)
		}
	}
	return rootBinaries(root)
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
		"a FIFO in a package's grant":   {"[Socket]\nListenFIFO=/run/agentos-g/f\n", `/run/agentos-g/f, below /run/agentos-g`},
		"a FIFO in a package's tree":    {"[Socket]\nListenFIFO=/run/systemd/pkg-g/f\n", `ListenFIFO=/run/systemd/pkg-g/f: a listen path of ours lies outside /run/agentos*`},
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

// TestImageOverlaysAreListed: every overlay directory under image/ is one
// imageOverlays lists, so a new image or board cannot ship files the env
// lookup and the link rule do not place (#6003).
func TestImageOverlaysAreListed(t *testing.T) {
	root := repoRoot(t)
	listed := map[string]bool{}
	for _, r := range allOverlays() {
		listed[r] = true
		if st, err := os.Stat(filepath.Join(root, r)); err != nil || !st.IsDir() {
			t.Errorf("listed overlay %s is not a directory: %v", r, err)
		}
	}
	err := filepath.WalkDir(filepath.Join(root, "image"), func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || (d.Name() != "overlay" && d.Name() != "mkosi.extra" && d.Name() != "mkosi.skeleton" && d.Name() != "rootfs-overlay") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if !listed[filepath.ToSlash(rel)] {
			t.Errorf("%s is an overlay imageOverlays does not list", filepath.ToSlash(rel))
		}
		return filepath.SkipDir
	})
	if err != nil {
		t.Fatal(err)
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
		// A user unit's env file is read as root too, so it sits in a root
		// tree (#4641), but what it holds is its user's.
		files["image/mkosi/agentos-x.service"] = "[Service]\nUser=agentos-x\nExecStart=/bin/true\nEnvironmentFile=-/etc/agentos/x.env\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
	// Only an overlay's copy is shipped: one elsewhere under image/ (an
	// example, a doc) is not read as the file (#6003 Security 2).
	// Only a copy in an overlay root of the unit's own image is shipped:
	// one elsewhere under image/ (an example, a doc, a directory merely
	// named overlay, another image's overlay) is not (#6003 Security 2).
	for _, copy := range []string{
		"image/docs/examples/etc/agentos/q.env",
		"image/docs/overlay/etc/agentos/q.env",
		"image/docs/mkosi.extra/etc/agentos/q.env",
		"image/enforcer/mkosi/mkosi.extra/etc/agentos/q.env",
		"image/mkosi/mkosi.extra/x/etc/agentos/q.env",
		"image/camnode/external/board/common/overlay/etc/agentos/q.env",
	} {
		t.Run("refuses a copy at "+copy, func(t *testing.T) {
			files := reachBase()
			files[unit] = "[Service]\nExecStart=/bin/true\nEnvironmentFile=/etc/agentos/q.env\n"
			files[copy] = "GOMEMLIMIT=1\n"
			if _, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), "/etc/agentos/q.env, which no file under image/ ships") {
				t.Fatalf("got %v, want the file unshipped", err)
			}
		})
	}
	t.Run("reads a camnode unit's copy from its own overlay", func(t *testing.T) {
		files := reachBase()
		files["image/camnode/external/board/common/overlay/etc/systemd/system/agentos-cam.service"] = "[Service]\nExecStart=/bin/true\nEnvironmentFile=/etc/agentos/q.env\n"
		files["image/camnode/external/board/qemu/overlay/etc/agentos/q.env"] = "LD_PRELOAD=/tmp/x.so\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err == nil || !strings.Contains(err.Error(), `variable "LD_PRELOAD"`) {
			t.Fatalf("got %v, want the board overlay's copy read", err)
		}
	})
	t.Run("refuses a linked env file", func(t *testing.T) {
		files := reachBase()
		files[unit] = root
		files[filepath.Dir(env)+"/z.env"] = "GOMEMLIMIT=1\n"
		r := fakeRepo(t, files)
		if err := os.Symlink("z.env", filepath.Join(r, env)); err != nil {
			t.Fatal(err)
		}
		// The link rule refuses it before the env lookup would read it.
		if _, err := rootBinaries(r); err == nil || !strings.Contains(err.Error(), env+": a link in an overlay") {
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
		bad := func(string, string) (map[string]string, error) {
			return map[string]string{"image/x/etc/agentos/y.env": "LD_PRELOAD=/tmp/x.so\n"}, nil
		}
		if err := builtUnitsWith(recs, t.TempDir(), bad); err == nil || !strings.Contains(err.Error(), `variable "LD_PRELOAD"`) {
			t.Fatalf("a preload: got %v", err)
		}
		good := func(string, string) (map[string]string, error) {
			return map[string]string{"image/x/etc/agentos/y.env": "GOMEMLIMIT=1\n"}, nil
		}
		if err := builtUnitsWith(recs, t.TempDir(), good); err != nil {
			t.Fatal(err)
		}
	})
}

// TestUserUnitOpens: a unit with no root command still has the manager
// open, mount or join paths as root for it (userOpens), each held out of
// the world trees and out of every grant, a unit's or a tmpfiles line's
// (#6143); and PermissionsStartOnly= and AmbientCapabilities= read as root
// past a closed set (#4641 R-c and the capability item).
// REQ: KRN-2
func TestUserUnitOpens(t *testing.T) {
	const unit = "image/mkosi/agentos-p.service"
	const head = "[Service]\nUser=agentos-p\nExecStart=/bin/true\n"
	base := reachBase() // agentos-x's RuntimeDirectory= grants /run/agentos-x
	base["image/mkosi/mkosi.extra/usr/lib/tmpfiles.d/agentos-q.conf"] = "d /run/agentos-q 0700 agentos-q agentos-q -\n"
	for name, c := range map[string]struct{ path, text, want string }{
		"an opened file below a grant":        {unit, head + "OpenFile=/run/agentos-x/s:s\n", `path "/run/agentos-x/s" is at or below /run/agentos-x`},
		"an opened file at a grant":           {unit, head + "OpenFile=/run/agentos-x\n", `path "/run/agentos-x" is at or below /run/agentos-x`},
		"an opened file through /var/run":     {unit, head + "OpenFile=/var/run/agentos-x/s\n", `is at or below /run/agentos-x`},
		"an opened file in a tmpfiles grant":  {unit, head + "OpenFile=/run/agentos-q/s:s:read-only\n", `is at or below /run/agentos-q`},
		"an opened file in the unit's grant":  {"image/mkosi/agentos-x.service.d/z.conf", "[Service]\nOpenFile=/run/agentos-x/k.sock\n", `is at or below /run/agentos-x`},
		"an opened file in /tmp":              {unit, head + "OpenFile=/tmp/s\n", `path "/tmp/s" is in /tmp`},
		"an opened file in /run/lock":         {unit, head + "OpenFile=/var/lock/s\n", `is in /run/lock`},
		"an opened file in /dev/shm":          {unit, head + "OpenFile=/run/shm/s\n", `is in /dev/shm`},
		"an opened file through /dev/fd":      {unit, head + "OpenFile=/dev/fd/3\n", `is in /dev/fd`},
		"a relative opened file":              {unit, head + "OpenFile=run/agentos-x/s\n", `want an absolute path`},
		"an opened file with a ..":            {unit, head + "OpenFile=/etc/../run/agentos-x/s\n", `want an absolute path with no ..`},
		"a quoted opened file":                {unit, head + "OpenFile=\"/etc/x\"\n", `byte "\""`},
		"an opened file with a specifier":     {unit, head + "OpenFile=/run/%i/s\n", `byte "%"`},
		"a bind from a grant":                 {unit, head + "BindPaths=/run/agentos-x/d:/srv/d\n", `BindPaths=/run/agentos-x/d:/srv/d: path "/run/agentos-x/d"`},
		"a read-only bind from a grant":       {unit, head + "BindReadOnlyPaths=/etc -/run/agentos-x/d\n", `path "/run/agentos-x/d"`},
		"a root directory in a grant":         {unit, head + "RootDirectory=/run/agentos-x/r\n", `path "/run/agentos-x/r"`},
		"a root image in /var/tmp":            {unit, head + "RootImage=/var/tmp/x.img\n", `path "/var/tmp/x.img" is in /var/tmp`},
		"a mount image in a grant":            {unit, head + "MountImages=-/run/agentos-q/x.img:/srv/x:ro\n", `path "/run/agentos-q/x.img"`},
		"an extension directory in a grant":   {unit, head + "ExtensionDirectories=-/run/agentos-x/e\n", `path "/run/agentos-x/e"`},
		"an extension image in /tmp":          {unit, head + "ExtensionImages=/tmp/e.raw\n", `path "/tmp/e.raw"`},
		"a network namespace in a grant":      {unit, head + "NetworkNamespacePath=/run/agentos-x/net\n", `path "/run/agentos-x/net"`},
		"an IPC namespace in /tmp":            {unit, head + "IPCNamespacePath=/tmp/ipc\n", `path "/tmp/ipc"`},
		"a BPF program in a grant":            {unit, head + "BPFProgram=egress:/run/agentos-x/p\n", `path "/run/agentos-x/p"`},
		"an ingress filter in a grant":        {unit, head + "IPIngressFilterPath=/run/agentos-x/i\n", `path "/run/agentos-x/i"`},
		"an egress filter in /dev/shm":        {unit, head + "IPEgressFilterPath=/dev/shm/e\n", `path "/dev/shm/e"`},
		"a dynamic user's opened file":        {unit, "[Service]\nDynamicUser=yes\nExecStart=/bin/true\nOpenFile=/tmp/s\n", `path "/tmp/s" is in /tmp`},
		"start-only permissions spelt t":      {unit, head + "PermissionsStartOnly=t\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"start-only permissions spelt y":      {unit, head + "PermissionsStartOnly=y\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"start-only permissions misspelt":     {unit, head + "PermissionsStartOnly=nope\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"start-only permissions in a drop-in": {"image/mkosi/agentos-x.service.d/z.conf", "[Service]\nPermissionsStartOnly=on\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"an ambient override of file modes":   {unit, head + "AmbientCapabilities=CAP_DAC_OVERRIDE\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"an ambient setuid in lower case":     {unit, head + "AmbientCapabilities=cap_net_raw cap_setuid\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"an ambient capability by number":     {unit, head + "AmbientCapabilities=7\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"an inverted ambient list":            {unit, head + "AmbientCapabilities=~CAP_NET_RAW\nWorkingDirectory=/tmp\n", `path "/tmp"`},
		"an ambient reboot on the core":       {unit, head + "AmbientCapabilities=CAP_SYS_BOOT\nWorkingDirectory=/tmp\n", `path "/tmp"`},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			files := clone(base)
			files[c.path] = c.text
			_, err := rootBinaries(fakeRepo(t, files))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
		})
	}
	for name, text := range map[string]string{
		// The keepers' shape: the kernel's socket, outside every grant.
		"a keeper's key socket":          head + "OpenFile=/run/agentos-kernel/key-mail.sock:clerk-key\n",
		"an opened file in a root tree":  head + "OpenFile=/etc/agentos/f:f:read-only\n",
		"a bind beside a grant":          head + "BindReadOnlyPaths=-/var/lib/agentos/modem /run/agentos-xy\nBindPaths=/var/lib/agentos-x:/srv/x\n",
		"a grant's own bind destination": head + "BindPaths=/var/lib/agentos/d:/run/agentos-x/d\n",
		"an empty reset":                 head + "OpenFile=\nBindPaths=\n",
		"start-only permissions off":     head + "PermissionsStartOnly=OFF\nPermissionsStartOnly=f\nPermissionsStartOnly=0\nWorkingDirectory=/tmp\n",
		"network ambient capabilities":   head + "AmbientCapabilities=CAP_NET_BIND_SERVICE cap_net_raw\nAmbientCapabilities=CAP_WAKE_ALARM CAP_BLOCK_SUSPEND\nAmbientCapabilities=\nWorkingDirectory=/tmp\n",
	} {
		t.Run("passes "+name, func(t *testing.T) {
			files := clone(base)
			files[unit] = text
			if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
				t.Fatal(err)
			}
		})
	}
	// The camera node's kernel has no kexec, so its reboot capability
	// reads as non-root there alone (test_image_camnode pins both off).
	t.Run("passes the camera node's ambient reboot", func(t *testing.T) {
		files := clone(base)
		files["image/camnode/external/board/common/overlay/etc/systemd/system/agentos-c.service"] = head + "AmbientCapabilities=cap_sys_boot\nWorkingDirectory=/tmp\n"
		if _, err := rootBinaries(fakeRepo(t, files)); err != nil {
			t.Fatal(err)
		}
	})
	// A built tree: our unit's opened file in a package's grant.
	t.Run("refuses a built unit's opened file in a package's grant", func(t *testing.T) {
		pkg := map[string]any{"unit": "pkg-g.service", "files": []any{map[string]any{"path": "/usr/lib/systemd/system/pkg-g.service", "ours": false,
			"text": "[Service]\nUser=pkg\nExecStart=/usr/bin/pkg\nRuntimeDirectory=pkg-g\n"}}}
		ours := map[string]any{"unit": "agentos-o.service", "files": []any{map[string]any{"path": "/usr/lib/systemd/system/agentos-o.service", "ours": true,
			"text": "[Service]\nUser=agentos-o\nExecStart=/bin/true\nOpenFile=/run/pkg-g/s\n"}}}
		b, err := json.Marshal(map[string]any{"units": []any{pkg, ours}})
		if err != nil {
			t.Fatal(err)
		}
		var recs unitRecords
		if err := json.Unmarshal(b, &recs); err != nil {
			t.Fatal(err)
		}
		if err := builtUnits(recs, t.TempDir()); err == nil || !strings.Contains(err.Error(), `path "/run/pkg-g/s" is at or below /run/pkg-g`) {
			t.Fatalf("got %v, want the package's grant held", err)
		}
	})
}
