package main

// The end-to-end test runs this test binary again in two roles. "unlock" is
// this command with a test pin source; it execs the binary once more as
// "kernel", which is cmd/agentos-kernel's body (kernelproc.RunKernel) with an
// in-memory anchor, since no production anchor exists yet. Run as root, the
// kernel drops to nobody, and every uid check is the real one.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernelproc"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// REQ: STO-2, CLK-1, HW-5a

const (
	roleEnv   = "AGENTOS_UNLOCK_ROLE"
	unlockEnv = "AGENTOS_UNLOCK_CFG"
	asKernel  = "as-kernel" // the kernel main's argument from the unlock step
)

func TestMain(m *testing.M) {
	role := os.Getenv(roleEnv)
	if len(os.Args) == 3 && os.Args[1] == asKernel {
		role = "kernel" // the unlock step exec'd this, with an empty environment
	}
	switch role {
	case "":
		os.Exit(m.Run())
	case "unlock":
		var r unlockRole
		if err := json.Unmarshal([]byte(os.Getenv(unlockEnv)), &r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, unlockAndExec(r.Config(), r.pins))
		os.Exit(2)
	case "kernel":
		var cfg kernelproc.MainConfig
		if err := json.Unmarshal([]byte(os.Args[2]), &cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		keys, err := handoff.ReadKeys(os.NewFile(handoff.KeyFD, "keys"))
		if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
			err = kernelproc.RunKernel(ctx, cfg, keys, &kernel.MemAnchor{})
			stop()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(3)
}

// unlockRole is the unlock step's command line, and the pins a test source
// gives it.
type unlockRole struct {
	Store, TPM, Exec string
	Kernel           string // the kernel's kernelproc.MainConfig, as JSON: its one argument after asKernel
	UID, GID         int
	PolicyKey        []byte // PKIX
	Anchor           []byte
}

func (r unlockRole) Config() config {
	c := config{store: r.Store, tpm: r.TPM, exec: r.Exec, uid: r.UID, gid: r.GID, args: []string{asKernel, r.Kernel}}
	if os.Geteuid() != 0 {
		// A plain user cannot shed its supplementary groups. Every other
		// check of the drop still runs first; as root the real drop runs.
		c.dropTo = func(uid, gid int) error {
			if err := drop(uid, gid); !errors.Is(err, errExtraGroup) {
				return err
			}
			return nil
		}
	}
	return c
}

// extraGroups says whether this process has a supplementary group besides
// its gid.
func extraGroups() bool {
	gs, err := syscall.Getgroups()
	if err != nil {
		panic(err)
	}
	for _, g := range gs {
		if g != os.Getgid() {
			return true
		}
	}
	return false
}

func (r unlockRole) pins(transport.TPM) (*ecdsa.PublicKey, []byte, error) {
	k, err := x509.ParsePKIXPublicKey(r.PolicyKey)
	if err != nil {
		return nil, nil, err
	}
	return k.(*ecdsa.PublicKey), r.Anchor, nil
}

func gen(seed byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey)
}

var pcrs = []uint{9, 12}

// rig is a box: a software TPM, a sealed store with a tpm slot and the
// owner's anchors, and the ids the processes run as.
type rig struct {
	t                  *testing.T
	sw                 *swtpm.TPM
	dir, store, bin    string
	policy             *ecdsa.PrivateKey
	anchor             []byte
	kernelUID, kernelG int
	ownerUID, meterUID int
	keys               handoff.KernelKeys // what the store derives, read through its recovery slot
}

func newRig(t *testing.T, putAnchors bool) *rig {
	t.Helper()
	r := &rig{t: t, sw: swtpm.Start(t)}
	r.sw.Reboot()
	r.sw.Measure(9, "initrd-A")
	r.sw.Measure(12, "usrhash=aaaa quiet")
	r.kernelUID, r.kernelG, r.ownerUID, r.meterUID = os.Getuid(), os.Getgid(), os.Getuid(), os.Getuid()
	if os.Geteuid() == 0 {
		r.kernelUID, r.kernelG, r.meterUID = 65534, 65534, 65533
	}
	// Socket paths must stay short, so not t.TempDir.
	dir, err := os.MkdirTemp("", "unlock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	r.dir = dir
	must(t, os.Chmod(dir, 0o755))
	kdir := filepath.Join(dir, "k")
	must(t, os.Mkdir(kdir, 0o700))
	must(t, os.Chown(kdir, r.kernelUID, r.kernelG))
	r.bin = testBinary(t, dir)

	r.policy, err = tpmseal.NewPolicyKey()
	must(t, err)
	p, err := tpmseal.SignCurrent(r.sw.TPM(), r.policy, pcrs)
	must(t, err)
	rec := make([]byte, seal.RecoveryLen)
	rec[0] = 1
	r.store = filepath.Join(dir, "store")
	st, err := seal.Create(r.store, seal.Recovery{Key: rec})
	must(t, err)
	defer st.Close()
	_, err = st.AddSlot(seal.TPM{TPM: r.sw.TPM(), PolicyKey: &r.policy.PublicKey, Policies: []tpmseal.Policy{p}, Host: "Test PC"})
	must(t, err)
	if putAnchors {
		must(t, st.Put(handoff.AnchorsEntry, append(bytes.Clone(gen(1)), gen(2)...)))
	}
	r.anchor, err = st.Anchor()
	must(t, err)
	r.keys.Log, err = st.LogKey()
	must(t, err)
	r.keys.Head, err = st.HeadKey()
	must(t, err)
	return r
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// testBinary is this test binary where the kernel's uid can exec it.
func testBinary(t *testing.T, dir string) string {
	self, err := os.Executable()
	must(t, err)
	if os.Geteuid() != 0 {
		return self
	}
	b, err := os.ReadFile(self)
	must(t, err)
	bin := filepath.Join(dir, "bin")
	must(t, os.WriteFile(bin, b, 0o755))
	return bin
}

func (r *rig) role(pk *ecdsa.PublicKey, anchor []byte) unlockRole {
	der, err := x509.MarshalPKIXPublicKey(pk)
	must(r.t, err)
	return unlockRole{Store: r.store, TPM: r.sw.Socket(), Exec: r.bin, UID: r.kernelUID, GID: r.kernelG, PolicyKey: der, Anchor: anchor}
}

func (r *rig) mainConfig() kernelproc.MainConfig {
	c := kernelproc.MainConfig{
		Log:       filepath.Join(r.dir, "k", "log"),
		OwnerSock: filepath.Join(r.dir, "k", "owner.sock"), OwnerUID: r.ownerUID,
		MeterSock: filepath.Join(r.dir, "k", "meter.sock"), MeterUID: r.meterUID,
		Tick: 50 * time.Millisecond,
	}
	if r.kernelUID != r.ownerUID {
		c.Peers = []int{r.ownerUID, r.meterUID}
	}
	return c
}

// boot runs the unlock step, which becomes the kernel process.
func (r *rig) boot() (*exec.Cmd, *bytes.Buffer) {
	r.t.Helper()
	k, err := json.Marshal(r.mainConfig())
	must(r.t, err)
	role := r.role(&r.policy.PublicKey, r.anchor)
	role.Kernel = string(k)
	u, err := json.Marshal(role)
	must(r.t, err)
	cmd := exec.Command(r.bin, "-test.run=^$")
	cmd.Env = append(os.Environ(), roleEnv+"=unlock", unlockEnv+"="+string(u))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	must(r.t, cmd.Start())
	r.t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, &out
}

func (r *rig) owner() kernelproc.Owner {
	return kernelproc.Owner{Conn: kernelproc.Conn{Socket: r.mainConfig().OwnerSock, UID: r.kernelUID, Timeout: 5 * time.Second}}
}

// up waits for the owner socket to answer, as the kernel's uid.
func (r *rig) up(cmd *exec.Cmd, out *bytes.Buffer) {
	r.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := r.owner().Status(); err == nil {
			return
		}
		if cmd.ProcessState != nil || time.Now().After(deadline) {
			r.t.Fatalf("the kernel never answered; its output:\n%s", out)
		}
	}
}

func (r *rig) shutdown(cmd *exec.Cmd, out *bytes.Buffer) {
	r.t.Helper()
	must(r.t, cmd.Process.Signal(syscall.SIGTERM))
	if err := cmd.Wait(); err != nil {
		r.t.Fatalf("the kernel's exit: %v; its output:\n%s", err, out)
	}
}

// STO-2, CLK-1, HW-5a: at boot the unlock step opens the store through
// this PC's tpm slot and becomes the kernel process under the kernel's own
// uid, which answers on the owner socket. The process holds neither the
// store nor the TPM open, and a second boot reads the first boot's log, so
// the log key it was handed is the store's.
func TestTheUnlockStepBecomesTheKernel(t *testing.T) {
	r := newRig(t, true)
	cmd, out := r.boot()
	r.up(cmd, out)
	if os.Geteuid() == 0 {
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", cmd.Process.Pid))
		must(t, err)
		for _, fd := range fds {
			to, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", cmd.Process.Pid, fd.Name()))
			if strings.Contains(to, r.store) || strings.Contains(to, r.sw.Socket()) {
				t.Errorf("the kernel process holds %s open", to)
			}
		}
		env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", cmd.Process.Pid))
		must(t, err)
		if len(env) != 0 {
			t.Errorf("the kernel process inherited an environment: %q", env)
		}
		st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		must(t, err)
		for _, l := range strings.Split(string(st), "\n") {
			f := strings.Fields(l)
			if len(f) == 5 && (f[0] == "Uid:" || f[0] == "Gid:") && strings.Join(f[1:], " ") != "65534 65534 65534 65534" {
				t.Errorf("the kernel process runs with %s", l)
			}
			if len(f) >= 1 && f[0] == "Groups:" && len(f) > 1 && strings.Join(f[1:], " ") != "65534" {
				t.Errorf("the kernel process keeps %s", l)
			}
			if len(f) == 2 && (f[0] == "CapPrm:" || f[0] == "CapEff:" || f[0] == "CapAmb:" || f[0] == "CapInh:") && strings.Trim(f[1], "0") != "" {
				t.Errorf("the kernel process keeps %s", l)
			}
		}
	}
	must(t, r.owner().Stop())
	r.shutdown(cmd, out)

	cmd, out = r.boot()
	r.up(cmd, out)
	c, err := r.owner().Changes()
	must(t, err)
	if !c.Stopped {
		t.Fatal("the second boot lost the first boot's STOP")
	}
	r.shutdown(cmd, out)
}

// STO-2a-b: a log the store's key does not open is never a fresh box. The
// kernel process refuses it, and the log is left as it was.
func TestTheKernelRefusesALogUnderAnotherKey(t *testing.T) {
	r := newRig(t, true)
	other := kernelproc.KernelConfig{
		Log: r.mainConfig().Log, Anchor: &kernel.MemAnchor{}, Key: [32]byte{1},
		Pub: r.keys.Head.Public().(ed25519.PublicKey), Sign: r.keys.Head, Anchors: []ed25519.PublicKey{gen(1), gen(2)},
	}
	h, err := kernelproc.OpenKernel(other, time.Now().UnixMilli())
	must(t, err)
	must(t, h.With(func(k *kernel.Kernel) error { return k.Stop(time.Now().UnixMilli()) }))
	h.Close()
	must(t, os.Chown(other.Log, r.kernelUID, r.kernelG))
	before, err := os.ReadFile(other.Log)
	must(t, err)
	cmd, out := r.boot()
	err = cmd.Wait()
	if err == nil || !strings.Contains(out.String(), kernelproc.ErrLogKey.Error()) {
		t.Fatalf("the kernel took a log under another key: %v\n%s", err, out)
	}
	after, err := os.ReadFile(other.Log)
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("the refused log was changed")
	}
}

// STO-2a-k: without its pins from off the drive, with the wrong anchor, or
// with another policy key, the step unlocks nothing and so execs nothing.
// A store with no owner's anchors is refused too.
func TestTheUnlockStepFailsClosed(t *testing.T) {
	r := newRig(t, true)
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	if err := unlockAndExec(c, storePins(c.store)); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("no pins on the TPM: got %v, want ErrNoPins", err)
	}
	wrong := bytes.Clone(r.anchor)
	wrong[0] ^= 1
	if _, err := unlock(c, r.role(&r.policy.PublicKey, wrong).pins); !errors.Is(err, seal.ErrTampered) {
		t.Fatalf("wrong anchor: got %v, want ErrTampered", err)
	}
	other, err := tpmseal.NewPolicyKey()
	must(t, err)
	if _, err := unlock(c, r.role(&other.PublicKey, r.anchor).pins); !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("another policy key: got %v, want ErrNoSlot", err)
	}
	if b, err := unlock(c, r.role(&r.policy.PublicKey, r.anchor).pins); err != nil {
		t.Fatalf("the right pins: %v", err)
	} else {
		clear(b)
	}

	bare := newRig(t, false)
	if _, err := unlock(bare.role(&bare.policy.PublicKey, bare.anchor).Config(), bare.role(&bare.policy.PublicKey, bare.anchor).pins); err == nil || !strings.Contains(err.Error(), "hardware keys") {
		t.Fatalf("no owner's anchors: got %v", err)
	}
}

// The kernel never runs as root, and a step that is not root cannot become
// anyone else.
func TestTheDropRefusesRootAndChecksItTook(t *testing.T) {
	for _, ids := range [][2]int{{0, 980}, {980, 0}, {-1, 980}} {
		if err := drop(ids[0], ids[1]); err == nil {
			t.Errorf("drop to %v was allowed", ids)
		}
		if err := unlockAndExec(config{uid: ids[0], gid: ids[1]}, storePins("/nonexistent")); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("unlock for %v went as far as the pins: %v", ids, err)
		}
	}
	if os.Geteuid() != 0 {
		if err := drop(os.Getuid()+1, os.Getgid()); err == nil {
			t.Error("a step that is not root became another uid")
		}
		// A plain user keeps any supplementary groups it has, and cannot
		// drop them, so the step refuses it (CI's runner is in several).
		err := drop(os.Getuid(), os.Getgid())
		if extraGroups() {
			if !errors.Is(err, errExtraGroup) {
				t.Errorf("a plain user with supplementary groups: got %v, want errExtraGroup", err)
			}
		} else if err != nil {
			t.Errorf("already the kernel's ids: %v", err)
		}
	}
}

// STO-2c: the production source reads the policy key and anchor that
// enrollment pinned on this TPM, and unlocks with them; pins of another key
// or anchor for the same store open nothing.
func TestTheProductionPinSourceReadsTheTPM(t *testing.T) {
	r := newRig(t, true)
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	id, err := seal.ReadID(r.store)
	must(t, err)
	srk, err := tpmseal.Identity(r.sw.TPM())
	must(t, err)
	must(t, tpmseal.WritePins(r.sw.TPM(), srk, id, tpmseal.Pins{PolicyKey: &r.policy.PublicKey, Anchor: r.anchor}))
	b, err := unlock(c, storePins(r.store))
	must(t, err)
	want, err := handoff.KernelKeys{Log: r.keys.Log, Head: r.keys.Head, Anchors: []ed25519.PublicKey{gen(1), gen(2)}}.Marshal()
	must(t, err)
	if !bytes.Equal(b, want) {
		t.Fatal("the hand-off is not the store's keys")
	}

	wrong := bytes.Clone(r.anchor)
	wrong[0] ^= 1
	must(t, tpmseal.FreePins(r.sw.TPM(), srk, id))
	must(t, tpmseal.WritePins(r.sw.TPM(), srk, id, tpmseal.Pins{PolicyKey: &r.policy.PublicKey, Anchor: wrong}))
	if _, err := unlock(c, storePins(r.store)); !errors.Is(err, seal.ErrTampered) {
		t.Fatalf("pins with another anchor: got %v, want ErrTampered", err)
	}
}

func TestParse(t *testing.T) {
	c, err := parse([]string{"-store", "/s", "-uid", "980", "-gid", "981", "-exec", "/usr/lib/agentos/agentos-kernel", "--", "-log", "/l"}, io.Discard)
	if err != nil || c.uid != 980 || c.gid != 981 || c.tpm != "/dev/tpmrm0" || len(c.args) != 2 || c.args[0] != "-log" {
		t.Fatalf("parse: %+v %v", c, err)
	}
	for _, bad := range [][]string{
		{"-store", "/s", "-uid", "0", "-gid", "981", "-exec", "/k"},
		{"-store", "/s", "-uid", "980", "-gid", "981", "-exec", "k"},
		{"-uid", "980", "-gid", "981", "-exec", "/k"},
	} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad)
		}
	}
}

// A capability left after the drop is caught: root holds them all, a
// plain user none.
func TestNoCapsSeesCapabilities(t *testing.T) {
	err := noCaps()
	if os.Geteuid() == 0 && err == nil {
		t.Fatal("root's capabilities went unseen")
	}
	if os.Geteuid() != 0 && err != nil {
		t.Fatalf("a plain user: %v", err)
	}
}
