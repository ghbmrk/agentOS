package main

// The end-to-end test runs this test binary again in two roles. "unlock" is
// this command with a test pin source; it execs the binary once more as
// "kernel", which is cmd/agentos-kernel's body: its anchor (the TPM counter,
// over the connection on handoff.TPMFD) and proc.RunKernel. Run as root, the
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
	"github.com/ghbmrk/agentos/broker/cmd/agentos-kernel/anchor"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
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
		var cfg kernelRole
		if err := json.Unmarshal([]byte(os.Args[2]), &cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		keys, err := handoff.ReadKeys(os.NewFile(handoff.KeyFD, "keys"))
		var a kernel.Anchor
		if err == nil {
			a, err = anchor.Open(cfg.AnchorDir, keys, os.NewFile(handoff.TPMFD, "tpm"))
		}
		if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
			err = proc.RunKernel(ctx, cfg.Main, keys, a)
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

// kernelRole is the kernel main's configuration: its one argument after
// asKernel, as JSON.
type kernelRole struct {
	Main      proc.MainConfig
	AnchorDir string
}

// unlockRole is the unlock step's command line, and the pins a test source
// gives it.
type unlockRole struct {
	Store, TPM, Exec string
	Kernel           string // the kernel's kernelRole, as JSON: its one argument after asKernel
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

// rig is a box as enrollment leaves it: a software TPM, a sealed store
// with a tpm slot, the log's counter and the owner's anchors, the anchor's
// head file, and the ids the processes run as.
type rig struct {
	t                  *testing.T
	sw                 *swtpm.TPM
	dir, store, bin    string
	policy             *ecdsa.PrivateKey
	recovery           []byte
	anchor             []byte
	kernelUID, kernelG int
	ownerUID, meterUID int
	keys               handoff.KernelKeys // what the store derives, read through its recovery slot
}

// newRig makes the box; putAnchors false leaves the owner's anchors out of
// the store.
func newRig(t *testing.T, putAnchors bool) *rig {
	t.Helper()
	r := &rig{t: t, sw: swtpm.Start(t)}
	r.reboot()
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
	r.recovery = rec
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
	r.keys.Counter = r.enrollCounter(st)
	return r
}

// enrollCounter defines the log's counter, records it in the store and
// starts the anchor's head file, as agentos-enroll does (STO-2c).
func (r *rig) enrollCounter(st *seal.Store) handoff.Counter {
	t := r.t
	srk, err := tpmseal.Identity(r.sw.TPM())
	must(t, err)
	auth := []byte("0123456789abcdef0123456789abcdef")
	ref, err := tpmseal.DefineCounter(r.sw.TPM(), srk, st.ID(), auth)
	must(t, err)
	b, err := json.Marshal(map[string]any{"ref": json.RawMessage(ref.Marshal()), "auth": auth})
	must(t, err)
	must(t, st.Put(handoff.CounterEntry, b))
	dir := r.anchorDir()
	must(t, os.Mkdir(dir, 0o700))
	c := tpmseal.Counter{TPM: r.sw.TPM(), SRK: srk, Ref: ref, Auth: auth}
	must(t, proc.InitCounterAnchor(dir, r.mainConfig().Log, c, r.keys.Head))
	for _, p := range []string{filepath.Join(dir, "anchor"), dir} {
		must(t, os.Lchown(p, r.kernelUID, r.kernelG))
	}
	return handoff.Counter{SRK: srk, Handle: ref.Handle, Name: ref.Name, Auth: auth}
}

func (r *rig) anchorDir() string { return filepath.Join(r.dir, "k", "anchor") }

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

func (r *rig) mainConfig() proc.MainConfig {
	c := proc.MainConfig{
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

// reboot power-cycles the PC into its approved boot path. Each boot needs
// one: an unlock caps the slot until the next (#2977).
func (r *rig) reboot() {
	r.sw.Reboot()
	r.sw.Measure(9, "initrd-A")
	r.sw.Measure(12, "usrhash=aaaa quiet")
}

// boot power-cycles the PC and runs the unlock step, which becomes the
// kernel process.
func (r *rig) boot() (*exec.Cmd, *bytes.Buffer) {
	r.t.Helper()
	r.reboot()
	k, err := json.Marshal(kernelRole{Main: r.mainConfig(), AnchorDir: r.anchorDir()})
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

func (r *rig) owner() proc.Owner {
	return proc.Owner{Conn: proc.Conn{Socket: r.mainConfig().OwnerSock, UID: r.kernelUID, Timeout: 5 * time.Second}}
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

// exited waits for a kernel that should refuse to start; one still running
// after the wait fails the test.
func (r *rig) exited(cmd *exec.Cmd) error {
	r.t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		r.t.Fatal("the kernel started")
		return nil
	}
}

func (r *rig) shutdown(cmd *exec.Cmd, out *bytes.Buffer) {
	r.t.Helper()
	must(r.t, cmd.Process.Signal(syscall.SIGTERM))
	if err := cmd.Wait(); err != nil {
		r.t.Fatalf("the kernel's exit: %v; its output:\n%s", err, out)
	}
}

// STO-2, CLK-1, HW-5a, LOG-2: at boot the unlock step opens the store
// through this PC's tpm slot and becomes the kernel process under the
// kernel's own uid, which opens its counter anchor and answers on the owner
// socket. The process holds the store open nowhere, and a second boot reads
// the first boot's log and anchor, so the log key and counter it was handed
// are the store's.
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

// #2905 open point 2 (Mark, cmsg_01R91wiieBzMSvPKFsAJVvuK7gq3jqjc2vQq7vC7kHmrzJ):
// a store enrolled with no owner's anchors starts a setup-only kernel. It
// answers STATUS and the setup step and refuses everything else; it takes
// the owner's two hardware keys exactly once, each signing over this box's
// head key, and then serves normally without a restart. The window stays
// shut on the next boot, and a drive rolled back to before the setup entry
// starts no kernel, so the window never reopens.
func TestASetupOnlyKernelTakesTheOwnersKeysOnce(t *testing.T) {
	r := newRig(t, false)
	cmd, out := r.boot()
	r.up(cmd, out)
	o := r.owner()
	if err := o.Stop(); !errors.Is(err, proc.ErrSetupOnly) {
		t.Fatalf("STOP before setup: got %v, want ErrSetupOnly", err)
	}
	info, err := o.SetupInfo()
	must(t, err)
	box := r.keys.Head.Public().(ed25519.PublicKey)
	if !info.Open || !info.Box.Equal(box) {
		t.Fatalf("setup info %+v, want open over the box's head key", info)
	}
	saved := map[string][]byte{}
	for _, f := range []string{r.mainConfig().Log, filepath.Join(r.anchorDir(), "anchor")} {
		b, err := os.ReadFile(f)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		saved[f] = b
	}
	hw1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	hw2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32))
	otherBox := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, 32)).Public().(ed25519.PublicKey)
	unsigned := kernel.SignSetup(box, hw1, hw2)
	unsigned.Sigs[1] = unsigned.Sigs[0]
	for name, f := range map[string]kernel.FirstAnchors{
		"one key":            kernel.SignSetup(box, hw1),
		"the same key twice": kernel.SignSetup(box, hw1, hw1),
		"another box":        kernel.SignSetup(otherBox, hw1, hw2),
		"one key unsigned":   unsigned,
	} {
		if err := o.Setup(f); !errors.Is(err, kernel.ErrSetupKeys) {
			t.Errorf("%s: got %v, want ErrSetupKeys", name, err)
		}
	}
	must(t, o.Setup(kernel.SignSetup(box, hw1, hw2)))
	if info, err := o.SetupInfo(); err != nil || info.Open {
		t.Fatalf("setup info after setup: %+v %v, want closed", info, err)
	}
	if err := o.Setup(kernel.SignSetup(box, hw2, hw1)); !errors.Is(err, kernel.ErrSetupClosed) {
		t.Fatalf("a second setup: got %v, want ErrSetupClosed", err)
	}
	must(t, o.Stop()) // the kernel now serves as any other
	r.shutdown(cmd, out)

	cmd, out = r.boot()
	r.up(cmd, out)
	if c, err := r.owner().Changes(); err != nil || !c.Stopped {
		t.Fatalf("the second boot: %v %v, want the first boot's STOP", c, err)
	}
	if err := r.owner().Setup(kernel.SignSetup(box, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{14}, 32)), hw1)); !errors.Is(err, kernel.ErrSetupClosed) {
		t.Fatalf("setup on the second boot: got %v, want ErrSetupClosed", err)
	}
	r.shutdown(cmd, out)

	for f, b := range saved {
		if b == nil {
			must(t, os.Remove(f))
		} else {
			must(t, os.WriteFile(f, b, 0o600))
		}
	}
	cmd, out = r.boot()
	if err := r.exited(cmd); err == nil || !strings.Contains(out.String(), proc.ErrAnchorRolledBack.Error()) {
		t.Fatalf("a kernel started on a drive rolled back to before setup: %v\n%s", err, out)
	}
}

// LOG-2, STO-1: a drive rolled back, log and anchor together, to a copy
// from an earlier boot starts no kernel, since the counter has moved past
// it; the kernel says so and the copy is left as it was.
func TestARolledBackDriveStartsNoKernel(t *testing.T) {
	r := newRig(t, true)
	cmd, out := r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	files := []string{r.mainConfig().Log, filepath.Join(r.anchorDir(), "anchor")}
	saved := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		must(t, err)
		saved[f] = b
	}
	cmd, out = r.boot()
	r.up(cmd, out)
	must(t, r.owner().Stop())
	r.shutdown(cmd, out)
	for f, b := range saved {
		must(t, os.WriteFile(f, b, 0o600))
	}
	cmd, out = r.boot()
	if err := r.exited(cmd); err == nil || !strings.Contains(out.String(), proc.ErrAnchorRolledBack.Error()) {
		t.Fatalf("the kernel started on a rolled-back drive: %v\n%s", err, out)
	}
	for f, b := range saved {
		got, err := os.ReadFile(f)
		must(t, err)
		if !bytes.Equal(got, b) {
			t.Errorf("the refused kernel changed %s", f)
		}
	}
}

// STO-2a-b: a log the store's key does not open is never a fresh box. The
// kernel process refuses it, and the log is left as it was.
func TestTheKernelRefusesALogUnderAnotherKey(t *testing.T) {
	r := newRig(t, true)
	other := proc.KernelConfig{
		Log: r.mainConfig().Log, Anchor: &kernel.MemAnchor{}, Key: [32]byte{1},
		Pub: r.keys.Head.Public().(ed25519.PublicKey), Sign: r.keys.Head, Anchors: []ed25519.PublicKey{gen(1), gen(2)},
	}
	h, err := proc.OpenKernel(other, time.Now().UnixMilli())
	must(t, err)
	must(t, h.With(func(k *kernel.Kernel) error { return k.Stop(time.Now().UnixMilli()) }))
	h.Close()
	must(t, os.Chown(other.Log, r.kernelUID, r.kernelG))
	before, err := os.ReadFile(other.Log)
	must(t, err)
	cmd, out := r.boot()
	err = cmd.Wait()
	if err == nil || !strings.Contains(out.String(), proc.ErrLogKey.Error()) {
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
	r.reboot()

	// #2905 open point 2: a store with no owner's anchors yet hands over
	// none, and the kernel starts setup-only; an anchors entry that does
	// not read is refused.
	bare := newRig(t, false)
	bc := bare.role(&bare.policy.PublicKey, bare.anchor)
	b, err := unlock(bc.Config(), bc.pins)
	if err != nil {
		t.Fatalf("no owner's anchors: got %v, want a setup-only hand-off", err)
	}
	pr, pw, err := os.Pipe()
	must(t, err)
	_, err = pw.Write(b)
	must(t, err)
	pw.Close()
	clear(b)
	if k, err := handoff.ReadKeys(pr); err != nil || len(k.Anchors) != 0 {
		t.Fatalf("no owner's anchors: hand-off %v %v, want none", k.Anchors, err)
	}
	st, err := seal.Unlock(bare.store, seal.Recovery{Key: bare.recovery})
	must(t, err)
	must(t, st.Put(handoff.AnchorsEntry, []byte("short")))
	st.Close()
	if _, err := unlock(bc.Config(), bc.pins); err == nil || !strings.Contains(err.Error(), "hardware keys") {
		t.Fatalf("anchors that do not read: got %v", err)
	}

	// LOG-2: a store with no counter, or one that does not read, hands
	// the kernel nothing, so no kernel starts without its anchor.
	for name, v := range map[string][]byte{"none": nil, "garbled": []byte(`{"ref":{"handle":1},"auth":"YQ=="}`), "no auth": []byte(`{"ref":` + string(tpmseal.CounterRef{Handle: r.keys.Counter.Handle, Name: r.keys.Counter.Name}.Marshal()) + `}`)} {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		if v == nil {
			must(t, st.Delete(handoff.CounterEntry))
		} else {
			must(t, st.Put(handoff.CounterEntry, v))
		}
		st.Close()
		r.reboot()
		if _, err := unlock(c, r.role(&r.policy.PublicKey, r.anchor).pins); err == nil || !strings.Contains(err.Error(), "counter") {
			t.Errorf("%s counter: got %v", name, err)
		}
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
	want, err := handoff.KernelKeys{Log: r.keys.Log, Head: r.keys.Head, Counter: r.keys.Counter, Anchors: []ed25519.PublicKey{gen(1), gen(2)}}.Marshal()
	must(t, err)
	if !bytes.Equal(b, want) {
		t.Fatal("the hand-off is not the store's keys")
	}

	wrong := bytes.Clone(r.anchor)
	wrong[0] ^= 1
	r.reboot()
	must(t, tpmseal.FreePins(r.sw.TPM(), srk, id))
	must(t, tpmseal.WritePins(r.sw.TPM(), srk, id, tpmseal.Pins{PolicyKey: &r.policy.PublicKey, Anchor: wrong}))
	if _, err := unlock(c, storePins(r.store)); !errors.Is(err, seal.ErrTampered) {
		t.Fatalf("pins with another anchor: got %v, want ErrTampered", err)
	}
}

// K6 (#2977), CLK-1: once the unlock step has the store open, it caps the
// slot's boot path, so for the rest of the boot no connection to this TPM
// unseals it. PCRs are the TPM's, not a connection's, so this holds for the
// kernel's on handoff.TPMFD as for this test's (a software TPM serves one
// connection at a time, so it is tried once the kernel has stopped, still in
// the same boot). The next boot unlocks as before.
func TestTheSlotIsLockedAfterUnlock(t *testing.T) {
	r := newRig(t, true)
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	pins := r.role(&r.policy.PublicKey, r.anchor).pins
	b, err := unlock(c, pins)
	must(t, err)
	clear(b)
	if _, err := unlock(c, pins); !errors.Is(err, tpmseal.ErrNoPolicy) {
		t.Fatalf("a second unlock in the same boot: got %v, want ErrNoPolicy", err)
	}
	tpmOpens := func() error {
		st, err := seal.Unlock(r.store, seal.TPM{TPM: r.sw.TPM(), PolicyKey: &r.policy.PublicKey, Anchor: r.anchor})
		if err == nil {
			st.Close()
		}
		return err
	}
	cmd, out := r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	if err := tpmOpens(); !errors.Is(err, tpmseal.ErrNoPolicy) {
		t.Errorf("after the kernel's boot, the tpm slot: got %v, want ErrNoPolicy", err)
	}
	r.reboot()
	must(t, tpmOpens())
}

// A boot path the step cannot cap (here a slot over PCR 16, which locality 0
// can reset) hands the kernel nothing, though the store opened.
func TestAnUncappableSlotUnlocksNothing(t *testing.T) {
	r := newRig(t, true)
	r.sw.Measure(16, "resettable")
	p, err := tpmseal.SignCurrent(r.sw.TPM(), r.policy, []uint{16})
	must(t, err)
	st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
	must(t, err)
	_, err = st.AddSlot(seal.TPM{TPM: r.sw.TPM(), PolicyKey: &r.policy.PublicKey, Policies: []tpmseal.Policy{p}, Host: "Test PC"})
	must(t, err)
	st.Close()
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	if b, err := unlock(c, r.role(&r.policy.PublicKey, r.anchor).pins); err == nil || !strings.Contains(err.Error(), "cannot be capped") {
		clear(b)
		t.Fatalf("an uncappable slot: got %v", err)
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
