package clock

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// chronyc is the chrony client the box ships (P2-1). The broker reaches
// chronyd's command socket as root; authdata is refused elsewhere.
const chronyc = "/usr/bin/chronyc"

// chronycTimeout bounds one chronyc call.
const chronycTimeout = 3 * time.Second

func runChronyc(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, chronycTimeout)
	defer cancel()
	return exec.CommandContext(ctx, chronyc, append([]string{"-c", "-n"}, args...)...).Output()
}

// Sync reports how chronyd's sync is verified (HW-8; security T4, T5, and
// R1 on #177): SyncedNTS when its selected source is NTS-authenticated,
// SyncedPlain when at least three unauthenticated sources are combined.
// It never reads the kernel's sync flag: chronyd keeps that set, so the
// kernel never writes the host's hardware clock (chrony/chrony.conf).
func Sync() (SyncKind, error) { return chronySync(context.Background(), runChronyc) }

// Synced reports a verified NTP sync of either kind.
func Synced() (bool, error) {
	k, err := Sync()
	return k != NotSynced, err
}

// chronySync: chronyd is synchronised at a real stratum, and its selected
// source is NTS-authenticated or at least three sources are combined.
func chronySync(ctx context.Context, run func(context.Context, ...string) ([]byte, error)) (SyncKind, error) {
	out, err := run(ctx, "tracking")
	if err != nil {
		return NotSynced, err
	}
	f := strings.Split(strings.TrimSpace(string(out)), ",")
	if len(f) < 14 {
		return NotSynced, errors.New("clock: chronyc tracking: unexpected output")
	}
	stratum, err := strconv.Atoi(f[2])
	if err != nil || stratum <= 0 || stratum >= 16 || f[13] == "Not synchronised" {
		return NotSynced, nil
	}
	out, err = run(ctx, "sources")
	if err != nil {
		return NotSynced, err
	}
	selected, combined := "", 0
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, ",")
		if len(f) < 3 || f[0] != "^" {
			continue
		}
		switch f[1] {
		case "*":
			selected = f[2]
			combined++
		case "+":
			combined++
		}
	}
	if selected == "" {
		return NotSynced, nil
	}
	plain := NotSynced
	if combined >= 3 {
		plain = SyncedPlain
	}
	out, err = run(ctx, "authdata")
	if err != nil {
		return plain, nil // NTS cannot be confirmed
	}
	// chronyd accepts no unauthenticated reply from an nts source, so the
	// mode is enough; the key ID counts key establishments from 0 (R2).
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, ",")
		if len(f) >= 2 && f[0] == selected && f[1] == "NTS" {
			return SyncedNTS, nil
		}
	}
	return plain, nil
}
