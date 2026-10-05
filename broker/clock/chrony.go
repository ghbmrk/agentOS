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

// Synced reports a verified NTP sync from chronyd (HW-8; security T4, T5).
// It never reads the kernel's sync flag: chronyd keeps that set, so the
// kernel never writes the host's hardware clock (chrony/chrony.conf).
func Synced() (bool, error) { return chronySynced(context.Background(), runChronyc) }

// chronySynced: chronyd is synchronised at a real stratum, and its selected
// source is NTS-authenticated or at least three sources are combined.
func chronySynced(ctx context.Context, run func(context.Context, ...string) ([]byte, error)) (bool, error) {
	out, err := run(ctx, "tracking")
	if err != nil {
		return false, err
	}
	f := strings.Split(strings.TrimSpace(string(out)), ",")
	if len(f) < 14 {
		return false, errors.New("clock: chronyc tracking: unexpected output")
	}
	stratum, err := strconv.Atoi(f[2])
	if err != nil || stratum <= 0 || stratum >= 16 || f[13] == "Not synchronised" {
		return false, nil
	}
	out, err = run(ctx, "sources")
	if err != nil {
		return false, err
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
		return false, nil
	}
	if combined >= 3 {
		return true, nil
	}
	out, err = run(ctx, "authdata")
	if err != nil {
		return false, nil // NTS cannot be confirmed; fewer than three sources
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, ",")
		if len(f) >= 3 && f[0] == selected && f[1] == "NTS" && f[2] != "0" {
			return true, nil
		}
	}
	return false, nil
}
