package main

import (
	"debug/buildinfo"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
)

// e2eTag is the build tag of the vault process the e2e boot runs
// (image/e2e/agentos-egress.conf, ASSUMPTIONS E10).
const e2eTag = "agentos_e2e"

// serveStub serves the Codex plan stub where the agentos_e2e vault process
// dials it: a root-owned directory anyone may search, holding a socket only
// the vault's user may open.
func serveStub() (*codexstub.Stub, error) {
	u, err := user.Lookup("agentos-egress")
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(codexstub.Socket)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	os.Remove(codexstub.Socket)
	ln, err := net.Listen("unix", codexstub.Socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(codexstub.Socket, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	if err := os.Chown(codexstub.Socket, uid, -1); err != nil {
		ln.Close()
		return nil, err
	}
	s := codexstub.New()
	go http.Serve(ln, s)
	return s, nil
}

// checkVaultBuild fails unless the running vault process is the agentos_e2e
// build, so a run whose drop-in did not apply cannot pass on the image's
// own binary, whose plan route has no stub to reach.
func checkVaultBuild() error {
	out, err := command("systemctl", "show", "-p", "MainPID", "--value", "agentos-egress.service").Output()
	if err != nil {
		return fmt.Errorf("vault pid: %v", err)
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return fmt.Errorf("vault process not running")
	}
	bi, err := buildinfo.ReadFile("/proc/" + pid + "/exe")
	if err != nil {
		return fmt.Errorf("vault build info: %v", err)
	}
	if !hasTag(bi, e2eTag) {
		return fmt.Errorf("vault process is not the %s build", e2eTag)
	}
	return nil
}

// hasTag reports whether bi was built with tag among its -tags.
func hasTag(bi *debug.BuildInfo, tag string) bool {
	for _, s := range bi.Settings {
		if s.Key == "-tags" {
			for _, t := range strings.Split(s.Value, ",") {
				if t == tag {
					return true
				}
			}
		}
	}
	return false
}
