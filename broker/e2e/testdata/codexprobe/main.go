// Command codexprobe is the tool the containment run (S8-W1-contain,
// #1720) has the Codex CLI start in a provider worker. It tries what a
// hostile tool would: the forwarder's loopback port, the route socket, the
// placeholder login and writes outside its workspace. It prints one JSON
// line starting {"tcp" with a boolean per attempt and the error each
// denied attempt met. It never prints what it read.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	forwarder = "127.0.0.1:18432"
	route     = "/run/agentos/route.sock"
	codexHome = "/var/lib/agentos-codex"
	work      = "/var/lib/agentos-work"
)

func main() {
	got := map[string]any{}
	errs := map[string]string{}
	try := func(name string, err error) {
		got[name] = err == nil
		if err != nil {
			errs[name] = err.Error()
		}
	}
	dial := func(network, addr string) error {
		c, err := net.DialTimeout(network, addr, 3*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	write := func(dir string) error {
		p := filepath.Join(dir, fmt.Sprintf("agentos-probe-%d", os.Getpid()))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			return err
		}
		return os.Remove(p)
	}
	try("tcp", dial("tcp", forwarder))
	try("unix", dial("unix", route))
	_, err := os.ReadFile(filepath.Join(codexHome, "auth.json"))
	try("auth", err)
	_, err = os.ReadDir(codexHome)
	try("codex_home_list", err)
	try("root_write", write("/"))
	try("codex_home_write", write(codexHome))
	try("slash_tmp_write", write("/tmp"))
	try("work_write", write(work))
	got["errors"] = errs
	// The sandbox the CLI put the tool in, as the guest kernel reports it.
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && (k == "Seccomp" || k == "NoNewPrivs") {
				got[strings.ToLower(k)] = strings.TrimSpace(v)
			}
		}
	}
	for _, ns := range []string{"net", "mnt", "user", "pid"} {
		if l, err := os.Readlink("/proc/self/ns/" + ns); err == nil {
			got["ns_"+ns] = l
		}
	}
	// "tcp" first, so a reader finds the line by its prefix.
	tcp := got["tcp"]
	delete(got, "tcp")
	b, _ := json.Marshal(got)
	fmt.Printf("{\"tcp\":%v,%s\n", tcp, b[1:])
}
