// Command agentos-hostdisk reads the host PC's disks without touching them
// (HW-8, HW-8a; package hostdisk). It runs as root only and prints only
// classes, enums, flags and sizes.
//
//	agentos-hostdisk classify NAME   udev helper: AGENTOS_DISK=drive|host|unknown
//	agentos-hostdisk list            the host disks, described, as JSON
//
// It only reads partition tables and volume signatures, opened read-only.
// The image installs it root-owned at /usr/lib/agentos/agentos-hostdisk for
// udev/61-agentos-host-disks.rules.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ghbmrk/agentos/broker/hostdisk"
)

var geteuid = os.Geteuid

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var s hostdisk.System
	root := geteuid() == 0
	switch {
	case len(args) == 2 && args[0] == "classify":
		// Always exit 0 with a value, so udev records the answer.
		if !root {
			fmt.Print("AGENTOS_DISK=unknown\n")
			return 0
		}
		fmt.Print(s.ClassifyEnv(args[1]))
		return 0
	case len(args) == 1 && args[0] == "list":
		if !root {
			fmt.Fprintln(os.Stderr, "agentos-hostdisk: root only")
			return 1
		}
		l, err := s.HostDisks()
		if err != nil {
			fmt.Fprintln(os.Stderr, "agentos-hostdisk: cannot list disks")
			return 1
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(l); err != nil {
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: agentos-hostdisk classify NAME | list")
	return 2
}
