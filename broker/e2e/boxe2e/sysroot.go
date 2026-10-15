package main

import (
	"os"
	"path/filepath"
)

// buildSysroot lays out, under root, the sysfs entries and device node of
// one SIM7600G-H AT port (USB vendor 1e0e, interface 02), with the node a
// link to slave, the simulated modem's pseudo-terminal. agentos-modem's
// -sys-root then finds it through at.Discover, as it finds the real modem
// under /. A rebuild replaces what is there.
func buildSysroot(root, slave string) error {
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	dev := filepath.Join(root, "sys/devices/pci0000:00/usb1/1-2")
	intf := filepath.Join(dev, "1-2:1.2")
	for _, d := range []string{filepath.Join(intf, "ttyUSB2"), filepath.Join(root, "sys/bus/usb-serial/devices"), filepath.Join(root, "dev")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for path, v := range map[string]string{filepath.Join(dev, "idVendor"): "1e0e\n", filepath.Join(intf, "bInterfaceNumber"): "02\n"} {
		if err := os.WriteFile(path, []byte(v), 0o644); err != nil {
			return err
		}
	}
	if err := os.Symlink("../../../devices/pci0000:00/usb1/1-2/1-2:1.2/ttyUSB2", filepath.Join(root, "sys/bus/usb-serial/devices/ttyUSB2")); err != nil {
		return err
	}
	return os.Symlink(slave, filepath.Join(root, "dev/ttyUSB2"))
}
