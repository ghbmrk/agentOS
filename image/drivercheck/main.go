// Command drivercheck is the image build's devslot.Check (DEVSLOT-image, DEV-1, DEV-4). It reads
// one driver's entry from standard input, {"declaration": ..., "classes": {operation: class}},
// refuses a declaration the slot would refuse or a class row that is not one DEV-4 class per
// declared operation, and prints the declaration in canonical form (encoding/json of
// devslot.Declaration), which the image's drivers.json carries and the host compares byte for byte.
// It runs on the build host only and ships in no image. It is one file with no module of its own:
// image/build.sh builds it inside the broker's module (go build ../image/drivercheck/main.go), so
// it links this checkout's devslot.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// maxEntry bounds what is read: a declaration is a few kilobytes.
const maxEntry = 1 << 20

// pins are stand-ins: a declaration names no device, so the build checks it against a pin of
// the right form for its link kind; the host checks the real pin at connection (DEV-3).
var pins = map[devslot.LinkKind]devslot.Pin{
	devslot.GATT: {Address: "00:00:00:00:00:00"},
	devslot.TCP:  {Host: netip.MustParseAddr("192.168.0.1"), Key: [32]byte{1}},
}

type entry struct {
	Declaration json.RawMessage
	Classes     map[string]key.Verb
}

func strict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("data after the value")
	}
	return nil
}

func check(in []byte) ([]byte, error) {
	var e entry
	if err := strict(in, &e); err != nil {
		return nil, fmt.Errorf("entry: %w", err)
	}
	var d devslot.Declaration
	if err := strict(e.Declaration, &d); err != nil {
		return nil, fmt.Errorf("declaration: %w", err)
	}
	if err := devslot.Check(d, pins[d.Link]); err != nil {
		return nil, err
	}
	// The class row names one class per declared operation, and each is a DEV-4 verb: the
	// declaration with the row's classes in place of its verbs passes the same Check.
	if len(e.Classes) != len(d.Operations) {
		return nil, errors.New("the class row names one class for each declared operation and no other")
	}
	c := d
	c.Operations = make([]devslot.Operation, len(d.Operations))
	for i, o := range d.Operations {
		v, ok := e.Classes[o.Name]
		if !ok {
			return nil, fmt.Errorf("the class row has no class for operation %s", o.Name)
		}
		o.Verb = v
		c.Operations[i] = o
	}
	if err := devslot.Check(c, pins[c.Link]); err != nil {
		return nil, fmt.Errorf("class row: %w", err)
	}
	return json.Marshal(d)
}

func main() {
	in, err := io.ReadAll(io.LimitReader(os.Stdin, maxEntry+1))
	if err == nil && len(in) > maxEntry {
		err = errors.New("entry over 1 MiB")
	}
	var out []byte
	if err == nil {
		out, err = check(in)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "drivercheck:", err)
		os.Exit(1)
	}
	os.Stdout.Write(append(out, '\n'))
}
