package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/ghbmrk/agentos/broker/durable"
)

// recordOwnerSIM records an adopted SIM as the owner line's in
// agentos-modem's roles file (P2-2w d2b), where the bridge reads it at
// each open. agentosd writes it, not the bridge: the bridge parses hostile
// PDUs, and its unit binds the roles directory read-only (L3 on #170).
// The file is replaced whole by rename, keeps the other keys it holds,
// and is 0644 for the bridge's user; one that is not JSON is left alone.
func recordOwnerSIM(path string) func(iccid string) error {
	return func(iccid string) error {
		roles := map[string]json.RawMessage{}
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return err
		default:
			if err := json.Unmarshal(b, &roles); err != nil {
				return errors.New("agentosd: the modem's roles file is not JSON")
			}
		}
		v, _ := json.Marshal(iccid)
		roles["owner_iccid"] = v
		out, err := json.Marshal(roles)
		if err != nil {
			return err
		}
		return durable.WriteFile(path, out, 0o644)
	}
}
