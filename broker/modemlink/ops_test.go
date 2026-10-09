package modemlink_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

type ops struct{ l *modemlink.Link }

// call runs op as owner.sock would; t nil ignores errors.
func (o ops) call(t *testing.T, op string, args, out any) error {
	b, _ := json.Marshal(args)
	res, err := o.l.Ops()[op](context.Background(), sockets.Peer{Kind: "owner"}, b)
	if err != nil {
		if t != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return err
	}
	if out != nil {
		raw, _ := json.Marshal(res)
		return json.Unmarshal(raw, out)
	}
	return nil
}
