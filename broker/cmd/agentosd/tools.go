package main

import (
	"context"
	"encoding/json"

	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/workers"
)

// registeredTools is every broker tool set agentosd serves on a guest
// socket beside the effect tools: the question tools, the recall tools,
// and the worker tools when an image is registered (wt not nil). Their
// errors reach the guest only through the guest plane's filter (guesterr,
// SR2-3g). managed_tree went with the learning loop (MIG-4-untrusted-learn):
// nothing adopts a tree for the agent any more.
func registeredTools(qs *questions, recall guest.Tools, wt *workers.Tools) toolSet {
	tools := toolSet{qs.tools(), recall}
	if wt != nil {
		tools = append(tools, wt)
	}
	return tools
}

// toolSet serves several broker tool sets on one guest socket (guest
// G15), in order; a nil entry is skipped.
type toolSet []guest.Tools

func (s toolSet) List() []map[string]any {
	var out []map[string]any
	for _, t := range s {
		if t != nil {
			out = append(out, t.List()...)
		}
	}
	return out
}

func (s toolSet) Call(ctx context.Context, machine, lineage, name string, args json.RawMessage) (string, bool, error) {
	for _, t := range s {
		if t == nil {
			continue
		}
		if text, ok, err := t.Call(ctx, machine, lineage, name, args); ok {
			return text, ok, err
		}
	}
	return "", false, nil
}
