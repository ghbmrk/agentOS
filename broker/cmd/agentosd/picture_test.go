package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-12, CH12-mms-c

// A picture texted to the owner line reaches the journal as a picture
// record naming only who sent it, and STATUS's note counts it.
func TestPictureJournal(t *testing.T) {
	const owner = "+15550000999"
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, map[string]journal.Executor{}, func(string) string { return daemon.Redacted })
	if err != nil {
		t.Fatal(err)
	}
	pics := &pictureJournal{}
	pics.tell(true) // before the journal opens: counted by the link only
	link := modemlink.New(modemlink.Config{Owner: owner, Picture: pics.tell})
	pics.open(eng.RecordPicture)
	call := func(op string, args any) {
		t.Helper()
		b, _ := json.Marshal(args)
		if _, err := link.Ops()[op](context.Background(), sockets.Peer{Kind: "owner"}, b); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	call(bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK})
	call(bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: owner, ID: "1", Picture: true})
	call(bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: "+15550000777", ID: "2", Picture: true})
	var got []string
	for _, r := range eng.Trail() {
		if r.Type == journal.RecPicture {
			got = append(got, r.Picture.From)
			if raw, _ := json.Marshal(r); strings.Contains(string(raw), "555") {
				t.Fatalf("a picture record names a number: %s", raw)
			}
		}
	}
	if len(got) != 2 || got[0] != journal.PictureOwner || got[1] != journal.PictureOther {
		t.Fatalf("journaled %v", got)
	}
	if n := link.PictureNote(); n != "Pictures by text: 1 from you, 1 from others. Not opened yet." {
		t.Fatalf("note %q", n)
	}
}
