package adapter

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/verb"
)

// REQ: ADP-6
func TestADP6PrivateDerivedMayEnterPipeline(t *testing.T) {
	err := Check(Proposal{
		Name:           "mail-lite",
		PrivateDerived: true,
		Ops:            map[string]string{"list": verb.Read, "draft": verb.Draft},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// REQ: ADP-6
func TestADP6PublicWithoutCleanRoomRefused(t *testing.T) {
	err := Check(Proposal{
		Name: "mail-lite",
		Ops:  map[string]string{"list": verb.Read},
	})
	if err == nil || err.Error() != "adapter: must be private-derived or clean-room (OSS-3)" {
		t.Fatalf("got %v", err)
	}
}

// REQ: ADP-6
func TestADP6UnknownVerbRefused(t *testing.T) {
	err := Check(Proposal{
		Name:           "x",
		PrivateDerived: true,
		Ops:            map[string]string{"hack": "eval"},
	})
	if err == nil {
		t.Fatal("accepted unknown verb")
	}
}

// REQ: ADP-6
func TestADP6CleanRoomMayPublish(t *testing.T) {
	err := Check(Proposal{
		Name:      "rss",
		CleanRoom: true,
		Ops:       map[string]string{"fetch": verb.Read},
		NewGrants: []string{"net:rss.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// REQ: ADP-6
func TestADP6BothPrivateAndCleanRoomRefused(t *testing.T) {
	err := Check(Proposal{
		Name:           "x",
		PrivateDerived: true,
		CleanRoom:      true,
		Ops:            map[string]string{"a": verb.Read},
	})
	if err == nil {
		t.Fatal("accepted both")
	}
}
