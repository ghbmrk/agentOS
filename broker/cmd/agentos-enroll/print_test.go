package main

// REQ: CLK-1

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
	"github.com/ghbmrk/agentos/broker/tpmseal"
)

// The counter record enrollment writes to the store prints no auth value,
// in sixteen verbs, bare and in holders with unexported pointer, value and
// interface fields, while its JSON form stays the one agentos-unlock reads
// (CLK-1, DECOY-b-8, #4865).
func TestCounterRecPrintsNoAuth(t *testing.T) {
	auth := []byte("enroll-counter-auth-canary-0123")
	a := bytes.Clone(auth)
	r := counterRec{Ref: tpmseal.CounterRef{Handle: 0x01800001, Name: []byte{0, 0xb}}, Auth: new(&a)}
	secrettest.NoKey(t, [][]byte{auth}, secrettest.Holders(r)...)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ref":{"handle":25165825,"name":"AAs="},"auth":"` + b64(auth) + `"}`
	if string(b) != want {
		t.Fatalf("the record's JSON is %s, not %s", b, want)
	}
	var back counterRec
	if err := json.Unmarshal(b, &back); err != nil || !bytes.Equal(back.auth(), auth) || back.Ref.Handle != r.Ref.Handle {
		t.Fatalf("the record does not read back: %v", err)
	}
	if got := back.Counter(nil, nil).Auth.Get(); !bytes.Equal(got, auth) {
		t.Fatalf("the counter's auth is %q", got)
	}
	var none counterRec
	if err := json.Unmarshal([]byte(`{"ref":{"handle":1},"auth":null}`), &none); err != nil || none.auth() != nil {
		t.Fatalf("a null auth reads as %q: %v", none.auth(), err)
	}
}

func b64(b []byte) string {
	j, _ := json.Marshal(b)
	return string(j[1 : len(j)-1])
}
