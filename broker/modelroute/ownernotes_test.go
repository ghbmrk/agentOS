package modelroute

// REQ: CRED-8, CRED-9

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// egress K6: the vault process's notices for the owner are a closed set
// of kinds with at most a count, never text, so agentosd only ever sends
// its own wording (L3 on #142). An unknown kind or an out-of-range count
// is skipped and counted as dropped, and the list is capped.
func TestOwnerNotesAreAClosedSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var body atomic.Value
	var method, urlPath atomic.Value
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method.Store(r.Method)
		urlPath.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body.Load().(string))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	v := NewVerifier(path)

	body.Store(`{"notes":[{"kind":"unlock_pending"},{"kind":"wrong_passphrase","n":3},{"kind":"say this"},{"kind":"wrong_code","n":-1},{"kind":"unlocked","n":100000}],"dropped":2}`)
	notes, dropped, err := v.OwnerNotes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if method.Load() != http.MethodPost || urlPath.Load() != "/owner-notes" {
		t.Fatalf("asked %v %v", method.Load(), urlPath.Load())
	}
	if len(notes) != 2 || notes[0] != (OwnerNote{Kind: NoteUnlockPending}) || notes[1] != (OwnerNote{Kind: NoteWrongPassphrase, N: 3}) || dropped != 5 {
		t.Fatalf("notes %+v dropped %d", notes, dropped)
	}
	many := `{"notes":[` + strings.TrimSuffix(strings.Repeat(`{"kind":"wrong_code"},`, MaxOwnerNotes+3), ",") + `]}`
	body.Store(many)
	if notes, dropped, err = v.OwnerNotes(context.Background()); err != nil || len(notes) != MaxOwnerNotes || dropped != 3 {
		t.Fatalf("over the cap: %d notes, %d dropped, %v", len(notes), dropped, err)
	}
	body.Store(`{"notes":[],"dropped":-4}`)
	if _, _, err = v.OwnerNotes(context.Background()); err == nil {
		t.Fatal("negative dropped count accepted")
	}
	body.Store(`not json`)
	if _, _, err = v.OwnerNotes(context.Background()); err == nil {
		t.Fatal("garbage accepted")
	}
	for _, k := range OwnerNoteKinds {
		if !k.Known() {
			t.Fatalf("%q not known", k)
		}
	}
	if OwnerNoteKind("unlocked ").Known() || OwnerNoteKind("").Known() {
		t.Fatal("unknown kind known")
	}
}
