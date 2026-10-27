package localsrv

// REQ: BAK-1, BAK-2, CH-7

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// fakeBackups records what reached the owner side.
type fakeBackups struct {
	calls []string
	err   error
}

func (f *fakeBackups) List(context.Context) (localapi.BackupChoice, error) {
	f.calls = append(f.calls, "list")
	return localapi.BackupChoice{Lines: []string{"Backups: none."}}, f.err
}

func (f *fakeBackups) Begin(_ context.Context, p localapi.BackupPlace) (localapi.BackupBegun, error) {
	f.calls = append(f.calls, "begin "+p.Name)
	return localapi.BackupBegun{N: 1, Challenge: make([]byte, 32)}, f.err
}

func (f *fakeBackups) Add(_ context.Context, p localapi.BackupPlace, n int, ad, cd, sig []byte) error {
	f.calls = append(f.calls, fmt.Sprintf("add %s %d %x %x %x", p.Name, n, ad, cd, sig))
	return f.err
}

func (f *fakeBackups) Remove(_ context.Context, name string) error {
	f.calls = append(f.calls, "remove "+name)
	return f.err
}

func backupRig(t *testing.T) (*rig, *fakeBackups) {
	r, _ := passkeyRig(t)
	f := &fakeBackups{}
	r.srv.cfg.Backups = f
	r.ops = r.srv.Ops()
	return r, f
}

var testPlace = localapi.BackupPlace{Name: "drive2", Kind: localapi.BackupKindDir, Locator: "/media/drive2/agentos"}

func backupArgs(tok string) map[string]any {
	return map[string]any{
		localapi.OpBackups:      localapi.Auth{Token: tok},
		localapi.OpBackupBegin:  localapi.BackupBegin{Token: tok, Place: testPlace},
		localapi.OpBackupAdd:    localapi.BackupAdd{Token: tok, Place: testPlace, N: 1, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{2}, Signature: []byte{3}},
		localapi.OpBackupRemove: localapi.BackupRemove{Token: tok, Name: "drive2"},
	}
}

// Every backup op is refused without a live session and reaches nothing;
// with one, each reaches the owner side.
func TestBackupOpsNeedALiveSession(t *testing.T) {
	r, f := backupRig(t)
	for _, op := range localapi.BackupOps {
		for _, tok := range []string{"", strings.Repeat("0", 2*localapi.TokenBytes), "made-up"} {
			if _, err := r.call(op, backupArgs(tok)[op]); code(err) != localapi.ErrUnauthorized {
				t.Errorf("%s with %q: %v", op, tok, err)
			}
		}
		if _, err := r.raw(op, `{}`); code(err) != localapi.ErrUnauthorized {
			t.Errorf("%s with no args: %v", op, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	tok := r.signIn()
	for _, op := range localapi.BackupOps {
		if _, err := r.call(op, backupArgs(tok)[op]); err != nil {
			t.Errorf("%s: %v", op, err)
		}
	}
	want := []string{"list", "begin drive2", "add drive2 1 01 02 03", "remove drive2"}
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("calls %v", f.calls)
	}
}

// The frames are bounded before anything reaches the owner side, and
// begins are counted.
func TestBackupFramesAreBounded(t *testing.T) {
	r, f := backupRig(t)
	tok := r.signIn()
	big := make([]byte, localapi.MaxPasskeyAssertion+1)
	with := func(edit func(*localapi.BackupPlace)) localapi.BackupPlace {
		p := testPlace
		edit(&p)
		return p
	}
	add := func(p localapi.BackupPlace, n int, ad, cd, sig []byte) localapi.BackupAdd {
		return localapi.BackupAdd{Token: tok, Place: p, N: n, AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
	}
	one := []byte{1}
	for i, c := range []struct {
		op   string
		args any
	}{
		{localapi.OpBackupBegin, localapi.BackupBegin{Token: tok, Place: with(func(p *localapi.BackupPlace) { p.Kind = "s3" })}},
		{localapi.OpBackupBegin, localapi.BackupBegin{Token: tok, Place: with(func(p *localapi.BackupPlace) { p.Name = "" })}},
		{localapi.OpBackupBegin, localapi.BackupBegin{Token: tok, Place: with(func(p *localapi.BackupPlace) { p.Name = strings.Repeat("a", 65) })}},
		{localapi.OpBackupBegin, localapi.BackupBegin{Token: tok, Place: with(func(p *localapi.BackupPlace) { p.Locator = "" })}},
		{localapi.OpBackupBegin, localapi.BackupBegin{Token: tok, Place: with(func(p *localapi.BackupPlace) { p.Locator = "/" + strings.Repeat("a", 1024) })}},
		{localapi.OpBackupBegin, localapi.BackupBegin{Token: tok, Place: with(func(p *localapi.BackupPlace) { p.Newest = 1 })}},
		{localapi.OpBackupAdd, add(testPlace, -1, one, one, one)},
		{localapi.OpBackupAdd, add(testPlace, localapi.MaxBackupN+1, one, one, one)},
		{localapi.OpBackupAdd, add(testPlace, 1, big, one, one)},
		{localapi.OpBackupAdd, add(testPlace, 1, one, one, nil)},
		{localapi.OpBackupAdd, add(with(func(p *localapi.BackupPlace) { p.Kind = "" }), 1, one, one, one)},
		{localapi.OpBackupRemove, localapi.BackupRemove{Token: tok}},
		{localapi.OpBackupRemove, localapi.BackupRemove{Token: tok, Name: strings.Repeat("a", 65)}},
	} {
		if _, err := r.call(c.op, c.args); code(err) != localapi.ErrBadArgs {
			t.Errorf("case %d (%s): %v", i, c.op, err)
		}
	}
	if _, err := r.raw(localapi.OpBackupRemove, `{"token":"`+tok+`","name":"a","extra":1}`); code(err) != localapi.ErrBadArgs {
		t.Errorf("an unknown field: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	for i := range BackupBeginsPerMinute + 1 {
		_, err := r.call(localapi.OpBackupBegin, backupArgs(tok)[localapi.OpBackupBegin])
		if want := i == BackupBeginsPerMinute; (code(err) == localapi.ErrLimited) != want {
			t.Fatalf("begin %d: %v", i, err)
		}
	}
	// The passkey page's own begins count apart.
	if _, err := r.call(localapi.OpPasskeyBegin, passkeyArgs(tok)[localapi.OpPasskeyBegin]); err != nil {
		t.Fatalf("passkey begin after backup begins: %v", err)
	}
}

// The ops are served only with Backups and Passkeys both: the add's tap
// needs the passkey page's name.
func TestBackupOpsNeedPasskeys(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Backups = &fakeBackups{}
	for _, op := range localapi.BackupOps {
		if r.srv.Ops()[op] != nil {
			t.Fatalf("%s served without passkeys", op)
		}
	}
	p, _ := passkeyRig(t)
	for _, op := range localapi.BackupOps {
		if p.ops[op] != nil {
			t.Fatalf("%s served without Backups", op)
		}
	}
	b, _ := backupRig(t)
	if len(b.ops) != len(localapi.Ops)+len(localapi.PasskeyOps)+len(localapi.BackupOps) {
		t.Fatalf("%d ops with backups", len(b.ops))
	}
}

// Only the closed set of codes reaches the page.
func TestBackupRefusalsAreTheClosedSet(t *testing.T) {
	r, f := backupRig(t)
	tok := r.signIn()
	for _, c := range localapi.BackupCodes {
		f.err = sockets.Code(c)
		if _, err := r.call(localapi.OpBackupAdd, backupArgs(tok)[localapi.OpBackupAdd]); code(err) != c {
			t.Errorf("%s: %v", c, err)
		}
	}
	for _, e := range []error{errors.New("kernel: a backup destination needs your hardware key's signature"),
		sockets.Code(localapi.ErrPasskeyNotAnchor), sockets.Code("kernel text")} {
		f.err = e
		for _, op := range localapi.BackupOps {
			if _, err := r.call(op, backupArgs(tok)[op]); code(err) != localapi.ErrBackupUnavailable {
				t.Errorf("%s with %v: %v", op, e, err)
			}
		}
	}
}

// The status page carries the notice's fixed lines.
func TestStatusCarriesTheBackupNotice(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.BackupNotes = func() []string {
		return []string{"Backups: none, so I hold the only copy of your data; add a drive on the Backups page."}
	}
	out, err := r.call(localapi.OpStatus, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if st := out.(localapi.Status); len(st.Backups) != 1 {
		t.Fatalf("status %+v", st)
	}
}
