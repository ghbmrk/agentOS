package card

import (
	"errors"
	"strings"
	"testing"
)

// REQ: REC-1, REC-4, ID-1
// MIG-4-recovery-group (#3445): a refusal names the mistyped group, 1 to 8
// as printed, and is still ErrRecoveryKey; a wrong length names none.
func TestStoreRecoveryKeyNamesGroup(t *testing.T) {
	key := mustGen(t, 11).RecoveryKey
	groups := strings.Split(key, "-")
	if len(groups) != recoveryGroups {
		t.Fatalf("%d groups", len(groups))
	}
	retype := func(g, i int, c byte) string {
		gs := append([]string(nil), groups...)
		b := []byte(gs[g])
		b[i] = c
		gs[g] = string(b)
		return strings.Join(gs, "-")
	}
	other := func(c byte) byte {
		if c == 'A' {
			return 'B'
		}
		return 'A'
	}
	for g := range groups {
		for i := 0; i <= recoveryGroupKey; i++ {
			cases := map[string]string{
				"wrong symbol":   retype(g, i, other(groups[g][i])),
				"unknown symbol": retype(g, i, '1'),
			}
			if i < recoveryGroupKey && groups[g][i] != groups[g][i+1] {
				gs := append([]string(nil), groups...)
				gs[g] = swap(gs[g], i)
				cases["neighbours swapped"] = strings.Join(gs, "-")
			}
			for name, s := range cases {
				rk, err := StoreRecoveryKey(s)
				var m *MistypedError
				if rk != nil || !errors.As(err, &m) || m.Group != g+1 {
					t.Fatalf("group %d symbol %d %s: %v, %v", g+1, i, name, rk, err)
				}
				if !errors.Is(err, ErrRecoveryKey) {
					t.Fatalf("group %d: %v is not ErrRecoveryKey", g+1, err)
				}
				if want := "group " + string(rune('1'+g)) + " "; !strings.Contains(err.Error(), want) {
					t.Fatalf("group %d: message %q", g+1, err)
				}
			}
		}
	}
	// The first mistyped group is the one named.
	gs := append([]string(nil), groups...)
	for _, g := range []int{2, 5} {
		b := []byte(gs[g])
		b[0] = other(b[0])
		gs[g] = string(b)
	}
	var m *MistypedError
	if _, err := StoreRecoveryKey(strings.Join(gs, "-")); !errors.As(err, &m) || m.Group != 3 {
		t.Fatalf("two groups: %v", err)
	}
	for _, s := range []string{"", key[:len(key)-6], key + "-AAAAA"} {
		_, err := StoreRecoveryKey(s)
		if err != ErrRecoveryKey {
			t.Fatalf("%q: %v, want plain ErrRecoveryKey", s, err)
		}
	}
	if !recoveryKeyOK(key) || recoveryKeyOK(retype(4, 0, other(groups[4][0]))) {
		t.Fatal("recoveryKeyOK disagrees with the parser")
	}
}

func swap(s string, i int) string {
	b := []byte(s)
	b[i], b[i+1] = b[i+1], b[i]
	return string(b)
}
