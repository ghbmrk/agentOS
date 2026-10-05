package loops

import (
	"strconv"
	"strings"
)

// Version schemes for advisory matching. Debian packages use dpkg ordering
// (the default, since the host is Debian); everything else that names
// "semver" uses semantic versioning.
const (
	SchemeDeb    = "deb"
	SchemeSemver = "semver"
)

// versionBelow reports v < fixed under the scheme. A version either side
// that does not parse counts as below: fail closed, so an unreadable
// version is reported, never assumed fixed.
func versionBelow(scheme, v, fixed string) bool {
	var c int
	var ok bool
	if scheme == SchemeSemver {
		c, ok = semverCompare(v, fixed)
	} else {
		c, ok = debCompare(v, fixed)
	}
	return !ok || c < 0
}

// debCompare orders two Debian versions as dpkg does:
// [epoch:]upstream[-revision], where "~" sorts before anything, even the
// end of the string.
func debCompare(a, b string) (int, bool) {
	ea, ua, ra, ok1 := debParse(a)
	eb, ub, rb, ok2 := debParse(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if ea != eb {
		if ea < eb {
			return -1, true
		}
		return 1, true
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c, true
	}
	return verrevcmp(ra, rb), true
}

func debParse(v string) (epoch int, upstream, revision string, ok bool) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		n, err := strconv.Atoi(v[:i])
		if err != nil || n < 0 {
			return 0, "", "", false
		}
		epoch, v = n, v[i+1:]
	}
	upstream = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
		if revision == "" {
			return 0, "", "", false
		}
	}
	if upstream == "" || upstream[0] < '0' || upstream[0] > '9' {
		return 0, "", "", false
	}
	for _, r := range upstream {
		if !isAlnum(r) && !strings.ContainsRune(".+~-:", r) {
			return 0, "", "", false
		}
	}
	for _, r := range revision {
		if !isAlnum(r) && !strings.ContainsRune(".+~", r) {
			return 0, "", "", false
		}
	}
	return epoch, upstream, revision, true
}

func isAlnum(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

// debOrder is dpkg's character weight in the non-digit parts.
func debOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func verrevcmp(a, b string) int {
	isDigit := func(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }
	for a != "" || b != "" {
		for a != "" && !isDigit(a) || b != "" && !isDigit(b) {
			// An empty side weighs 0, like a digit; a non-digit never
			// weighs 0, so equal weights mean the same non-digit both
			// sides.
			x, y := 0, 0
			if a != "" {
				x = debOrder(a[0])
			}
			if b != "" {
				y = debOrder(b[0])
			}
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
			a, b = a[1:], b[1:]
		}
		var na, nb string
		na, a = leadingDigits(a)
		nb, b = leadingDigits(b)
		if c := numCompare(na, nb); c != 0 {
			return c
		}
	}
	return 0
}

func leadingDigits(s string) (string, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

// numCompare compares decimal digit strings of any length.
func numCompare(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// semverCompare orders MAJOR[.MINOR[.PATCH]][-pre][+build], with a missing
// MINOR or PATCH read as 0 and a leading "v" ignored. A prerelease sorts
// before its release.
func semverCompare(a, b string) (int, bool) {
	ca, pa, ok1 := semverParse(a)
	cb, pb, ok2 := semverParse(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := range ca {
		if c := numCompare(ca[i], cb[i]); c != 0 {
			return c, true
		}
	}
	switch {
	case pa == nil && pb == nil:
		return 0, true
	case pa == nil:
		return 1, true
	case pb == nil:
		return -1, true
	}
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, y := pa[i], pb[i]
		_, ex := strconv.ParseUint(x, 10, 64)
		_, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if c := numCompare(x, y); c != 0 {
				return c, true
			}
		case ex == nil:
			return -1, true
		case ey == nil:
			return 1, true
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c, true
			}
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1, true
	case len(pa) > len(pb):
		return 1, true
	}
	return 0, true
}

func semverParse(v string) (core [3]string, pre []string, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		if v[i+1:] == "" {
			return core, nil, false
		}
		pre = strings.Split(v[i+1:], ".")
		for _, p := range pre {
			if p == "" {
				return core, nil, false
			}
			for _, r := range p {
				if !isAlnum(r) && r != '-' {
					return core, nil, false
				}
			}
		}
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		return core, nil, false
	}
	core = [3]string{"0", "0", "0"}
	for i, p := range parts {
		if p == "" {
			return core, nil, false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return core, nil, false
			}
		}
		core[i] = p
	}
	return core, pre, true
}
