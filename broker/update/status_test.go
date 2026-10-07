package update

// REQ: UPD-2, UPD-8

import (
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func roleOf(t *testing.T, s RepoStatus, name string) RoleStatus {
	t.Helper()
	for _, r := range s.Roles {
		if r.Role == name {
			return r
		}
	}
	t.Fatalf("no %s in status %+v", name, s.Roles)
	return RoleStatus{}
}

func warned(s RepoStatus, sub string) bool {
	for _, w := range s.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// UX-46-4: status shows each role's version, signatures against its
// threshold, and expiry, and a fresh repository has nothing to warn about.
func TestRepoStatusShowsVersionsSignaturesAndExpiry(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 2)
	s, err := f.repo.Status()
	if err != nil {
		t.Fatal(err)
	}
	root := roleOf(t, s, "root")
	if root.Version != 1 || root.Signatures != 2 || root.Threshold != 2 || root.Expires.IsZero() {
		t.Fatalf("root %+v", root)
	}
	tg := roleOf(t, s, "targets")
	if tg.Version != 2 || tg.Signatures != 2 || tg.Threshold != 2 {
		t.Fatalf("targets %+v", tg)
	}
	if ts := roleOf(t, s, "timestamp"); ts.Signatures != 1 || ts.Threshold != 1 || !ts.Expires.Equal(t0.Add(TimestampExpiry)) {
		t.Fatalf("timestamp %+v", ts)
	}
	if len(s.Releases) != 1 || s.Releases[0] != 2 {
		t.Fatalf("releases %v", s.Releases)
	}
	if len(s.Warnings) != 0 {
		t.Fatalf("fresh repository warned: %q", s.Warnings)
	}
}

// A signature that does not verify, or one from a key outside the role,
// is not counted toward the threshold.
func TestRepoStatusCountsOnlyValidRoleSignatures(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.must(f.repo.Sign("targets", f.tgt[1]))
	s, err := f.repo.Status()
	if err != nil {
		t.Fatal(err)
	}
	st := roleOf(t, s, "targets")
	if st.StagedVersion != 2 || st.StagedSignatures != 1 || st.StagedThreshold != 2 {
		t.Fatalf("staged targets %+v", st)
	}
	if !strings.Contains(strings.Join(s.Notes, "\n"), "staged targets v2: 1 of 2 signatures") {
		t.Fatalf("notes %q", s.Notes)
	}
	// A root key's signature on targets is not a targets signature.
	p := f.repo.p("staged", "targets.json")
	m, err := metadata.Targets().FromFile(p)
	f.must(err)
	signer, err := Signer(f.root[0])
	f.must(err)
	_, err = m.Sign(signer)
	f.must(err)
	f.must(writeMeta(p, m))
	if st := roleOf(t, mustV(f.repo.Status()), "targets"); st.StagedSignatures != 1 {
		t.Fatalf("a root key counted for targets: %+v", st)
	}
	// Tamper with the staged file's payload: its one signature no longer
	// verifies.
	m.Signed.Version = 9
	f.must(writeMeta(p, m))
	s = mustV(f.repo.Status())
	if st := roleOf(t, s, "targets"); st.StagedSignatures != 0 {
		t.Fatalf("a signature over other bytes counted: %+v", st)
	}
}

// PR1: root or targets expiring within RenewWithin (60 days) is a
// warning, so CI fails long before boxes refuse the metadata.
func TestRepoStatusWarnsSixtyDaysBeforeRootOrTargetsExpire(t *testing.T) {
	f := newFixture(t)
	// Init stamps root and targets v1 from the real clock.
	exp := roleOf(t, mustV(f.repo.Status()), "root").Expires
	f.now = exp.Add(-59*24*time.Hour - time.Hour)
	f.must(f.repo.Refresh(f.snap, f.ts))
	s := mustV(f.repo.Status())
	if !warned(s, "root v1 expires in 59 days") || !warned(s, "targets v1 expires in 59 days") {
		t.Fatalf("no 60-day warning: %q", s.Warnings)
	}
	f.now = exp.Add(-61*24*time.Hour - time.Hour)
	f.must(f.repo.Refresh(f.snap, f.ts))
	if s := mustV(f.repo.Status()); warned(s, "root") || warned(s, "targets") {
		t.Fatalf("warned 61 days out: %q", s.Warnings)
	}
}

// PU1/PU2: the online roles alarm at half their life, and an expired
// role says so plainly.
func TestRepoStatusAlarmsAtHalfExpiryOfOnlineRoles(t *testing.T) {
	f := newFixture(t)
	f.now = t0.Add(TimestampExpiry/2 + time.Minute)
	s := mustV(f.repo.Status())
	if !warned(s, "timestamp v1 is past half its life") || !warned(s, "run refresh") {
		t.Fatalf("no half-life alarm: %q", s.Warnings)
	}
	if warned(s, "snapshot") {
		t.Fatalf("snapshot warned early: %q", s.Warnings)
	}
	f.now = t0.Add(TimestampExpiry + time.Minute)
	s = mustV(f.repo.Status())
	if !warned(s, "timestamp v1 expired") {
		t.Fatalf("no expired warning: %q", s.Warnings)
	}
	f.must(f.repo.Refresh(f.snap, f.ts))
	if s := mustV(f.repo.Status()); warned(s, "timestamp") {
		t.Fatalf("refresh did not clear the alarm: %q", s.Warnings)
	}
}

// A repository with nothing published is not reported healthy.
func TestRepoStatusUnpublishedRepositoryWarns(t *testing.T) {
	dir := t.TempDir()
	_, rp := genKeys(t, dir, "r", 1)
	_, tp := genKeys(t, dir, "t", 1)
	_, sp := genKeys(t, dir, "s", 1)
	_, tsp := genKeys(t, dir, "ts", 1)
	r, err := Init(dir+"/repo", RootConfig{Root: rp, Targets: tp, Snapshot: sp, Timestamp: tsp})
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !warned(s, "no published root") {
		t.Fatalf("unpublished repository: %q", s.Warnings)
	}
	if !strings.Contains(strings.Join(s.Notes, "\n"), "staged root v1: 0 of 1 signatures") {
		t.Fatalf("notes %q", s.Notes)
	}
}
