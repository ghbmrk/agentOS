package change

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// Package is what one installation shares with another (CHG-4). It holds
// only files and pass counts on public cases: no case content, journal,
// session, identity, installation ID, grant, or any other authority
// (CHG-5). Import refuses any other field.
type Package struct {
	Format   int      `json:"format"`
	Classes  []Class  `json:"classes"`
	Files    Tree     `json:"files"`
	Evidence Evidence `json:"evidence"`
}

// Evidence is counts only, from public cases and security fixtures.
type Evidence struct {
	PublicCases    int `json:"public_cases"`
	PublicPassed   int `json:"public_passed"`
	PublicBaseline int `json:"public_baseline"`
	Fixtures       int `json:"fixtures"`
	FixturesPassed int `json:"fixtures_passed"`
}

// PackageFormat is the only format Import accepts.
const PackageFormat = 1

// MaxPackage bounds an imported package.
const MaxPackage = 1 << 20

var ErrNotShareable = errors.New("change: not shareable")

// Export builds a package from an active adoption. Sharing is opt-in
// (SetSharing), and only an adoption built from public inputs, changing
// only procedures and skills, with no file the private-content check flags,
// can be exported (CHG-4, CHG-5). The caller sends the bytes over whatever
// git-like channel the owner chose; there is no registry.
func (p *Pipeline) Export(ctx context.Context, id string) ([]byte, error) {
	p.mu.Lock()
	if !p.st.Sharing {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w: sharing is off", ErrNotShareable)
	}
	a := p.adoptionLocked(id)
	if a == nil || a.Reverted != "" {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w: no active adoption %s", ErrNotShareable, id)
	}
	if !a.Public {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w: %s was built from private inputs", ErrNotShareable, id)
	}
	pkg := Package{Format: PackageFormat, Classes: append([]Class(nil), a.Classes...), Files: Tree{}}
	for _, e := range a.Edits {
		c := classOf(e.Path)
		if c != ClassProcedure && c != ClassSkill {
			p.mu.Unlock()
			return nil, fmt.Errorf("%w: only procedures and skills are shared, %s is %s", ErrNotShareable, e.Path, c)
		}
		if e.After == nil {
			p.mu.Unlock()
			return nil, fmt.Errorf("%w: a deletion is not shared", ErrNotShareable)
		}
		if p.cfg.Private == nil || p.cfg.Private([]byte(e.Path)) || p.cfg.Private(e.After) {
			p.mu.Unlock()
			return nil, fmt.Errorf("%w: %s may carry private content", ErrNotShareable, e.Path)
		}
		pkg.Files[e.Path] = e.After
	}
	prev, _, err := undoTree(p.st.Active, a)
	if err != nil {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w: %v", ErrNotShareable, err)
	}
	cur := p.st.Active.clone()
	set := p.freezeLocked(a.Classes)
	p.mu.Unlock()

	var pub frozen
	for _, c := range set.heldOut {
		if c.Public {
			pub.heldOut = append(pub.heldOut, c)
		}
	}
	pub.security = set.security
	s := p.evaluate(ctx, prev, cur, pub)
	pkg.Evidence = Evidence{PublicCases: s.HeldOut, PublicPassed: s.Passed, PublicBaseline: s.BaselinePassed,
		Fixtures: s.Security, FixturesPassed: s.SecurityPassed}
	sort.Slice(pkg.Classes, func(i, j int) bool { return pkg.Classes[i] < pkg.Classes[j] })
	return canonicalJSON(pkg), nil
}

// Import re-qualifies a received package locally, on this installation's
// own held-out and security suites, as a shared candidate. The sender's
// evidence is never authority: a shared candidate is never auto-adopted,
// so the owner approves or rejects it (CHG-3, CHG-4).
func (p *Pipeline) Import(ctx context.Context, data []byte) (Report, Package, error) {
	var pkg Package
	if len(data) > MaxPackage {
		return Report{}, pkg, errors.New("change: package too large")
	}
	if err := decodeStrict(data, &pkg); err != nil {
		return Report{}, pkg, fmt.Errorf("change: package refused: %w", err)
	}
	if pkg.Format != PackageFormat || len(pkg.Files) == 0 {
		return Report{}, pkg, errors.New("change: package refused: unknown format or no files")
	}
	for path := range pkg.Files {
		if err := cleanPath(path); err != nil {
			return Report{}, pkg, err
		}
		if c := classOf(path); c != ClassProcedure && c != ClassSkill {
			return Report{}, pkg, fmt.Errorf("change: package refused: %s is %s (CHG-5)", path, c)
		}
	}
	rep, err := p.propose(ctx, Candidate{Source: Shared, Origin: "share", Files: pkg.Files}, false)
	return rep, pkg, err
}
