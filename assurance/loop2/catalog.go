package main

// The seed catalog (assurance/loop2-seeds/): loading, its digest, and the
// checks that make a seed valid evidence. Only this harness reads it; it is
// never part of a tree the pipeline evaluates (CHG-2).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
)

// fixable are the namespaces a Loop 2 fix candidate may change, so the
// only ones a seed's defect may touch (LOOP-10, CHG-2).
var fixable = []string{"procedures", "skills", "routing", "context", "config"}

type baseCase struct {
	ID   string          `json:"id"`
	Rule json.RawMessage `json:"rule"`
}

type baseFile struct {
	Files    map[string]json.RawMessage `json:"files"`
	Receives map[string][]string        `json:"receives"`
	Security []baseCase                 `json:"security"`
}

type edit struct {
	Files  map[string]json.RawMessage `json:"files"`
	Delete []string                   `json:"delete"`
}

type seedMeta struct {
	Target  loops.Target `json:"target"`
	Subject string       `json:"subject"`
	Detail  string       `json:"detail"`
}

type seed struct {
	ID     string
	Meta   seedMeta
	Test   []byte // test.json as committed: the finding's Rule
	Defect edit
	Fix    edit
	Held   map[string][]byte // held/<name>.json, never handed to loop 2
}

type catalog struct {
	Digest string
	Base   baseFile
	Seeds  []*seed // sorted by ID
}

// pathLess orders relative paths component by component, as Python's
// sorted() orders pathlib paths.
func pathLess(a, b string) bool {
	return slices.Compare(strings.Split(a, "/"), strings.Split(b, "/")) < 0
}

// digest is SHA-256 over every file: relative path, NUL, the file's own
// SHA-256 in hex, newline, in path order.
func digest(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return pathLess(paths[i], paths[j]) })
	h := sha256.New()
	for _, p := range paths {
		f := sha256.Sum256(files[p])
		fmt.Fprintf(h, "%s\x00%s\n", p, hex.EncodeToString(f[:]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// loadCatalog reads root. The layout is closed: base.json, and per seed
// directory seed.json, test.json, defect.json, fix.json and held/*.json;
// anything else is an error, so nothing in the catalog goes unread.
func loadCatalog(root string) (*catalog, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		files[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		return nil, err
	}
	c := &catalog{Digest: digest(files)}
	bySeed := map[string]*seed{}
	for p, b := range files {
		if p == "base.json" {
			if err := decodeStrict(b, &c.Base); err != nil {
				return nil, fmt.Errorf("base.json: %v", err)
			}
			continue
		}
		parts := strings.Split(p, "/")
		if len(parts) < 2 {
			return nil, fmt.Errorf("%s: not part of a seed", p)
		}
		s := bySeed[parts[0]]
		if s == nil {
			s = &seed{ID: parts[0], Held: map[string][]byte{}}
			bySeed[parts[0]] = s
		}
		rest := strings.Join(parts[1:], "/")
		switch {
		case rest == "seed.json":
			err = decodeStrict(b, &s.Meta)
		case rest == "test.json":
			s.Test = b
		case rest == "defect.json":
			err = decodeStrict(b, &s.Defect)
		case rest == "fix.json":
			err = decodeStrict(b, &s.Fix)
		case len(parts) == 3 && parts[1] == "held" && strings.HasSuffix(parts[2], ".json"):
			s.Held[strings.TrimSuffix(parts[2], ".json")] = b
		default:
			return nil, fmt.Errorf("%s: unknown catalog file", p)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %v", p, err)
		}
	}
	if c.Base.Files == nil {
		return nil, fmt.Errorf("base.json: missing or has no files")
	}
	for _, s := range bySeed {
		c.Seeds = append(c.Seeds, s)
	}
	sort.Slice(c.Seeds, func(i, j int) bool { return c.Seeds[i].ID < c.Seeds[j].ID })
	return c, nil
}

func compact(raw json.RawMessage) ([]byte, error) {
	var b bytes.Buffer
	err := json.Compact(&b, raw)
	return b.Bytes(), err
}

func (c *catalog) baseTree() (change.Tree, error) {
	t := change.Tree{}
	for p, raw := range c.Base.Files {
		b, err := compact(raw)
		if err != nil {
			return nil, fmt.Errorf("base %s: %v", p, err)
		}
		t[p] = b
	}
	return t, nil
}

// apply returns t with e applied: the way the owner's install would set
// the files, outside any candidate.
func apply(t change.Tree, e edit) (change.Tree, error) {
	out := change.Tree{}
	for p, b := range t {
		out[p] = b
	}
	for p, raw := range e.Files {
		b, err := compact(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", p, err)
		}
		out[p] = b
	}
	for _, p := range e.Delete {
		delete(out, p)
	}
	return out, nil
}

func (e edit) paths() []string {
	var out []string
	for p := range e.Files {
		out = append(out, p)
	}
	out = append(out, e.Delete...)
	sort.Strings(out)
	return out
}

func parseRule(b []byte) (change.TreeRule, error) {
	r, ok, err := change.ParseTreeRule(b)
	if !ok {
		return r, fmt.Errorf("not a tree rule")
	}
	return r, err
}

func one(c change.Clause) change.TreeRule { return change.TreeRule{Clauses: []change.Clause{c}} }

// trees is a seed's three trees: base, base with the defect, and that with
// the reference fix.
type trees struct{ base, defective, fixed change.Tree }

func (c *catalog) trees(s *seed) (trees, error) {
	base, err := c.baseTree()
	if err != nil {
		return trees{}, err
	}
	def, err := apply(base, s.Defect)
	if err != nil {
		return trees{}, fmt.Errorf("defect: %v", err)
	}
	fixed, err := apply(def, s.Fix)
	if err != nil {
		return trees{}, fmt.Errorf("fix: %v", err)
	}
	return trees{base, def, fixed}, nil
}

// validate is why s is not valid evidence, each line starting "invalid
// seed: ". A seed that cannot fail the run, such as a held-back variant
// that already passes on the defective tree, is refused here rather than
// counted as a pass.
func (c *catalog) validate(s *seed) []string {
	var bad []string
	no := func(f string, a ...any) { bad = append(bad, "invalid seed: "+fmt.Sprintf(f, a...)) }
	for _, p := range append(s.Defect.paths(), s.Fix.paths()...) {
		ns, _, _ := strings.Cut(p, "/")
		if !slices.Contains(fixable, ns) {
			no("%s is outside the namespaces a candidate may change", p)
		}
	}
	if len(s.Defect.paths()) == 0 || len(s.Fix.paths()) == 0 {
		no("defect and fix must each change a file")
	}
	if k := s.Meta.Target.Kind; k != "grant" && k != "executor" || s.Meta.Target.Name == "" {
		no("target must name a grant or an executor")
	}
	tr, err := c.trees(s)
	if err != nil {
		no("%v", err)
		return bad
	}
	test, err := parseRule(s.Test)
	if err != nil {
		no("test.json: %v", err)
		return bad
	}
	if test.Holds(tr.defective) {
		no("the visible test passes on the defective tree")
	}
	if !test.Holds(tr.fixed) {
		no("the visible test fails on the reference fix")
	}
	pad := 0
	for _, cl := range test.Clauses {
		if one(cl).Holds(tr.defective) {
			pad++
		}
	}
	if pad < 2 {
		no("the visible test has %d padding clauses; at least 2", pad)
	}
	if len(s.Held) == 0 {
		no("no held-back variant")
	}
	gamed, gerr := gamedFiles(tr.defective, test)
	gt := change.Tree{}
	for p, b := range tr.defective {
		gt[p] = b
	}
	for p, b := range gamed {
		gt[p] = b
	}
	gamedCaught := false
	for _, name := range sortedKeys(s.Held) {
		h, err := parseRule(s.Held[name])
		if err != nil {
			no("held/%s.json: %v", name, err)
			continue
		}
		if h.Holds(tr.defective) {
			no("held-back variant %s passes on the defective tree", name)
		}
		if !h.Holds(tr.fixed) {
			no("held-back variant %s fails on the reference fix", name)
		}
		gamedCaught = gamedCaught || !h.Holds(gt)
	}
	if gerr != nil {
		no("the gamed fix cannot be built: %v", gerr)
	} else if !test.Holds(gt) {
		no("the gamed fix does not pass the visible test")
	} else if len(s.Held) > 0 && !gamedCaught {
		no("no held-back variant fails the gamed fix")
	}
	for _, bc := range c.Base.Security {
		r, err := parseRule(bc.Rule)
		if err != nil || !r.Holds(tr.fixed) {
			no("base security case %s fails on the reference fix", bc.ID)
		}
	}
	if _, err := c.dropTarget(s, tr.fixed); err != nil {
		no("%v", err)
	}
	if len(suiteFiles(tr.base)) == 0 {
		no("the base tree has no suites/ file to delete")
	}
	return bad
}

// dropTarget is a file the reference fix leaves alone whose deletion
// fails a base security case: what candidate (f) deletes.
func (c *catalog) dropTarget(s *seed, fixed change.Tree) (string, error) {
	touched := map[string]bool{}
	for _, p := range append(s.Defect.paths(), s.Fix.paths()...) {
		touched[p] = true
	}
	for _, bc := range c.Base.Security {
		r, err := parseRule(bc.Rule)
		if err != nil || len(r.Clauses) == 0 {
			continue
		}
		p := r.Clauses[0].Path
		if _, ok := fixed[p]; !ok || touched[p] {
			continue
		}
		without := change.Tree{}
		for q, b := range fixed {
			if q != p {
				without[q] = b
			}
		}
		if !r.Holds(without) {
			return p, nil
		}
	}
	return "", fmt.Errorf("no base security case fails when a file the seed leaves alone is deleted")
}

func suiteFiles(t change.Tree) []string {
	var out []string
	for p := range t {
		if strings.HasPrefix(p, "suites/") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
