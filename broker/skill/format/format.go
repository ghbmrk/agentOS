// Package format is the compiled-skill file format: its types, strict
// canonical decoding, validation, and the task shape a file's own steps
// give. It imports only the standard library (no network), so the broker's
// checks can use it without linking the skill bridge (ARC-2).
package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Version is the skill file format version.
const Version = 1

// Namespaces in the managed tree (change pipeline): compiled skills and
// procedures.
const (
	SkillsNS     = "skills"
	ProceduresNS = "procedures"
)

// Bounds on a skill file.
const (
	MaxSteps = 32
	MaxSlots = 32
	MaxValue = 16 << 10 // bytes of one bound value
	MaxFile  = 64 << 10
	maxDepth = 8
)

// SlotType is what an input may hold. The compiler infers it from every
// observed value; the runner checks it before any effect (an assumption).
type SlotType string

const (
	Text   SlotType = "text"
	Email  SlotType = "email"
	Number SlotType = "number"
	Bool   SlotType = "bool"
	JSON   SlotType = "json" // an array or object
)

// Slot is one input.
type Slot struct {
	Name string   `json:"name"`
	Type SlotType `json:"type"`
	// Max bounds a text or email value in bytes, and a json value's
	// encoding.
	Max int `json:"max"`
}

// Node is one value in a step's params: a literal, a slot, or an object of
// nodes. Exactly one is set.
type Node struct {
	Lit  json.RawMessage `json:"lit,omitempty"`
	Slot string          `json:"slot,omitempty"`
	Obj  map[string]Node `json:"obj,omitempty"`
}

// Step is one broker effect.
type Step struct {
	Account    string          `json:"account"`
	Action     string          `json:"action"`
	Params     map[string]Node `json:"params,omitempty"`
	Recipients []Node          `json:"recipients,omitempty"`
}

// Kind tells a compiled skill from a procedure.
type Kind string

const (
	KindSkill     Kind = "skill"     // from repeated trajectories; constants are literals
	KindProcedure Kind = "procedure" // from one trajectory; every value is a slot
)

// Skill is a compiled skill or procedure file.
type Skill struct {
	Version int    `json:"version"`
	Kind    Kind   `json:"kind"`
	ID      string `json:"id"`
	// Runs is how many successful trajectories it was compiled from.
	Runs  int    `json:"runs"`
	Slots []Slot `json:"slots"`
	Steps []Step `json:"steps"`
}

var (
	// keyRE is a param or object key: compile walks only objects keyed
	// like this (compile keyRE, security B1), so no other key is structure.
	keyRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	idRE    = regexp.MustCompile(`^[kp][0-9a-f]{12}$`)
	slotRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	nameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`) // as broker/guest
	emailRE = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
)

// IsFileName reports whether path has a skill or procedure file's name:
// skills/ or procedures/, then an ID, then .json. Only such files are
// offered by the skill bridge or superseded by a skill.
func IsFileName(path string) bool { return fileRE.MatchString(path) }

var fileRE = regexp.MustCompile(`^(` + SkillsNS + `|` + ProceduresNS + `)/[kp][0-9a-f]{12}\.json$`)

// ValidID reports whether id is a skill or procedure ID: k or p and 12 hex.
func ValidID(id string) bool { return idRE.MatchString(id) }

// ErrInvalid marks a skill file the runner refuses.
var ErrInvalid = errors.New("skill: invalid skill file")

// Path is a skill's file in the managed tree.
func (s *Skill) Path() string {
	ns := SkillsNS
	if s.Kind == KindProcedure {
		ns = ProceduresNS
	}
	return ns + "/" + s.ID + ".json"
}

// Decode parses and validates a skill file strictly: unknown fields,
// anything but the canonical encoding, and any rule in Validate refuse it.
func Decode(b []byte) (*Skill, error) {
	if len(b) > MaxFile {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxFile)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s Skill
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	// Only the canonical encoding is accepted: no duplicate keys, spacing,
	// or trailing data, so the bytes reviewed are the bytes run (security
	// C2 on #89).
	if !bytes.Equal(b, s.Encode()) {
		return nil, fmt.Errorf("%w: not in canonical form", ErrInvalid)
	}
	return &s, nil
}

// DecodeFile decodes the file at path in the managed tree and checks that
// its name is its own: path is its kind's namespace plus its ID, and the
// shape in the ID is the one its steps give (Shape). A file that passes
// is for exactly the task its name says (P3-6e).
func DecodeFile(path string, b []byte) (*Skill, error) {
	s, err := Decode(b)
	if err != nil {
		return nil, err
	}
	if s.Path() != path {
		return nil, fmt.Errorf("%w: %s holds %s", ErrInvalid, path, s.Path())
	}
	if s.Shape() != s.ID[1:] {
		return nil, fmt.Errorf("%w: %s holds another task's steps", ErrInvalid, path)
	}
	return s, nil
}

// Encode renders a skill canonically (sorted keys, no spaces).
func (s *Skill) Encode() []byte {
	b, _ := json.Marshal(s)
	return b
}

// Validate checks every structural rule. A skill never names the broker's
// own account or a meta.* action: those are the owner's (OP-5), and the
// broker refuses them from a guest anyway.
func (s *Skill) Validate() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }
	if s.Version != Version {
		return bad("version %d", s.Version)
	}
	if s.Kind != KindSkill && s.Kind != KindProcedure {
		return bad("kind %q", s.Kind)
	}
	if !idRE.MatchString(s.ID) || (s.ID[0] == 'k') != (s.Kind == KindSkill) {
		return bad("id %q", s.ID)
	}
	if s.Runs < 1 {
		return bad("runs %d", s.Runs)
	}
	if len(s.Steps) == 0 || len(s.Steps) > MaxSteps {
		return bad("%d steps", len(s.Steps))
	}
	if len(s.Slots) > MaxSlots {
		return bad("%d slots", len(s.Slots))
	}
	slots := map[string]bool{}
	for _, sl := range s.Slots {
		if !slotRE.MatchString(sl.Name) || sl.Name == "run_id" || slots[sl.Name] {
			return bad("slot name %q", sl.Name)
		}
		switch sl.Type {
		case Text, Email, Number, Bool, JSON:
		default:
			return bad("slot %s type %q", sl.Name, sl.Type)
		}
		if sl.Max < 1 || sl.Max > MaxValue {
			return bad("slot %s max %d", sl.Name, sl.Max)
		}
		slots[sl.Name] = true
	}
	used := map[string]bool{}
	for i, st := range s.Steps {
		if !nameRE.MatchString(st.Account) || !nameRE.MatchString(st.Action) {
			return bad("step %d: account or action", i+1)
		}
		if st.Account == "broker" || strings.HasPrefix(st.Action, "meta.") {
			return bad("step %d: broker-state change", i+1)
		}
		for k, n := range st.Params {
			if !keyRE.MatchString(k) {
				return bad("step %d param key %q", i+1, k)
			}
			if err := checkNode(n, slots, used, 1); err != nil {
				return bad("step %d param %q: %v", i+1, k, err)
			}
		}
		for _, n := range st.Recipients {
			if err := checkNode(n, slots, used, 1); err != nil {
				return bad("step %d recipient: %v", i+1, err)
			}
			if n.Obj != nil {
				return bad("step %d recipient: object", i+1)
			}
		}
	}
	for name := range slots {
		if !used[name] {
			return bad("slot %s unused", name)
		}
	}
	if s.Kind == KindProcedure && s.hasLiteral() {
		return bad("a procedure carries no literal values")
	}
	return nil
}

func (s *Skill) hasLiteral() bool {
	var lit func(Node) bool
	lit = func(n Node) bool {
		if len(n.Lit) > 0 {
			return true
		}
		for _, c := range n.Obj {
			if lit(c) {
				return true
			}
		}
		return false
	}
	for _, st := range s.Steps {
		for _, n := range st.Params {
			if lit(n) {
				return true
			}
		}
		for _, n := range st.Recipients {
			if lit(n) {
				return true
			}
		}
	}
	return false
}

func checkNode(n Node, slots, used map[string]bool, depth int) error {
	if depth > maxDepth {
		return errors.New("too deep")
	}
	set := 0
	if len(n.Lit) > 0 {
		set++
		if !json.Valid(n.Lit) {
			return errors.New("literal is not JSON")
		}
	}
	if n.Slot != "" {
		set++
		if !slots[n.Slot] {
			return fmt.Errorf("unknown slot %q", n.Slot)
		}
		used[n.Slot] = true
	}
	if n.Obj != nil {
		set++
		// compile never walks into an empty object (it is one JSON leaf),
		// so an empty obj would change the skill but not its shape.
		if len(n.Obj) == 0 {
			return errors.New("empty object")
		}
		for k, c := range n.Obj {
			if !keyRE.MatchString(k) {
				return fmt.Errorf("object key %q", k)
			}
			if err := checkNode(c, slots, used, depth+1); err != nil {
				return err
			}
		}
	}
	if set != 1 {
		return errors.New("a node must be exactly one of lit, slot, obj")
	}
	return nil
}

// Bind checks every input against its slot (the input assumptions) and
// returns the bound values. A failure names the slot and why, for the
// model; no effect has been requested.
func (s *Skill) Bind(args map[string]json.RawMessage) (map[string]any, error) {
	out := map[string]any{}
	known := map[string]bool{"run_id": true}
	for _, sl := range s.Slots {
		known[sl.Name] = true
		raw, ok := args[sl.Name]
		if !ok {
			return nil, fmt.Errorf("input %s is missing", sl.Name)
		}
		v, err := bindOne(sl, raw)
		if err != nil {
			return nil, err
		}
		out[sl.Name] = v
	}
	var extra []string
	for k := range args {
		if !known[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return nil, fmt.Errorf("unknown inputs: %s", strings.Join(extra, ", "))
	}
	return out, nil
}

func bindOne(sl Slot, raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("input %s is not JSON", sl.Name)
	}
	switch sl.Type {
	case Text, Email:
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("input %s must be a string", sl.Name)
		}
		if len(str) > sl.Max {
			return nil, fmt.Errorf("input %s is longer than %d bytes, which no past run needed", sl.Name, sl.Max)
		}
		if sl.Type == Email && !emailRE.MatchString(str) {
			return nil, fmt.Errorf("input %s must be an email address", sl.Name)
		}
		return str, nil
	case Number:
		if _, ok := v.(json.Number); !ok {
			return nil, fmt.Errorf("input %s must be a number", sl.Name)
		}
		return v, nil
	case Bool:
		if _, ok := v.(bool); !ok {
			return nil, fmt.Errorf("input %s must be true or false", sl.Name)
		}
		return v, nil
	case JSON:
		switch v.(type) {
		case []any, map[string]any:
		default:
			return nil, fmt.Errorf("input %s must be a list or an object", sl.Name)
		}
		if b, _ := json.Marshal(v); len(b) > sl.Max {
			return nil, fmt.Errorf("input %s is larger than %d bytes, which no past run needed", sl.Name, sl.Max)
		}
		return v, nil
	}
	return nil, fmt.Errorf("input %s has an unknown type", sl.Name)
}

// Fill builds step i's params and recipients from bound values.
func (s *Skill) Fill(i int, vals map[string]any) (map[string]any, []string, error) {
	st := s.Steps[i]
	var params map[string]any
	if len(st.Params) > 0 {
		params = map[string]any{}
		for k, n := range st.Params {
			v, err := fillNode(n, vals)
			if err != nil {
				return nil, nil, err
			}
			params[k] = v
		}
	}
	var recips []string
	for _, n := range st.Recipients {
		v, err := fillNode(n, vals)
		if err != nil {
			return nil, nil, err
		}
		r, ok := v.(string)
		if !ok {
			return nil, nil, errors.New("a recipient must be a string")
		}
		recips = append(recips, r)
	}
	return params, recips, nil
}

func fillNode(n Node, vals map[string]any) (any, error) {
	switch {
	case len(n.Lit) > 0:
		dec := json.NewDecoder(bytes.NewReader(n.Lit))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	case n.Slot != "":
		v, ok := vals[n.Slot]
		if !ok {
			return nil, fmt.Errorf("input %s is missing", n.Slot)
		}
		return v, nil
	default:
		m := map[string]any{}
		for k, c := range n.Obj {
			v, err := fillNode(c, vals)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, nil
	}
}

// Shape is the shape of the task this file was compiled from, recomputed
// from its own steps: the accounts and actions in order, and every value's
// position and JSON kind (a slot's kind from its type, a literal's from
// its value). It equals compile.Shape of the source trajectories: Validate
// admits only keys compile walks (keyRE), which need no escaping, and no
// empty object. So a file's content, not its name, says which task it is
// for (P3-6e).
func (s *Skill) Shape() string {
	types := map[string]SlotType{}
	for _, sl := range s.Slots {
		types[sl.Name] = sl.Type
	}
	kind := func(n Node) byte {
		if n.Slot != "" {
			switch types[n.Slot] {
			case Text, Email:
				return 's'
			case Number:
				return 'n'
			case Bool:
				return 'b'
			}
			return 'j'
		}
		dec := json.NewDecoder(bytes.NewReader(n.Lit))
		dec.UseNumber()
		var v any
		dec.Decode(&v)
		switch v.(type) {
		case string:
			return 's'
		case bool:
			return 'b'
		case nil:
			return 'z'
		case json.Number:
			return 'n'
		}
		return 'j'
	}
	h := sha256.New()
	for i, st := range s.Steps {
		fmt.Fprintf(h, "step %d %q %q %d\n", i, st.Account, st.Action, len(st.Recipients))
	}
	for i, st := range s.Steps {
		var walk func(path string, n Node)
		walk = func(path string, n Node) {
			if n.Obj == nil {
				fmt.Fprintf(h, "%d/p/%s %c\n", i, path, kind(n))
				return
			}
			for _, k := range sortedKeys(n.Obj) {
				walk(path+"/"+k, n.Obj[k])
			}
		}
		for _, k := range sortedKeys(st.Params) {
			walk(k, st.Params[k])
		}
		for r, n := range st.Recipients {
			fmt.Fprintf(h, "%d/r/%d %c\n", i, r, kind(n))
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func sortedKeys(m map[string]Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
