package skill

import (
	"regexp"

	"github.com/ghbmrk/agentos/broker/skill/format"
)

// The file format lives in skill/format, which imports no network code,
// so the broker's checks can decode skills without linking this bridge
// (ARC-2). These names keep the bridge's API.
type (
	SlotType = format.SlotType
	Slot     = format.Slot
	Node     = format.Node
	Step     = format.Step
	Kind     = format.Kind
	Skill    = format.Skill
)

const (
	Version       = format.Version
	SkillsNS      = format.SkillsNS
	ProceduresNS  = format.ProceduresNS
	MaxSteps      = format.MaxSteps
	MaxSlots      = format.MaxSlots
	MaxValue      = format.MaxValue
	MaxFile       = format.MaxFile
	Text          = format.Text
	Email         = format.Email
	Number        = format.Number
	Bool          = format.Bool
	JSON          = format.JSON
	KindSkill     = format.KindSkill
	KindProcedure = format.KindProcedure
)

var (
	ErrInvalid = format.ErrInvalid
	Decode     = format.Decode
	DecodeFile = format.DecodeFile
)

var runIDRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
