// Package change now holds only the file store its old change pipeline
// used (store.go): Store, MemStore, FileStore, Content, MemContent and
// DirContent, which claim, firstboot, apply, localui and cmd/agentosd
// still use. The pipeline itself was deleted (#2785 c3) and is in git
// history; c4 moves the store to its own package and deletes this one.
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package change

// Executor is the journal executor name the deleted pipeline registered.
// cmd/agentosd still registers it as retired, so a recorded intent naming
// it is refused rather than unknown; c4 removes both.
const Executor = "change"
